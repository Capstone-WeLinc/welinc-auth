import { HttpException, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AccountEventType, Prisma, SessionEndReason } from '@prisma/client';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import type { Env } from '../../config/env';
import { AuthService, validateEmailDomain } from '../auth.service';
import { PrismaService } from '../../shared/prisma.service';
import { AccountEventsService } from '../events/account-events.service';
import { SessionService } from '../sessions/session.service';
import { AdminAlertsService } from './admin-alerts.service';
import { MAX_SUITE_ADMINS } from '../../../prisma/seeds/manifest';

type Tx = Prisma.TransactionClient;

/** Spec 0013, AC-1, AC-2: every change to `suite_admins` takes this lock first. */
export async function lockSuiteAdmins(tx: Tx): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext('suite_admins'))`;
}

/** Spec 0013: a written reason is 10 to 500 characters once trimmed. */
export const REASON_MIN = 10;
export const REASON_MAX = 500;

export function reasonProblem(reason: string): string | null {
  const length = reason.trim().length;
  if (length < REASON_MIN || length > REASON_MAX) {
    return `the reason must be ${REASON_MIN} to ${REASON_MAX} characters`;
  }
  return null;
}

export type RecoveryInput = {
  email: string;
  reason: string;
  /** Where the script ran, for the `ADMIN_RECOVERY` row. */
  host: string;
  osUser: string;
};

export type RecoveryResult = {
  userId: string;
  name: string;
  email: string;
  /** False when the person already was a suite admin (only unlocked and signed out). */
  added: boolean;
  sessionsEnded: number;
};

export type CreateInput = RecoveryInput & { name: string };

export type CreateResult = {
  userId: string;
  name: string;
  email: string;
  /** False when the setup code could not be sent (the limits or the mail failed). */
  setupEmailSent: boolean;
};

/** `users.name` is `varchar(100)`. */
const NAME_MAX = 100;

/** A refusal: the script prints it and exits 1, nothing written. */
export class RecoveryRefused extends Error {}

type Target = {
  id: string;
  name: string;
  email: string;
  is_active: boolean;
  deleted_at: Date | null;
  email_verified: boolean;
};

/**
 * Spec 0013, AC-12: `npm run admin:recover`, the way back when no suite admin can sign in. Run
 * from the server shell, so whoever runs it already holds the server. One transaction: unlock,
 * the suite admin row (granter null), every live session ended (`ADMIN_ENDED`), `ADMIN_RECOVERY`
 * and `SUITE_ADMIN_ACTIONED`. Prints no password or code: the person uses Forgot password.
 */
@Injectable()
export class AdminRecoveryService {
  private readonly logger = new Logger('AdminRecovery');

  constructor(
    private readonly prisma: PrismaService,
    private readonly sessions: SessionService,
    private readonly events: AccountEventsService,
    private readonly alerts: AdminAlertsService,
    private readonly auth: AuthService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  /**
   * Suite spec 0013, AC-12b: `admin:recover --create`, the first suite admin of a database with
   * nobody in it (a new hosted production, VRMS spec 0008 AC-15). Runs only while no suite admin
   * exists. One transaction: the account (no roles, no password, email not verified), the suite
   * admin row (granter null), `ADMIN_RECOVERY` and `SUITE_ADMIN_ACTIONED`. After the commit the
   * setup code goes to the address; using it verifies the email and sets the password. No AC-13
   * alert: the only suite admin is the person just made, and nobody else holds an admin role yet.
   */
  async create(input: CreateInput): Promise<CreateResult> {
    const problem = reasonProblem(input.reason);
    if (problem) throw new RecoveryRefused(problem);
    const reason = input.reason.trim();
    const name = input.name.trim();
    if (name.length === 0 || name.length > NAME_MAX) {
      throw new RecoveryRefused(`the name must be 1 to ${NAME_MAX} characters`);
    }
    const email = input.email.trim().toLowerCase();
    const production =
      this.config.get('NODE_ENV', { infer: true }) === 'production';
    try {
      await validateEmailDomain(email, production);
    } catch (error) {
      if (error instanceof HttpException) {
        throw new RecoveryRefused(
          `${email} can't receive mail (${error.message}), so the setup code would never arrive`,
        );
      }
      throw error;
    }
    // Nobody knows this password: the setup code is the only way in (spec 0009, AC-15)
    const passwordHash = await argon2.hash(
      crypto.randomBytes(32).toString('hex'),
    );

    const user = await this.prisma.$transaction(async (tx) => {
      await lockSuiteAdmins(tx);
      if ((await tx.suiteAdmin.count()) > 0) {
        throw new RecoveryRefused(
          'a suite admin exists already; --create is only for a database with none. Use the plain form',
        );
      }
      const existing = await tx.user.findFirst({
        where: { email: { equals: email, mode: 'insensitive' } },
        select: { id: true },
      });
      if (existing) {
        throw new RecoveryRefused(
          `an account with the email ${email} exists already; use the plain form without --create`,
        );
      }
      const created = await tx.user.create({
        data: {
          name,
          email,
          passwordHash,
          passwordSet: false,
          emailVerified: false,
          isActive: true,
        },
        select: { id: true, name: true, email: true },
      });
      await tx.suiteAdmin.create({
        data: { userId: created.id, grantedById: null, reason },
      });
      await this.events.record(tx, {
        userId: created.id,
        actorId: null,
        type: AccountEventType.ADMIN_RECOVERY,
        reason,
        newValue: JSON.stringify({
          host: input.host,
          osUser: input.osUser,
          created: true,
        }),
      });
      await this.events.record(tx, {
        userId: created.id,
        actorId: null,
        type: AccountEventType.SUITE_ADMIN_ACTIONED,
        reason,
      });
      return created;
    });
    this.logger.log(
      `admin recovery user=${user.id} created=true host=${input.host}`,
    );
    const setupEmailSent = await this.auth.sendSetupCode(user);
    return {
      userId: user.id,
      name: user.name,
      email: user.email,
      setupEmailSent,
    };
  }

  async recover(input: RecoveryInput): Promise<RecoveryResult> {
    const problem = reasonProblem(input.reason);
    if (problem) throw new RecoveryRefused(problem);
    const reason = input.reason.trim();
    const email = input.email.trim().toLowerCase();

    const result = await this.prisma.$transaction(async (tx) => {
      await lockSuiteAdmins(tx);
      const [target] = await tx.$queryRaw<Target[]>`
        SELECT id, name, email, is_active, deleted_at, email_verified
        FROM users WHERE lower(email) = ${email} FOR UPDATE`;
      if (!target)
        throw new RecoveryRefused(`no account has the email ${email}`);
      if (target.deleted_at)
        throw new RecoveryRefused('the account is deleted');
      if (!target.is_active)
        throw new RecoveryRefused('the account is not active');
      if (!target.email_verified) {
        throw new RecoveryRefused(
          'the account has not verified its email, so it could not receive a reset code',
        );
      }
      // A temporary grant of a suite admin being recovered doesn't count (spec 0013, AC-3)
      const roles = await tx.userRoleAssignment.count({
        where: { userId: target.id, temporaryGrantId: null },
      });
      if (roles > 0) {
        throw new RecoveryRefused(
          'the account holds a system role; a suite admin holds none. Use a separate account',
        );
      }
      const already = await tx.suiteAdmin.findUnique({
        where: { userId: target.id },
        select: { userId: true },
      });
      if (!already && (await tx.suiteAdmin.count()) >= MAX_SUITE_ADMINS) {
        throw new RecoveryRefused(
          `${MAX_SUITE_ADMINS} suite admins exist already; recover one of them instead`,
        );
      }

      await tx.user.update({
        where: { id: target.id },
        data: { lockedAt: null, failedLoginAttempts: 0 },
      });
      if (!already) {
        await tx.suiteAdmin.create({
          data: { userId: target.id, grantedById: null, reason },
        });
      }
      const sessionsEnded = await this.sessions.endAllForUser(
        tx,
        target.id,
        SessionEndReason.ADMIN_ENDED,
      );
      await this.events.record(tx, {
        userId: target.id,
        actorId: null,
        type: AccountEventType.ADMIN_RECOVERY,
        reason,
        newValue: JSON.stringify({ host: input.host, osUser: input.osUser }),
      });
      if (!already) {
        await this.events.record(tx, {
          userId: target.id,
          actorId: null,
          type: AccountEventType.SUITE_ADMIN_ACTIONED,
          reason,
        });
      }
      return {
        userId: target.id,
        name: target.name,
        email: target.email,
        added: !already,
        sessionsEnded,
      };
    });
    this.logger.log(
      `admin recovery user=${result.userId} added=${result.added} host=${input.host}`,
    );
    // AC-13: every suite admin and every system's admins hear about it
    await this.alerts.send(null, [
      {
        kind: 'ADMIN_RECOVERY',
        targetId: result.userId,
        systems: 'ALL',
        reason,
      },
    ]);
    await this.alerts.flush();
    return result;
  }
}
