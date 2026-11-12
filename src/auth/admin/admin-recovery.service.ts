import { Injectable, Logger } from '@nestjs/common';
import { AccountEventType, Prisma, SessionEndReason } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { AccountEventsService } from '../events/account-events.service';
import { SessionService } from '../sessions/session.service';
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
  ) {}

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
      const roles = await tx.userRoleAssignment.count({
        where: { userId: target.id },
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
    return result;
  }
}
