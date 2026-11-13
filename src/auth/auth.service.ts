import {
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../config/env';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs/promises';
import * as dns from 'dns';
import {
  AccountEventType,
  DeletionRequestStatus,
  Prisma,
  ReauthPurpose,
  SessionEndReason,
  SystemType,
  VerificationPurpose,
} from '@prisma/client';
import { AccountEventsService } from './events/account-events.service';
import {
  DELETION_REQUEST_REASON,
  PasswordCheckReason,
  SignInFailReason,
} from './events/event-types';
import { PasswordCheckService } from './reauth/password-check.service';
import {
  closePendingOnAdminDelete,
  markRestored,
} from './deletion/deletion-steps';
import { notRestorable } from './deletion/deletion.service';
import { NO_META, type RequestMeta } from './events/request-meta';
import {
  AdminAlertsService,
  type AdminAlert,
} from './admin/admin-alerts.service';
import {
  AdminStandingService,
  alertSystemsOf,
  isAdmin,
} from './admin/admin-standing.service';
import {
  isSuiteAdmin,
  isSuiteAdminNoRolesError,
  suiteAdminNoRoles,
  suiteAdminSelfOnly,
  temporaryRole,
} from './admin/admin-errors';
import {
  afterCursor,
  decodePeopleCursor,
  encodePeopleCursor,
  parsePeopleLimit,
  statusWhere,
  type PeopleStatus,
} from './admin/people-page';

/** Who sent a code and from where (spec 0011, AC-5); the user themselves when left out. */
type CodeSender = { actorId?: string; meta?: RequestMeta };
import { PrismaService } from '../shared/prisma.service';
import {
  CatalogService,
  holdsAdmin,
  type AdminRoles,
} from './roles/catalog.service';
import type { RoleAssignment } from './roles/catalog.types';
import { TokenService } from './tokens/token.service';
import { SessionService } from './sessions/session.service';
import { MailService } from '../shared/mail.service';
import { CreateUserDto } from './dto/create-user.dto';
import { ListUsersQueryDto } from './dto/list-users.query.dto';
import { LoginDto } from './dto/login.dto';
import { SetUserStatusDto } from './dto/set-user-status.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { RoleAssignmentDto } from './dto/role-assignment.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { StartEmailChangeDto } from './dto/email-verification.dto';
import { coded } from './errors';
import { DEV_EMAIL_DOMAINS } from '../shared/dev-email-domains';
import {
  accountLocked,
  countWrongPassword,
  lockActive,
  MAX_FAILED_ATTEMPTS,
} from './lockout';
import { CodeService, type CheckResult } from './codes/code.service';
import {
  CodeSendLimitError,
  MailFailedError,
  codeExpired,
  invalidCode,
} from './codes/code-errors';
import {
  adminChangedEmailEmail,
  emailChangeCodeEmail,
  emailChangeStartedEmail,
  emailChangedEmail,
  passwordCodeEmail,
  type Email,
} from './codes/code-emails';
import {
  SELF_DEACTIVATE,
  SELF_DELETE,
  SELF_ROLE,
  adminSystems,
  assertAnotherAdmin,
  change,
  lockAccount,
  roleChanges,
  rolesKey,
} from './user-changes';
import type { EventInput } from './events/account-events.service';
import {
  AccountScope,
  AdminCaller,
  LOOKUP_LIMIT,
  assertInScope,
  LookupLimiter,
  assertInSystem,
  assertNotAdminElsewhere,
  assertNotShared,
  assertOwnSystemRoles,
  otherSystems,
  replaceSystemRoles,
} from './user-scope';

export { newOtp } from './codes/code.service';

/** The password family: setup and reset codes (spec 0009, AC-2). */
const PASSWORD_CODES = [
  VerificationPurpose.PASSWORD_SETUP,
  VerificationPurpose.PASSWORD_RESET,
] as const;
const EMAIL_CHANGE = [VerificationPurpose.EMAIL_CHANGE] as const;

/** AC-17, AC-21: an address another account holds (deleted accounts included). */
const emailTaken = () =>
  coded(
    HttpStatus.CONFLICT,
    'EMAIL_TAKEN',
    'Another account already uses this email',
  );

const isUniqueViolation = (error: unknown) =>
  typeof error === 'object' &&
  error !== null &&
  'code' in error &&
  (error as { code?: string }).code === 'P2002';

/**
 * Suite spec 0015: a deactivated account learns so only after its right password (and a code
 * step, when one runs). Anyone without the password still gets the generic 401.
 */
const accountInactive = () =>
  coded(
    HttpStatus.FORBIDDEN,
    'ACCOUNT_INACTIVE',
    'This account is deactivated. Ask your admin to turn it back on.',
  );

// Domains a development machine accepts without a DNS lookup (and logs instead of mailing)
export { DEV_EMAIL_DOMAINS };

export async function validateEmailDomain(
  email: string,
  production: boolean,
): Promise<void> {
  const domain = email.split('@')[1];
  if (!domain) {
    throw new BadRequestException('Invalid email format');
  }

  // Made up test addresses skip the mail check on your own machine only; when hosted, every
  // address must be on a domain that can receive mail, or its setup and reset codes never arrive
  if (!production && DEV_EMAIL_DOMAINS.includes(domain.toLowerCase())) {
    return;
  }

  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err || !addresses || addresses.length === 0) {
        dns.resolve(domain, (err2, ips) => {
          if (err2 || !ips || ips.length === 0) {
            reject(
              new BadRequestException(
                'Email domain does not exist or cannot receive mail',
              ),
            );
          } else {
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  });
}

/** The stable `code` of a coded error body (spec 0001 section 11), if any. */
function errorCode(error: unknown): string | undefined {
  if (!(error instanceof HttpException)) return undefined;
  const body = error.getResponse();
  return typeof body === 'object' && body !== null && 'code' in body
    ? String(body.code)
    : undefined;
}

/** Only the part after `@`, for the no account log line (spec 0011, AC-2). */
export function emailDomain(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1).toLowerCase() : '';
}
const FORGOT_PASSWORD_MESSAGE =
  'If that email is registered, an OTP has been sent.';

/** The fields every admin answer returns, mapped by mapManagedUser. */
const MANAGED_USER_SELECT = {
  id: true,
  name: true,
  email: true,
  emailVerified: true,
  passwordSet: true,
  contact: true,
  profilePicture: true,
  isActive: true,
  lockedAt: true,
  createdAt: true,
  updatedAt: true,
  roles: {
    select: {
      role: true,
      system: true,
      temporaryGrant: { select: { expiresAt: true } },
    },
  },
} satisfies Prisma.UserSelect;

/** The signed in caller of a public route, when they sent a valid token (OptionalJwtAuthGuard). */
export type OptionalCaller = {
  sub: string;
  email: string;
  sid: string;
  roles: RoleAssignment[];
} | null;

type ManagedUserRecord = {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  passwordSet: boolean;
  contact: string | null;
  profilePicture: string | null;
  isActive: boolean;
  lockedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  roles: (RoleAssignment & {
    temporaryGrant?: { expiresAt: Date } | null;
  })[];
};

/** The person a login finishes for (the launcher answer and the session). */
export type SignInUser = {
  id: string;
  name: string;
  email: string;
  profilePicture: string | null;
};

export type AuthUserResponse = {
  id: string;
  name: string;
  email: string;
  contact: string | null;
  profilePicture: string | null;
  roles: RoleAssignment[];
};

export type ManagedUserResponse = {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  /** Spec 0009, AC-22: false while setup is pending. */
  passwordSet: boolean;
  contact: string | null;
  profilePicture: string | null;
  isActive: boolean;
  isLocked: boolean;
  lockedAt: string | null;
  createdAt: string;
  updatedAt: string;
  roles: RoleAssignment[];
};

/** An admin answer: only the caller's system roles, plus the other systems by name (spec 0011, AC-26). */
export type ScopedUserResponse = ManagedUserResponse & {
  otherSystems: SystemType[];
  /** Spec 0013, AC-11: when the person's temporary role in this system ends, else null. */
  temporaryUntil: string | null;
};

export type LookupUserResponse = {
  id: string;
  name: string;
  email: string;
  systems: SystemType[];
};

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly lookupLimiter = new LookupLimiter();
  /** Where setup and reset emails send people (spec 0009, AC-16). */
  private readonly passwordLink: string;
  /** Hosted: every email domain must receive mail (`validateEmailDomain`). */
  private readonly production: boolean;

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokenService,
    private readonly mailService: MailService,
    config: ConfigService<Env, true>,
    private readonly sessions: SessionService,
    private readonly catalog: CatalogService,
    private readonly codes: CodeService,
    private readonly events: AccountEventsService,
    private readonly passwords: PasswordCheckService,
    private readonly admins: AdminStandingService,
    private readonly alerts: AdminAlertsService,
  ) {
    // PORTAL_URL is required and checked at boot (spec 0010)
    const portalUrl = config.get('PORTAL_URL', { infer: true });
    this.passwordLink = `${portalUrl.replace(/\/+$/, '')}/forgot-password`;
    this.production = config.get('NODE_ENV', { infer: true }) === 'production';
  }

  /**
   * The password check shared by the portal and the mobile login: lockout, inactive accounts,
   * the failure counter. Which systems the person may enter is decided by the caller (the
   * launcher answer, spec 0007; the mobile grant, spec 0004).
   */
  async checkCredentials(
    dto: Pick<LoginDto, 'email' | 'password'>,
    meta: RequestMeta,
  ): Promise<{
    user: SignInUser & { emailVerified: boolean };
  }> {
    // TODO: Transparent migration — if passwordHash starts with '$2b$' (bcrypt),
    // verify with bcrypt first, re-hash with argon2, then save. Requires bcrypt as
    // an optional dep. Skipped until all passwords are migrated.

    const user = await this.prisma.user.findFirst({
      where: { email: dto.email, deletedAt: null },
      select: {
        id: true,
        name: true,
        email: true,
        contact: true,
        profilePicture: true,
        emailVerified: true,
        passwordHash: true,
        isActive: true,
        failedLoginAttempts: true,
        lockedAt: true,
        roles: {
          select: {
            role: true,
            system: true,
          },
        },
      },
    });

    // User not found — generic message to prevent user enumeration. Spec 0011, AC-2: no row,
    // one log line with the address and only the email's domain
    if (!user) {
      this.logger.warn(
        `sign in for no account ip=${meta.ip ?? '-'} domain=@${emailDomain(dto.email)}`,
      );
      throw new UnauthorizedException('Invalid credentials');
    }

    // A running lock is checked before the password, so a locked account tries nothing
    if (lockActive(user.lockedAt)) {
      await this.recordFail(user.id, SignInFailReason.ACCOUNT_LOCKED, meta);
      throw accountLocked(user.lockedAt);
    }

    const isPasswordValid = await argon2.verify(
      user.passwordHash,
      dto.password,
    );

    if (!isPasswordValid) {
      // The row (and the counter) commit before the error answer (AC-7)
      const outcome = await this.recordFail(
        user.id,
        SignInFailReason.WRONG_PASSWORD,
        meta,
      );
      if (outcome.locked) {
        throw accountLocked();
      }

      throw new UnauthorizedException({
        message: 'Invalid credentials',
        remainingAttempts: outcome.attemptsLeft,
        isLocked: false,
      });
    }

    // Spec 0015: the right password on a deactivated account says so (the count is left alone)
    if (!user.isActive) {
      await this.recordFail(user.id, SignInFailReason.ACCOUNT_INACTIVE, meta);
      throw accountInactive();
    }

    // Successful login: reset the counter, and clear a lock that ran out
    await this.prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockedAt: null },
    });

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        profilePicture: user.profilePicture,
        emailVerified: user.emailVerified,
      },
    };
  }

  /**
   * Spec 0009, AC-9 step (2): the account checks `/auth/login` makes, without a password and
   * without counting anything. Locked: 403 `ACCOUNT_LOCKED`; deactivated or deleted: 401.
   */
  async assertCanSignIn(
    userId: string,
    meta: RequestMeta,
  ): Promise<SignInUser> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: {
        id: true,
        name: true,
        email: true,
        profilePicture: true,
        isActive: true,
        lockedAt: true,
      },
    });
    // A deleted account counts as no account: no row (spec 0011, AC-1)
    if (!user) throw new UnauthorizedException('Invalid credentials');
    if (lockActive(user.lockedAt)) {
      await this.recordFail(user.id, SignInFailReason.ACCOUNT_LOCKED, meta);
      throw accountLocked(user.lockedAt);
    }
    // The password was right before this step started, so the account may hear why
    if (!user.isActive) {
      await this.recordFail(user.id, SignInFailReason.ACCOUNT_INACTIVE, meta);
      throw accountInactive();
    }
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      profilePicture: user.profilePicture,
    };
  }

  /**
   * Spec 0011, AC-1, AC-1b, AC-7: the one place a refused sign in is recorded, called from every
   * place that refuses one. Its row commits on its own (callers throw afterwards). A wrong
   * password moves the counter in one atomic UPDATE in the same transaction as the row: the 5th
   * writes one `LOCKED_OUT` and no `SIGN_IN_FAILED`, and a parallel try that finds the account
   * already locked writes `ACCOUNT_LOCKED`. The actor is left null: a refused try is not proof
   * that the person made it.
   */
  async recordFail(
    userId: string,
    reason: SignInFailReason,
    meta: RequestMeta,
    extra: { system?: SystemType; clientId?: string } = {},
  ): Promise<{ locked: boolean; attemptsLeft: number }> {
    const fail = (
      tx: Prisma.TransactionClient,
      failReason: SignInFailReason,
      attemptsLeft: number | null = null,
    ) =>
      this.events.record(tx, {
        userId,
        type: AccountEventType.SIGN_IN_FAILED,
        reason: failReason,
        attemptsLeft,
        system: extra.system ?? null,
        clientId: extra.clientId ?? null,
        meta,
      });

    if (reason !== SignInFailReason.WRONG_PASSWORD) {
      await this.prisma.$transaction((tx) => fail(tx, reason));
      return {
        locked: reason === SignInFailReason.ACCOUNT_LOCKED,
        attemptsLeft: 0,
      };
    }

    return this.prisma.$transaction(async (tx) => {
      const [row] = await tx.$queryRaw<{ attempts: number; locked: boolean }[]>(
        countWrongPassword(userId),
      );
      if (!row) {
        // Locked by a parallel try between the read and this update
        await fail(tx, SignInFailReason.ACCOUNT_LOCKED);
        return { locked: true, attemptsLeft: 0 };
      }
      if (row.locked) {
        await this.events.record(tx, {
          userId,
          type: AccountEventType.LOCKED_OUT,
          clientId: extra.clientId ?? null,
          meta,
        });
        return { locked: true, attemptsLeft: 0 };
      }
      const attemptsLeft = Math.max(0, MAX_FAILED_ATTEMPTS - row.attempts);
      await fail(tx, reason, attemptsLeft);
      return { locked: false, attemptsLeft };
    });
  }

  /**
   * Runs a sign in's system check (the launcher answer, the mobile grant) and records a
   * `NO_SYSTEM_ACCESS` or `APP_NOT_ALLOWED` refusal through `recordFail` before it is rethrown.
   * `APP_NOT_ALLOWED` carries the app's system; `NO_SYSTEM_ACCESS` stays account wide.
   */
  async withSignInCheck<T>(
    userId: string,
    meta: RequestMeta,
    check: () => Promise<T>,
    app: { system?: SystemType; clientId?: string } = {},
  ): Promise<T> {
    try {
      return await check();
    } catch (error) {
      const code = errorCode(error);
      if (code === SignInFailReason.NO_SYSTEM_ACCESS) {
        await this.recordFail(userId, code, meta, { clientId: app.clientId });
      } else if (code === SignInFailReason.APP_NOT_ALLOWED) {
        await this.recordFail(userId, code, meta, app);
      }
      throw error;
    }
  }

  /**
   * Spec 0013, AC-14a, AC-14b: uses the actor's `ADMIN_ACTION` reauth token inside `tx` (a
   * rollback leaves it unused), or 403 `REAUTH_REQUIRED`.
   */
  private useAdminAction(
    tx: Prisma.TransactionClient,
    actor: AdminCaller,
    reauthToken: unknown,
  ): Promise<void> {
    return this.passwords.consumeReauthToken(
      tx,
      typeof reauthToken === 'string' ? reauthToken : undefined,
      actor.id,
      actor.sid,
      ReauthPurpose.ADMIN_ACTION,
    );
  }

  /** AC-13: one alert per system whose admin role `before` and `after` differ on. */
  private async adminRoleAlerts(
    userId: string,
    before: RoleAssignment[],
    after: RoleAssignment[],
    db: Prisma.TransactionClient,
  ): Promise<AdminAlert[]> {
    const admins = await this.catalog.adminRoles(db);
    const was = new Set(adminSystems(before, admins));
    const now = new Set(adminSystems(after, admins));
    const alerts: AdminAlert[] = [];
    for (const system of now) {
      if (!was.has(system)) {
        alerts.push({
          kind: 'ADMIN_ROLE_ADDED',
          targetId: userId,
          systems: [system],
          roleSystem: system,
        });
      }
    }
    for (const system of was) {
      if (!now.has(system)) {
        alerts.push({
          kind: 'ADMIN_ROLE_REMOVED',
          targetId: userId,
          systems: [system],
          roleSystem: system,
        });
      }
    }
    return alerts;
  }

  /**
   * Spec 0013, AC-13, AC-14c: the alerts for roles given on create, attach or edit. An admin
   * role is `ADMIN_ROLE_ADDED` for anyone; when a suite admin acts, every other role given is
   * `SUITE_ROLE_GIVEN` and a new account is `SUITE_ACCOUNT_CREATED`.
   */
  private grantAlerts(
    userId: string,
    actor: AdminCaller,
    added: RoleAssignment[],
    admins: AdminRoles,
    created: boolean,
  ): AdminAlert[] {
    const alerts: AdminAlert[] = [];
    if (actor.suite && created) {
      alerts.push({
        kind: 'SUITE_ACCOUNT_CREATED',
        targetId: userId,
        systems: [actor.system],
        roleSystem: actor.system,
      });
    }
    for (const role of added) {
      if (admins.get(role.system) === role.role) {
        alerts.push({
          kind: 'ADMIN_ROLE_ADDED',
          targetId: userId,
          systems: [role.system],
          roleSystem: role.system,
        });
      } else if (actor.suite) {
        alerts.push({
          kind: 'SUITE_ROLE_GIVEN',
          targetId: userId,
          systems: [role.system],
          roleSystem: role.system,
          role: role.role,
        });
      }
    }
    return alerts;
  }

  async unlockUser(
    userId: string,
    actor: AdminCaller,
    reauthToken?: unknown,
  ): Promise<ScopedUserResponse> {
    const { user, alerts } = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.user.findFirst({
        where: { id: userId, deletedAt: null },
        select: {
          lockedAt: true,
          roles: { select: { role: true, system: true } },
        },
      });
      assertInSystem(existing, actor.system);
      // Not locked (or the lock ran out): nothing changes, so no change row, no recheck and no alert
      if (!lockActive(existing.lockedAt)) {
        return {
          user: await tx.user.findUniqueOrThrow({
            where: { id: userId },
            select: MANAGED_USER_SELECT,
          }),
          alerts: [] as AdminAlert[],
        };
      }
      // Spec 0013, AC-14b: unlocking an admin account needs the actor's password again
      const target = await this.admins.standing(userId, tx);
      if (isAdmin(target)) await this.useAdminAction(tx, actor, reauthToken);
      const updated = await tx.user.update({
        where: { id: userId },
        data: { lockedAt: null, failedLoginAttempts: 0 },
        select: MANAGED_USER_SELECT,
      });
      await this.events.record(
        tx,
        change(userId, actor, AccountEventType.UNLOCKED),
      );
      const unlockAlerts: AdminAlert[] = isAdmin(target)
        ? [
            {
              kind: 'ADMIN_UNLOCKED',
              targetId: userId,
              systems: alertSystemsOf(target),
            },
          ]
        : [];
      return { user: updated, alerts: unlockAlerts };
    });

    await this.alerts.send(actor.id, alerts);
    return this.mapScopedUser(user, actor.system);
  }

  /**
   * Spec 0013, AC-16: an admin sends a reset code (a setup code while setup is pending) to a
   * person of their system, by id. 409 `NOT_ACTIVE` for an inactive account; the code limits
   * answer 429 `CODE_SEND_LIMIT` and a failed email 503 `MAIL_FAILED`. An admin account needs
   * the actor's recheck and alerts (AC-14b).
   */
  async sendPasswordCode(
    userId: string,
    actor: AdminCaller,
    reauthToken?: unknown,
  ): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: {
        id: true,
        name: true,
        email: true,
        isActive: true,
        passwordSet: true,
        roles: { select: { role: true, system: true } },
      },
    });
    assertInSystem(user, actor.system);
    if (!user.isActive) {
      throw coded(
        HttpStatus.CONFLICT,
        'NOT_ACTIVE',
        'Activate this account before sending it a code',
      );
    }
    const target = await this.admins.standing(userId);
    if (isAdmin(target)) {
      await this.prisma.$transaction((tx) =>
        this.useAdminAction(tx, actor, reauthToken),
      );
    }
    const purpose = user.passwordSet
      ? VerificationPurpose.PASSWORD_RESET
      : VerificationPurpose.PASSWORD_SETUP;
    const result = await this.issuePasswordCode(user, purpose, {
      actorId: actor.id,
      meta: actor.meta,
    });
    if (result.kind === 'limited') {
      throw new CodeSendLimitError(result.retryAfter);
    }
    if (isAdmin(target)) {
      await this.alerts.send(actor.id, [
        {
          kind: 'ADMIN_CODE_SENT',
          targetId: userId,
          systems: alertSystemsOf(target),
        },
      ]);
    }
  }

  /**
   * Only users who hold a role in the caller's system. A `system` query can't widen it: the
   * guard already refused a `?system=` that differs from the token's `aud`. A `role` filter is
   * checked against that system's catalog (spec 0004, AC-9).
   */
  async listUsers(
    query: ListUsersQueryDto,
    caller: Pick<AdminCaller, 'system'>,
  ): Promise<(ScopedUserResponse & { pendingDeletion: boolean })[]> {
    if (query.role !== undefined) {
      await this.catalog.assertKnownRole(caller.system, query.role);
    }
    const users = await this.prisma.user.findMany({
      where: {
        deletedAt: null,
        roles: {
          some: {
            system: caller.system,
            ...(query.role !== undefined ? { role: query.role } : {}),
          },
        },
      },
      select: {
        ...MANAGED_USER_SELECT,
        // Spec 0012, AC-9: an EXISTS on a pending request
        deletionRequests: {
          where: { status: DeletionRequestStatus.PENDING },
          select: { id: true },
          take: 1,
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return users.map(({ deletionRequests, ...user }) => ({
      ...this.mapScopedUser(user, caller.system),
      pendingDeletion: deletionRequests.length > 0,
    }));
  }

  /**
   * Spec 0013, AC-16, AC-23: the portal's People list for one system, the same scope as
   * `listUsers` (people holding a role in it, not deleted), searched by name or email, filtered
   * by status, keyset paged by name then id.
   */
  async listPeople(
    query: {
      q?: string;
      status?: PeopleStatus;
      role?: string;
      cursor?: string;
      limit?: string;
    },
    caller: Pick<AccountScope, 'system'>,
  ): Promise<{
    items: (ScopedUserResponse & {
      pendingDeletion: boolean;
      suiteAdmin: boolean;
    })[];
    next: string | null;
  }> {
    if (query.role !== undefined) {
      if (caller.system === null) {
        throw coded(
          HttpStatus.BAD_REQUEST,
          'VALIDATION_FAILED',
          'A role filter needs a system',
        );
      }
      await this.catalog.assertKnownRole(caller.system, query.role);
    }
    const limit = parsePeopleLimit(query.limit);
    const cursor = query.cursor ? decodePeopleCursor(query.cursor) : null;
    const q = query.q?.trim();
    const rows = await this.prisma.user.findMany({
      where: {
        AND: [
          { deletedAt: null },
          // Spec 0013, AC-17: suite scope is every person, people with no role included
          caller.system === null
            ? {}
            : {
                roles: {
                  some: {
                    system: caller.system,
                    ...(query.role !== undefined ? { role: query.role } : {}),
                  },
                },
              },
          q
            ? {
                OR: [
                  { name: { contains: q, mode: 'insensitive' } },
                  { email: { contains: q, mode: 'insensitive' } },
                ],
              }
            : {},
          query.status ? statusWhere(query.status) : {},
          afterCursor(cursor),
        ],
      },
      select: {
        ...MANAGED_USER_SELECT,
        deletionRequests: {
          where: { status: DeletionRequestStatus.PENDING },
          select: { id: true },
          take: 1,
        },
        suiteAdmin: { select: { userId: true } },
      },
      orderBy: [{ name: 'asc' }, { id: 'asc' }],
      take: limit + 1,
    });
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    return {
      items: page.map(({ deletionRequests, suiteAdmin, ...user }) => ({
        ...this.mapScopedUser(user, caller.system),
        pendingDeletion: deletionRequests.length > 0,
        suiteAdmin: suiteAdmin !== null,
      })),
      next:
        rows.length > limit && last
          ? encodePeopleCursor({ name: last.name, id: last.id })
          : null,
    };
  }

  /**
   * Spec 0013, AC-23: one person for the portal's person page, in the admin's system. A soft
   * deleted account in its grace period is shown too (with `deletedAt`, so the page offers
   * Restore); an erased one answers 404 like anyone outside the system.
   */
  async getPerson(
    userId: string,
    caller: Pick<AccountScope, 'system'>,
  ): Promise<
    ScopedUserResponse & {
      pendingDeletion: boolean;
      deletedAt: string | null;
      suiteAdmin: boolean;
    }
  > {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, erasedAt: null },
      select: {
        ...MANAGED_USER_SELECT,
        deletedAt: true,
        deletionRequests: {
          where: { status: DeletionRequestStatus.PENDING },
          select: { id: true },
          take: 1,
        },
        suiteAdmin: { select: { userId: true } },
      },
    });
    assertInScope(user, caller.system);
    const { deletionRequests, deletedAt, suiteAdmin, ...rest } = user;
    return {
      ...this.mapScopedUser(rest, caller.system),
      pendingDeletion: deletionRequests.length > 0,
      deletedAt: deletedAt ? deletedAt.toISOString() : null,
      suiteAdmin: suiteAdmin !== null,
    };
  }

  /** Spec 0011, AC-29: active accounts outside the caller's system, to attach a role to. */
  async lookupUsers(
    q: string,
    caller: AdminCaller,
  ): Promise<LookupUserResponse[]> {
    this.lookupLimiter.hit(caller.id);
    const users = await this.prisma.user.findMany({
      where: {
        isActive: true,
        deletedAt: null,
        roles: { none: { system: caller.system } },
        // Spec 0013, AC-3: a suite admin can't be given a system role
        suiteAdmin: { is: null },
        OR: [
          { name: { contains: q, mode: 'insensitive' } },
          { email: { contains: q, mode: 'insensitive' } },
        ],
      },
      select: {
        id: true,
        name: true,
        email: true,
        roles: { select: { system: true } },
      },
      orderBy: [{ name: 'asc' }, { id: 'asc' }],
      take: LOOKUP_LIMIT,
    });

    return users.map((user) => ({
      id: user.id,
      name: user.name,
      email: user.email,
      systems: otherSystems(user.roles, caller.system),
    }));
  }

  async createUser(
    dto: CreateUserDto,
    actor: AdminCaller,
  ): Promise<ScopedUserResponse & { setupEmailSent: boolean }> {
    const roleAssignments = this.normalizeRoleAssignments(dto.roleAssignments);
    assertOwnSystemRoles(roleAssignments, actor.system);
    // Spec 0004, AC-10: 400, 403, then UNKNOWN_ROLE, then ROLE_LIMIT
    await this.catalog.assertRoleRules(roleAssignments, actor.system);
    // Spec 0013, AC-14a: giving the admin role needs the actor's password again; AC-14c: so
    // does every role and every account a suite admin gives
    const admins = await this.catalog.adminRoles();
    const givesAdmin = holdsAdmin(roleAssignments, actor.system, admins);
    const recheck = givesAdmin || actor.suite === true;

    // Spec 0011, AC-30: an email that already has an account outside this system can be attached
    const existing = await this.prisma.user.findFirst({
      where: {
        email: { equals: dto.email.trim(), mode: 'insensitive' },
      },
      select: {
        id: true,
        name: true,
        isActive: true,
        deletedAt: true,
        roles: { select: { role: true, system: true } },
      },
    });
    if (existing) {
      if (!this.isAttachable(existing, actor.system)) {
        throw new ConflictException('Email already exists');
      }
      if (!dto.attachExisting) {
        throw new ConflictException({
          statusCode: 409,
          message: 'This email already has a WeLinc account.',
          code: 'ACCOUNT_EXISTS',
          id: existing.id,
          name: existing.name,
          systems: otherSystems(existing.roles, actor.system),
        });
      }
      const attached = await this.attachExistingAccount(
        existing.id,
        roleAssignments,
        actor,
        recheck ? dto.reauthToken : null,
      );
      return { ...attached, setupEmailSent: false };
    }

    await validateEmailDomain(dto.email, this.production);

    // Nobody knows this password: the setup code is the only way in (spec 0009, AC-15)
    const passwordHash = await argon2.hash(
      crypto.randomBytes(32).toString('hex'),
    );

    let user: Prisma.UserGetPayload<{ select: typeof MANAGED_USER_SELECT }>;
    try {
      user = await this.prisma.$transaction(async (tx) => {
        if (recheck) await this.useAdminAction(tx, actor, dto.reauthToken);
        const created = await tx.user.create({
          data: {
            name: dto.name.trim(),
            email: dto.email.trim().toLowerCase(),
            passwordHash,
            // AC-15: both start false; using the setup code turns them true (AC-12)
            passwordSet: false,
            emailVerified: false,
            isActive: dto.isActive ?? true,
            roles: {
              create: roleAssignments,
            },
          },
          select: MANAGED_USER_SELECT,
        });

        // AC-6: CREATED plus one ROLE_CHANGED per system granted
        await this.events.recordMany(tx, [
          change(created.id, actor, AccountEventType.CREATED),
          ...roleChanges(created.id, actor, [], created.roles),
        ]);
        return created;
      });
    } catch (error) {
      this.handlePrismaError(error);
    }

    await this.alerts.send(
      actor.id,
      this.grantAlerts(user.id, actor, roleAssignments, admins, true),
    );

    // The user is saved: a failed or refused send only sets setupEmailSent to false. An inactive
    // user's code works once an admin activates them, while it lives (AC-15).
    const setupEmailSent = await this.trySendPasswordCode(
      user,
      VerificationPurpose.PASSWORD_SETUP,
      { actorId: actor.id, meta: actor.meta },
    );

    return { ...this.mapScopedUser(user, actor.system), setupEmailSent };
  }

  /**
   * Issues a setup or reset code and emails it. True when sent; false when the limits refused it
   * or the email failed (both already logged without the address).
   */
  private async trySendPasswordCode(
    user: { id: string; name: string; email: string },
    purpose:
      | typeof VerificationPurpose.PASSWORD_SETUP
      | typeof VerificationPurpose.PASSWORD_RESET,
    from: CodeSender = {},
  ): Promise<boolean> {
    try {
      const result = await this.issuePasswordCode(user, purpose, from);
      return result.kind === 'sent';
    } catch (error) {
      if (error instanceof MailFailedError) return false;
      throw error;
    }
  }

  private issuePasswordCode(
    user: { id: string; name: string; email: string },
    purpose:
      | typeof VerificationPurpose.PASSWORD_SETUP
      | typeof VerificationPurpose.PASSWORD_RESET,
    from: CodeSender = {},
  ) {
    return this.codes.issue({
      userId: user.id,
      purpose,
      actorId: from.actorId,
      meta: from.meta,
      mail: {
        to: user.email,
        build: (code) =>
          passwordCodeEmail({
            purpose,
            name: user.name,
            code,
            link: this.passwordLink,
          }),
      },
    });
  }

  /** A notice email (AC-24). A failure is only logged, without the address. */
  private async notify(
    userId: string,
    kind: string,
    to: string,
    email: Email,
  ): Promise<void> {
    try {
      await this.mailService.sendMail({
        to,
        ...email,
        tag: `user=${userId} purpose=${kind}`,
      });
    } catch (error) {
      this.logger.error(
        `notice email failed user=${userId} purpose=${kind}: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }

  /** Active, not deleted, and not in `system` yet: the only accounts create may attach to. */
  private isAttachable(
    user: {
      isActive: boolean;
      deletedAt: Date | null;
      roles: RoleAssignment[];
    },
    system: SystemType,
  ): boolean {
    return (
      user.isActive &&
      !user.deletedAt &&
      !user.roles.some((r) => r.system === system)
    );
  }

  /**
   * Adds the caller's system roles only; password, name and other roles stay (AC-30).
   * `adminAction` is the reauth token to use when the roles give the admin role (spec 0013,
   * AC-14a), or null when they don't.
   */
  private async attachExistingAccount(
    userId: string,
    roleAssignments: RoleAssignment[],
    actor: AdminCaller,
    adminAction: unknown,
  ): Promise<ScopedUserResponse> {
    const user = await this.prisma.$transaction(async (tx) => {
      // Spec 0004, AC-13: the account row first, then everything is decided from a fresh read
      await lockAccount(tx, userId);
      // Spec 0013, AC-3: a suite admin holds no permanent system role
      if ((await this.admins.standing(userId, tx)).suiteAdmin) {
        throw suiteAdminNoRoles();
      }
      if (adminAction !== null) {
        await this.useAdminAction(tx, actor, adminAction);
      }
      // Decided again inside the transaction, so a deactivate or attach in between wins
      const current = await tx.user.findUnique({
        where: { id: userId },
        select: {
          isActive: true,
          deletedAt: true,
          roles: { select: { role: true, system: true } },
        },
      });
      if (!current || !this.isAttachable(current, actor.system)) {
        throw new ConflictException('Email already exists');
      }
      await this.catalog.assertWithinLimit(
        [...current.roles, ...roleAssignments],
        actor.system,
        tx,
      );
      await tx.userRoleAssignment.createMany({
        data: roleAssignments.map((r) => ({ userId, ...r })),
      });
      await this.events.recordMany(
        tx,
        roleChanges(userId, actor, current.roles, [
          ...current.roles,
          ...roleAssignments,
        ]),
      );
      return tx.user.findUniqueOrThrow({
        where: { id: userId },
        select: MANAGED_USER_SELECT,
      });
    });

    await this.alerts.send(
      actor.id,
      this.grantAlerts(
        userId,
        actor,
        roleAssignments,
        await this.catalog.adminRoles(),
        false,
      ),
    );
    return this.mapScopedUser(user, actor.system);
  }

  async updateUser(
    userId: string,
    dto: UpdateUserDto,
    actor: AdminCaller,
  ): Promise<ScopedUserResponse & { setupEmailSent?: boolean }> {
    const userSelect = {
      id: true,
      name: true,
      email: true,
      passwordSet: true,
      isActive: true,
      deletedAt: true,
      roles: {
        select: {
          role: true,
          system: true,
          temporaryGrantId: true,
        },
      },
    } satisfies Prisma.UserSelect;

    // Outside the transaction: only the early 404 and the slow work (the DNS lookup).
    // Every decision about what changes is made from a fresh read inside the transaction below.
    const current = await this.prisma.user.findUnique({
      where: { id: userId },
      select: userSelect,
    });
    if (!current || current.deletedAt) {
      throw new NotFoundException('User not found');
    }
    assertInSystem(current, actor.system);

    const newName = dto.name?.trim();
    const requestedRoles = dto.roleAssignments
      ? this.normalizeRoleAssignments(dto.roleAssignments, true)
      : undefined;
    if (requestedRoles) {
      assertOwnSystemRoles(requestedRoles, actor.system);
      // Spec 0004, AC-10: UNKNOWN_ROLE, then ROLE_LIMIT, before the slow work below
      await this.catalog.assertRoleRules(requestedRoles, actor.system);
    }

    // A change of letter case only is no change (spec 0009, AC-21)
    const newEmail = dto.email?.trim().toLowerCase();
    if (newEmail && newEmail !== current.email.toLowerCase()) {
      // Your own email goes through /auth/profile/email, with a code (AC-21)
      if (actor.id === userId) {
        throw coded(
          HttpStatus.CONFLICT,
          'SELF_EMAIL',
          'Change your own email from your profile',
        );
      }
      await validateEmailDomain(newEmail, this.production);
      await this.assertEmailFree(newEmail, userId);
    }

    try {
      const { user, oldEmail, alerts } = await this.prisma.$transaction(
        async (tx) => {
          // Spec 0004, AC-13: lock the account, then read its roles again
          await lockAccount(tx, userId);
          const existingUser = await tx.user.findUnique({
            where: { id: userId },
            select: userSelect,
          });
          if (!existingUser || existingUser.deletedAt) {
            throw new NotFoundException('User not found');
          }
          assertInSystem(existingUser, actor.system);

          const isEmailChanging = !!(
            newEmail && newEmail !== existingUser.email.toLowerCase()
          );
          const admins = await this.catalog.adminRoles(tx);
          const target = await this.admins.standing(userId, tx);
          // Spec 0013, AC-14b: a suite admin's email changes only through their own inbox
          if (isEmailChanging && target.suiteAdmin) throw suiteAdminSelfOnly();
          // Another system's admin keeps their own sign in details (spec 0011, AC-28); a suite
          // admin acts across systems and rechecks their password instead (spec 0013, AC-14b)
          if (isEmailChanging && !actor.suite) {
            assertNotAdminElsewhere(existingUser.roles, actor.system, admins);
          }
          const isNameChanging = !!newName && newName !== existingUser.name;
          const roleAssignments = requestedRoles
            ? replaceSystemRoles(
                existingUser.roles,
                requestedRoles,
                actor.system,
              )
            : undefined;
          if (roleAssignments) {
            await this.catalog.assertWithinLimit(
              roleAssignments,
              actor.system,
              tx,
            );
          }
          const areRolesChanging =
            !!roleAssignments &&
            rolesKey(roleAssignments) !== rolesKey(existingUser.roles);
          const isActiveChanging =
            typeof dto.isActive === 'boolean' &&
            dto.isActive !== existingUser.isActive;

          if (actor.id === userId) {
            if (areRolesChanging) throw new ConflictException(SELF_ROLE);
            if (isActiveChanging && !dto.isActive) {
              throw new ConflictException(SELF_DEACTIVATE);
            }
          }
          // Spec 0013, AC-11: a temporary role is ended, never edited; AC-3: a suite admin
          // holds no permanent role; a suite admin is removed as one before deactivation
          if (
            areRolesChanging &&
            existingUser.roles.some(
              (r) => r.system === actor.system && !!r.temporaryGrantId,
            )
          ) {
            throw temporaryRole();
          }
          if (areRolesChanging && target.suiteAdmin) throw suiteAdminNoRoles();
          if (isActiveChanging && !dto.isActive && target.suiteAdmin) {
            throw isSuiteAdmin();
          }

          // An active admin who stops being one, by role or deactivation, must not be the last
          if (existingUser.isActive) {
            for (const system of adminSystems(existingUser.roles, admins)) {
              const losesAdmin =
                (isActiveChanging && dto.isActive === false) ||
                (areRolesChanging &&
                  !holdsAdmin(roleAssignments, system, admins));
              if (losesAdmin) await assertAnotherAdmin(tx, userId, system);
            }
          }

          // Spec 0013, AC-14a, AC-14b: one recheck covers giving the admin role and editing an
          // admin's email; the token is used once whatever the edit holds
          const roleAlerts = areRolesChanging
            ? await this.adminRoleAlerts(
                userId,
                existingUser.roles,
                roleAssignments,
                tx,
              )
            : [];
          const givesAdmin = roleAlerts.some(
            (a) => a.kind === 'ADMIN_ROLE_ADDED',
          );
          const before = new Set(
            existingUser.roles.map((r) => `${r.role}@${r.system}`),
          );
          const added = areRolesChanging
            ? roleAssignments.filter(
                (r) => !before.has(`${r.role}@${r.system}`),
              )
            : [];
          // AC-14c: every role a suite admin gives rechecks their password and alerts
          const suiteGives = actor.suite === true && added.length > 0;
          const emailOnAdmin = isEmailChanging && isAdmin(target);
          if (givesAdmin || emailOnAdmin || suiteGives) {
            await this.useAdminAction(tx, actor, dto.reauthToken);
          }
          const editAlerts: AdminAlert[] = [
            ...roleAlerts,
            ...(actor.suite
              ? this.grantAlerts(userId, actor, added, admins, false).filter(
                  (a) => a.kind === 'SUITE_ROLE_GIVEN',
                )
              : []),
            ...(emailOnAdmin
              ? [
                  {
                    kind: 'ADMIN_EMAIL_CHANGED' as const,
                    targetId: userId,
                    systems: alertSystemsOf(target),
                  },
                ]
              : []),
          ];

          const updated = await tx.user.update({
            where: { id: userId },
            data: {
              ...(isNameChanging ? { name: newName } : {}),
              // Confirmed at their next sign in (spec 0009, AC-21)
              ...(isEmailChanging
                ? { email: newEmail, emailVerified: false }
                : {}),
              ...(isActiveChanging ? { isActive: dto.isActive } : {}),
              // Only this system's rows that change: every other row, a temporary one or one
              // whose `created_at` the report reads as "since", stays as it is
              ...(areRolesChanging
                ? {
                    roles: {
                      deleteMany: existingUser.roles
                        .filter(
                          (r) =>
                            r.system === actor.system &&
                            !roleAssignments.some(
                              (n) => n.system === r.system && n.role === r.role,
                            ),
                        )
                        .map((r) => ({ system: r.system, role: r.role })),
                      create: added.map((r) => ({
                        role: r.role,
                        system: r.system,
                      })),
                    },
                  }
                : {}),
            },
            select: MANAGED_USER_SELECT,
          });

          const changes: EventInput[] = [];
          if (isNameChanging) {
            changes.push(
              change(userId, actor, AccountEventType.UPDATED, {
                field: 'name',
                oldValue: existingUser.name,
                newValue: newName,
              }),
            );
          }
          if (isEmailChanging) {
            changes.push(
              change(userId, actor, AccountEventType.UPDATED, {
                field: 'email',
                oldValue: existingUser.email,
                newValue: newEmail,
              }),
            );
          }
          if (areRolesChanging) {
            changes.push(
              ...roleChanges(
                userId,
                actor,
                existingUser.roles,
                roleAssignments,
              ),
            );
          }
          if (isActiveChanging) {
            changes.push(
              change(
                userId,
                actor,
                dto.isActive
                  ? AccountEventType.ACTIVATED
                  : AccountEventType.DEACTIVATED,
              ),
            );
          }
          await this.events.recordMany(tx, changes);
          if (isEmailChanging) {
            // AC-2: every live code of the user dies with the old address
            await this.codes.retireAll(tx, userId);
          }
          return {
            user: updated,
            oldEmail: isEmailChanging ? existingUser.email : null,
            alerts: editAlerts,
          };
        },
      );

      await this.alerts.send(actor.id, alerts);
      const answer = this.mapScopedUser(user, actor.system);
      if (oldEmail === null) return answer;

      // After the commit (AC-21): tell the old address; a pending setup gets a fresh code
      await this.notify(
        userId,
        'ADMIN_EMAIL_CHANGED',
        oldEmail,
        adminChangedEmailEmail({ name: user.name, newEmail: user.email }),
      );
      if (user.passwordSet) return answer;
      const setupEmailSent = await this.trySendPasswordCode(
        user,
        VerificationPurpose.PASSWORD_SETUP,
        { actorId: actor.id, meta: actor.meta },
      );
      return { ...answer, setupEmailSent };
    } catch (error) {
      if (isUniqueViolation(error)) throw emailTaken();
      if (isSuiteAdminNoRolesError(error)) throw suiteAdminNoRoles();
      this.handlePrismaError(error);
    }
  }

  /** 409 `EMAIL_TAKEN` when another account, deleted ones included, holds the address (AC-17, AC-21). */
  private async assertEmailFree(email: string, userId: string): Promise<void> {
    const holder = await this.prisma.user.findFirst({
      where: {
        email: { equals: email, mode: 'insensitive' },
        id: { not: userId },
      },
      select: { id: true },
    });
    if (holder) throw emailTaken();
  }

  async updateUserStatus(
    userId: string,
    dto: SetUserStatusDto,
    actor: AdminCaller,
  ): Promise<ScopedUserResponse> {
    if (!dto.isActive && actor.id === userId) {
      throw new ConflictException(SELF_DEACTIVATE);
    }

    const user = await this.prisma.$transaction(async (tx) => {
      // The account row before any admin role rows (spec 0004, AC-13 lock order)
      await lockAccount(tx, userId);
      const existing = await tx.user.findFirst({
        where: { id: userId, deletedAt: null },
        select: {
          isActive: true,
          roles: { select: { role: true, system: true } },
        },
      });
      // A shared account may be deactivated: it blocks every system, and the web app says so
      assertInSystem(existing, actor.system);
      // No change: no write and no change row
      if (existing.isActive === dto.isActive) {
        return tx.user.findUniqueOrThrow({
          where: { id: userId },
          select: MANAGED_USER_SELECT,
        });
      }
      if (!dto.isActive) {
        // Spec 0013, AC-3: remove the suite admin row first
        if ((await this.admins.standing(userId, tx)).suiteAdmin) {
          throw isSuiteAdmin();
        }
        const admins = await this.catalog.adminRoles(tx);
        for (const system of adminSystems(existing.roles, admins)) {
          await assertAnotherAdmin(tx, userId, system);
        }
      }
      const updated = await tx.user.update({
        where: { id: userId },
        data: { isActive: dto.isActive },
        select: MANAGED_USER_SELECT,
      });
      await this.events.record(
        tx,
        change(
          userId,
          actor,
          dto.isActive
            ? AccountEventType.ACTIVATED
            : AccountEventType.DEACTIVATED,
        ),
      );
      // Spec 0003 AC-4: deactivation ends every live session at once
      if (!dto.isActive) {
        await this.sessions.endAllForUser(
          tx,
          userId,
          SessionEndReason.DEACTIVATED,
          { endedById: actor.id, system: actor.system, ip: actor.meta?.ip },
        );
      }
      return updated;
    });

    return this.mapScopedUser(user, actor.system);
  }

  /**
   * Soft deletes an account. A suite admin (spec 0013, AC-17) may pass no system and may delete
   * a shared account; the last active admin rule still holds in every system.
   */
  async deleteUser(
    userId: string,
    actor: AccountScope,
  ): Promise<{ id: string }> {
    if (actor.id === userId) throw new ConflictException(SELF_DELETE);

    const alerts = await this.prisma.$transaction(async (tx) => {
      // The account row before any admin role rows (spec 0004, AC-13 lock order)
      await lockAccount(tx, userId);
      const existing = await tx.user.findFirst({
        where: { id: userId, deletedAt: null },
        select: {
          isActive: true,
          roles: { select: { role: true, system: true } },
        },
      });
      assertInScope(existing, actor.system);
      if (!actor.suite && actor.system !== null) {
        assertNotShared(existing.roles, actor.system);
      }
      // Spec 0013, AC-3: remove the suite admin row first
      if ((await this.admins.standing(userId, tx)).suiteAdmin) {
        throw isSuiteAdmin();
      }
      if (existing.isActive) {
        const admins = await this.catalog.adminRoles(tx);
        for (const system of adminSystems(existing.roles, admins)) {
          await assertAnotherAdmin(tx, userId, system);
        }
      }
      const now = new Date();
      await tx.user.update({
        where: { id: userId },
        data: {
          deletedAt: now,
          isActive: false,
          lockedAt: null,
        },
      });
      // Spec 0012, AC-13: a pending request closes as APPROVED by this admin, one DELETED
      const closed = await closePendingOnAdminDelete(tx, userId, actor, now);
      await this.events.record(
        tx,
        change(
          userId,
          actor,
          AccountEventType.DELETED,
          closed ? { reason: DELETION_REQUEST_REASON } : {},
        ),
      );
      // Spec 0003 AC-4
      await this.sessions.endAllForUser(tx, userId, SessionEndReason.DELETED, {
        endedById: actor.id,
        system: actor.system ?? undefined,
        ip: actor.meta?.ip,
      });
      // Spec 0013, AC-13: deleting an admin removes their admin role in each system
      return this.adminRoleAlerts(userId, existing.roles, [], tx);
    });

    await this.alerts.send(actor.id, alerts);
    return { id: userId };
  }

  /**
   * Spec 0012, AC-14: brings back an account in its grace period. It stays inactive with its
   * roles; an APPROVED request becomes RESTORED. Not deleted or already erased: 409.
   */
  async restoreUser(
    userId: string,
    actor: AccountScope,
  ): Promise<ScopedUserResponse> {
    const { user, alerts } = await this.prisma.$transaction(async (tx) => {
      await lockAccount(tx, userId);
      const existing = await tx.user.findFirst({
        where: { id: userId },
        select: {
          deletedAt: true,
          erasedAt: true,
          roles: { select: { role: true, system: true } },
        },
      });
      assertInScope(existing, actor.system);
      if (existing.deletedAt === null || existing.erasedAt !== null) {
        throw notRestorable();
      }
      const updated = await tx.user.update({
        where: { id: userId },
        data: { deletedAt: null, isActive: false },
        select: MANAGED_USER_SELECT,
      });
      await markRestored(tx, userId, actor, new Date());
      await this.events.record(
        tx,
        change(userId, actor, AccountEventType.RESTORED),
      );
      // Spec 0013, AC-13: a restored admin holds their admin role again
      return {
        user: updated,
        alerts: await this.adminRoleAlerts(userId, [], existing.roles, tx),
      };
    });
    await this.alerts.send(actor.id, alerts);
    return this.mapScopedUser(user, actor.system);
  }

  /**
   * Public (spec 0009, AC-13). Sends nothing to an unknown, inactive or deleted user, and answers
   * the same message either way, also inside the wait or over the limit. An admin of one of the
   * user's systems instead gets 429 `CODE_SEND_LIMIT` or 503 `MAIL_FAILED`, and the send is
   * recorded as CODE_SENT once it succeeded. A setup code goes out while setup is pending.
   */
  async forgotPassword(
    email: string,
    caller: OptionalCaller = null,
    meta: RequestMeta = NO_META,
    reauthToken?: unknown,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email: email.trim().toLowerCase() },
      select: {
        id: true,
        name: true,
        email: true,
        passwordSet: true,
        isActive: true,
        deletedAt: true,
        roles: { select: { system: true } },
      },
    });

    // Always the same answer, to prevent user enumeration
    if (!user || !user.isActive || user.deletedAt) {
      return { message: FORGOT_PASSWORD_MESSAGE };
    }

    const admins = caller ? await this.catalog.adminRoles() : null;
    const admin =
      caller &&
      admins &&
      user.roles.some((target) =>
        holdsAdmin(caller.roles, target.system, admins),
      )
        ? { id: caller.sub, email: caller.email, sid: caller.sid }
        : null;

    // Spec 0013, AC-14b: an admin sending a code to an admin account rechecks their password
    const target = admin ? await this.admins.standing(user.id) : null;
    const onAdmin = target !== null && isAdmin(target);
    if (admin && onAdmin) {
      await this.prisma.$transaction((tx) =>
        this.passwords.consumeReauthToken(
          tx,
          typeof reauthToken === 'string' ? reauthToken : undefined,
          admin.id,
          admin.sid,
          ReauthPurpose.ADMIN_ACTION,
        ),
      );
    }

    const purpose = user.passwordSet
      ? VerificationPurpose.PASSWORD_RESET
      : VerificationPurpose.PASSWORD_SETUP;
    let result: Awaited<ReturnType<AuthService['issuePasswordCode']>>;
    try {
      // Spec 0011, AC-5: CODE_SENT (once RESET_SENT) names the admin who sent it
      result = await this.issuePasswordCode(user, purpose, {
        actorId: admin?.id,
        meta,
      });
    } catch (error) {
      if (error instanceof MailFailedError && !admin) {
        return { message: FORGOT_PASSWORD_MESSAGE };
      }
      throw error;
    }
    if (result.kind === 'limited') {
      if (admin) throw new CodeSendLimitError(result.retryAfter);
      return { message: FORGOT_PASSWORD_MESSAGE };
    }
    if (admin && onAdmin && target) {
      await this.alerts.send(admin.id, [
        {
          kind: 'ADMIN_CODE_SENT',
          targetId: user.id,
          systems: alertSystemsOf(target),
        },
      ]);
    }
    return { message: FORGOT_PASSWORD_MESSAGE };
  }

  /** The active, not deleted user a public code route acts on, or null (AC-14). */
  private async codeUser(email: string): Promise<{ id: string } | null> {
    return this.prisma.user.findFirst({
      where: {
        email: email.trim().toLowerCase(),
        isActive: true,
        deletedAt: null,
      },
      select: { id: true },
    });
  }

  /**
   * AC-14: checks the live setup or reset code without using it up. Wrong tries count (AC-4), and
   * every refusal keeps the old message.
   */
  async verifyOtp(
    email: string,
    otp: string,
    meta: RequestMeta = NO_META,
  ): Promise<{ message: string }> {
    const user = await this.codeUser(email);
    if (!user) {
      throw new BadRequestException('Invalid or expired OTP');
    }
    const result = await this.codes.check({
      target: { userId: user.id, purposes: PASSWORD_CODES },
      code: otp,
      consume: false,
      meta,
    });
    if (result.kind !== 'right') {
      throw new BadRequestException('Invalid or expired OTP');
    }
    return { message: 'OTP is valid' };
  }

  /**
   * Public: a setup or reset code sets a new password (AC-12, AC-14). It also confirms the email,
   * marks the password set, ends a lockout and ends every session, in one transaction.
   */
  async otpResetPassword(
    email: string,
    otp: string,
    newPassword: string,
    meta: RequestMeta = NO_META,
  ): Promise<{ message: string }> {
    const user = await this.codeUser(email);
    if (!user) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    // Slow work before the locks
    const passwordHash = await argon2.hash(newPassword);
    const result = await this.codes.check({
      target: { userId: user.id, purposes: PASSWORD_CODES },
      code: otp,
      consume: true,
      meta,
      onRight: async (tx) => {
        await tx.user.update({
          where: { id: user.id },
          data: {
            passwordHash,
            emailVerified: true,
            passwordSet: true,
            // Completing a code also ends a lockout
            lockedAt: null,
            failedLoginAttempts: 0,
          },
        });
        // Spec 0011, AC-6: with the CODE_USED the check writes
        await this.events.record(tx, {
          userId: user.id,
          actorId: user.id,
          type: AccountEventType.PASSWORD_CHANGED,
          meta,
        });
        // Spec 0003 AC-4: a code reset ends every session of the user
        await this.sessions.endAllForUser(
          tx,
          user.id,
          SessionEndReason.PASSWORD_CHANGED,
          { ip: meta.ip },
        );
      },
    });
    if (result.kind !== 'right') {
      throw new BadRequestException('Invalid or expired OTP');
    }

    return { message: 'Password has been reset successfully.' };
  }

  /** The signed in user, with only the roles of `system`, the token's `aud` (spec 0004, AC-17). */
  async getCurrentUser(
    userId: string,
    system: SystemType,
  ): Promise<ManagedUserResponse & { pendingEmail: string | null }> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: MANAGED_USER_SELECT,
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const mapped = this.mapManagedUser(user);
    // Spec 0009, AC-20: the address of a live email change, or null
    const pending = await this.codes.liveCode(userId, EMAIL_CHANGE);
    return {
      ...mapped,
      roles: mapped.roles.filter((r) => r.system === system),
      pendingEmail: pending?.newEmail ?? null,
    };
  }

  async updateOwnProfile(
    userId: string,
    dto: UpdateProfileDto,
    meta: RequestMeta = NO_META,
  ): Promise<ManagedUserResponse> {
    await this.ensureUserExists(userId);

    const user = await this.prisma.$transaction(async (tx) => {
      const before = await tx.user.findUniqueOrThrow({
        where: { id: userId },
        select: { name: true, contact: true },
      });
      const name = dto.name != null ? dto.name.trim() : undefined;
      const contact =
        dto.contact != null ? dto.contact.trim() || null : undefined;
      const updated = await tx.user.update({
        where: { id: userId },
        data: {
          ...(name !== undefined ? { name } : {}),
          ...(contact !== undefined ? { contact } : {}),
        },
        select: MANAGED_USER_SELECT,
      });
      // Spec 0011, AC-6: your own rename, in the same transaction
      if (name !== undefined && name !== before.name) {
        await this.events.record(
          tx,
          change(
            userId,
            { id: userId, email: updated.email, meta },
            AccountEventType.UPDATED,
            { field: 'name', oldValue: before.name, newValue: name },
          ),
        );
      }
      // Spec 0012, AC-20: the phone is a plain contact field, and its changes are logged
      if (contact !== undefined && contact !== before.contact) {
        await this.events.record(
          tx,
          change(
            userId,
            { id: userId, email: updated.email, meta },
            AccountEventType.UPDATED,
            { field: 'contact', oldValue: before.contact, newValue: contact },
          ),
        );
      }
      return updated;
    });

    return this.mapManagedUser(user);
  }

  /**
   * Spec 0009, AC-17, AC-19: start changing your own email, or resend the pending change's code
   * when `newEmail` is the pending address. `users.email` stays until the code is used. The old
   * address is told when a change starts (not on a resend).
   */
  async startEmailChange(
    userId: string,
    dto: StartEmailChangeDto,
    sid: string,
    meta: RequestMeta = NO_META,
  ): Promise<{ pendingEmail: string; expiresAt: string; resendAfter: number }> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: { id: true, name: true, email: true },
    });
    if (!user) throw new NotFoundException('User not found');
    // Spec 0012, AC-2: the shared recheck and its lockout
    await this.passwords.verifyOwnPassword({
      userId,
      password: dto.currentPassword,
      reason: PasswordCheckReason.EMAIL_CHANGE,
      sid,
      meta,
    });

    const newEmail = dto.newEmail.trim().toLowerCase();
    if (newEmail === user.email.toLowerCase()) {
      throw coded(
        HttpStatus.BAD_REQUEST,
        'SAME_EMAIL',
        'That is already your email',
      );
    }
    await validateEmailDomain(newEmail, this.production);
    await this.assertEmailFree(newEmail, userId);

    const pending = await this.codes.liveCode(userId, EMAIL_CHANGE);
    const isResend = pending?.newEmail === newEmail;
    const result = await this.codes.issue({
      userId,
      purpose: VerificationPurpose.EMAIL_CHANGE,
      newEmail,
      meta,
      mail: {
        to: newEmail,
        build: (code) => emailChangeCodeEmail({ name: user.name, code }),
      },
    });
    if (result.kind === 'limited') {
      throw new CodeSendLimitError(result.retryAfter);
    }
    if (!isResend) {
      await this.notify(
        userId,
        'EMAIL_CHANGE_STARTED',
        user.email,
        emailChangeStartedEmail({ name: user.name, newEmail }),
      );
    }
    return {
      pendingEmail: newEmail,
      expiresAt: result.expiresAt.toISOString(),
      resendAfter: result.resendAfter,
    };
  }

  /**
   * Spec 0009, AC-18: the right code moves `users.email` to the pending address and confirms it,
   * retires every other live code and records the change, all under the user row lock. Sessions
   * stay. Taken by someone else meanwhile: 409 `EMAIL_TAKEN` and the pending change is retired.
   */
  async verifyEmailChange(
    userId: string,
    code: string,
    meta: RequestMeta = NO_META,
  ): Promise<ManagedUserResponse> {
    let result: CheckResult<{ oldEmail: string; name: string }>;
    try {
      result = await this.codes.check({
        target: { userId, purposes: EMAIL_CHANGE },
        code,
        consume: true,
        meta,
        onRight: async (tx, row) => {
          // The old address, read inside the transaction before the update (Value sourcing)
          const before = await tx.user.findUniqueOrThrow({
            where: { id: userId },
            select: { email: true, name: true },
          });
          await tx.user.update({
            where: { id: userId },
            data: { email: row.newEmail!, emailVerified: true },
          });
          await this.codes.retireAll(tx, userId);
          await this.events.record(
            tx,
            change(
              userId,
              { id: userId, email: before.email, meta },
              AccountEventType.UPDATED,
              {
                field: 'email',
                oldValue: before.email,
                newValue: row.newEmail,
              },
            ),
          );
          return { oldEmail: before.email, name: before.name };
        },
      });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      await this.prisma.$transaction((tx) =>
        this.codes.retire(tx, userId, EMAIL_CHANGE),
      );
      throw emailTaken();
    }
    if (result.kind === 'wrong') throw invalidCode(result.attemptsLeft);
    if (result.kind === 'dead') throw codeExpired();

    const newEmail = result.row.newEmail!;
    await this.notify(
      userId,
      'EMAIL_CHANGED',
      result.value.oldEmail,
      emailChangedEmail({ name: result.value.name, newEmail }),
    );
    const user = await this.prisma.user.findUniqueOrThrow({
      where: { id: userId },
      select: MANAGED_USER_SELECT,
    });
    return this.mapManagedUser(user);
  }

  /** Spec 0009, AC-19: drop the pending change; 204 also when none exists. */
  async cancelEmailChange(userId: string): Promise<void> {
    await this.prisma.$transaction((tx) =>
      this.codes.retire(tx, userId, EMAIL_CHANGE),
    );
  }

  /** `currentSid` is the caller's own session, the one a password change keeps (spec 0003 AC-4). */
  async changeOwnPassword(
    userId: string,
    dto: ChangePasswordDto,
    currentSid: string,
    meta: RequestMeta = NO_META,
  ): Promise<ManagedUserResponse> {
    if (dto.newPassword !== dto.confirmPassword) {
      throw new BadRequestException(
        'New password and confirm password do not match',
      );
    }

    // Spec 0012, AC-2: the shared recheck and its lockout
    await this.passwords.verifyOwnPassword({
      userId,
      password: dto.currentPassword,
      reason: PasswordCheckReason.PASSWORD_CHANGE,
      sid: currentSid,
      meta,
    });

    const passwordHash = await argon2.hash(dto.newPassword);
    const updated = await this.prisma.$transaction(async (tx) => {
      // Spec 0003 AC-4: every other session of the user ends; this one stays
      await this.sessions.endAllForUser(
        tx,
        userId,
        SessionEndReason.PASSWORD_CHANGED,
        { exceptSid: currentSid, ip: meta.ip },
      );
      // Spec 0011, AC-6
      await this.events.record(tx, {
        userId,
        actorId: userId,
        type: AccountEventType.PASSWORD_CHANGED,
        sessionId: currentSid,
        meta,
      });
      return tx.user.update({
        where: { id: userId },
        data: { passwordHash },
        select: MANAGED_USER_SELECT,
      });
    });

    return this.mapManagedUser(updated);
  }

  async uploadProfilePicture(
    userId: string,
    file: {
      originalname: string;
      buffer: Buffer;
      size: number;
      mimetype: string;
    },
    meta: RequestMeta = NO_META,
  ): Promise<ManagedUserResponse> {
    await this.ensureUserExists(userId);

    const ext = path.extname(file.originalname).toLowerCase();
    const filename = `${userId}${ext}`;
    const uploadDir = path.resolve('uploads', 'profiles');

    await fs.mkdir(uploadDir, { recursive: true });

    const filePath = path.join(uploadDir, filename);
    await fs.writeFile(filePath, file.buffer);

    const profilePicture = `/uploads/profiles/${filename}`;

    const user = await this.prisma.$transaction(async (tx) => {
      const updated = await tx.user.update({
        where: { id: userId },
        data: { profilePicture },
        select: MANAGED_USER_SELECT,
      });
      // Spec 0011, AC-6
      await this.events.record(tx, {
        userId,
        actorId: userId,
        type: AccountEventType.PICTURE_CHANGED,
        meta,
      });
      return updated;
    });

    return this.mapManagedUser(user);
  }

  async getProfileSummary(userId: string) {
    await this.ensureUserExists(userId);
    return {
      totalLogs: 0,
      logsThisMonth: 0,
      inProgress: 0,
      completed: 0,
      totalCards: 0,
    };
  }

  private normalizeRoleAssignments(
    roleAssignments: RoleAssignmentDto[],
    allowEmpty = false,
  ): RoleAssignment[] {
    if (roleAssignments.length === 0 && !allowEmpty) {
      throw new BadRequestException('At least one role assignment is required');
    }

    const seen = new Set<string>();
    const normalized = roleAssignments.map((assignment) => ({
      role: assignment.role,
      system: assignment.system,
    }));

    for (const assignment of normalized) {
      const key = `${assignment.role}:${assignment.system}`;
      if (seen.has(key)) {
        throw new BadRequestException(
          'Duplicate role assignments are not allowed',
        );
      }
      seen.add(key);
    }

    return normalized;
  }

  /**
   * One system's view of a person (spec 0011, AC-26), or with `system` null (a suite admin,
   * spec 0013 AC-17) every system's roles and no `otherSystems`.
   */
  private mapScopedUser(
    user: ManagedUserRecord,
    system: SystemType | null,
  ): ScopedUserResponse {
    const mapped = this.mapManagedUser(user);
    const inScope = user.roles.filter(
      (r) => system === null || r.system === system,
    );
    const ends = inScope
      .map((r) => r.temporaryGrant?.expiresAt)
      .filter((at): at is Date => at instanceof Date)
      .sort((a, b) => b.getTime() - a.getTime());
    return {
      ...mapped,
      roles: mapped.roles.filter((r) => system === null || r.system === system),
      otherSystems: system === null ? [] : otherSystems(user.roles, system),
      temporaryUntil: ends[0] ? ends[0].toISOString() : null,
    };
  }

  private mapManagedUser(user: ManagedUserRecord): ManagedUserResponse {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      emailVerified: user.emailVerified,
      passwordSet: user.passwordSet,
      contact: user.contact,
      profilePicture: user.profilePicture,
      isActive: user.isActive,
      isLocked: lockActive(user.lockedAt),
      lockedAt: lockActive(user.lockedAt) ? user.lockedAt!.toISOString() : null,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
      roles: user.roles.map((role) => ({
        role: role.role,
        system: role.system,
      })),
    };
  }

  private async ensureUserExists(userId: string): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: { id: true },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }
  }

  private handlePrismaError(error: unknown): never {
    if (typeof error === 'object' && error !== null && 'code' in error) {
      const code = (error as { code?: string }).code;
      if (code === 'P2002') {
        throw new ConflictException('Email already exists');
      }
    }

    throw error as Error;
  }
}
