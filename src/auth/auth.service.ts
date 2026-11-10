import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
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
  Prisma,
  SessionEndReason,
  SystemType,
  UserChangeAction,
  VerificationPurpose,
} from '@prisma/client';
import { PrismaService } from '../shared/prisma.service';
import { CatalogService, holdsAdmin } from './roles/catalog.service';
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
import { ListChangesQueryDto } from './dto/list-changes.query.dto';
import { StartEmailChangeDto } from './dto/email-verification.dto';
import { coded } from './errors';
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
  decodeChangeCursor,
  encodeChangeCursor,
  rolesKey,
} from './user-changes';
import {
  AdminCaller,
  LOOKUP_LIMIT,
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

const accountLocked = () =>
  new ForbiddenException({
    code: 'ACCOUNT_LOCKED',
    message: 'Account is locked. Contact your Admin to unlock.',
    remainingAttempts: 0,
    isLocked: true,
  });

/** Domains a development machine accepts without a DNS lookup. */
export const DEV_EMAIL_DOMAINS = [
  'welinc.com',
  'localhost',
  'test.com',
  'example.com',
];

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

const MAX_FAILED_ATTEMPTS = 5;
const CHANGES_PAGE_SIZE = 50;
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
  roles: { select: { role: true, system: true } },
} satisfies Prisma.UserSelect;

/** The signed in caller of a public route, when they sent a valid token (OptionalJwtAuthGuard). */
export type OptionalCaller = {
  sub: string;
  email: string;
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
  roles: RoleAssignment[];
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
  async checkCredentials(dto: Pick<LoginDto, 'email' | 'password'>): Promise<{
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

    // User not found — generic message to prevent user enumeration
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Locked account check — must happen before password validation
    if (user.lockedAt !== null) {
      throw accountLocked();
    }

    // Deactivated account
    if (!user.isActive) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await argon2.verify(
      user.passwordHash,
      dto.password,
    );

    if (!isPasswordValid) {
      const newAttempts = user.failedLoginAttempts + 1;
      const shouldLock = newAttempts >= MAX_FAILED_ATTEMPTS;

      await this.prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: newAttempts,
          ...(shouldLock ? { lockedAt: new Date() } : {}),
        },
      });

      if (shouldLock) {
        throw accountLocked();
      }

      throw new UnauthorizedException({
        message: 'Invalid credentials',
        remainingAttempts: MAX_FAILED_ATTEMPTS - newAttempts,
        isLocked: false,
      });
    }

    // Successful login — reset failure counter
    await this.prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0 },
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
  async assertCanSignIn(userId: string): Promise<SignInUser> {
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
    if (!user) throw new UnauthorizedException('Invalid credentials');
    if (user.lockedAt !== null) throw accountLocked();
    if (!user.isActive) throw new UnauthorizedException('Invalid credentials');
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      profilePicture: user.profilePicture,
    };
  }

  async unlockUser(
    userId: string,
    actor: AdminCaller,
  ): Promise<ScopedUserResponse> {
    const user = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.user.findFirst({
        where: { id: userId, deletedAt: null },
        select: {
          lockedAt: true,
          roles: { select: { role: true, system: true } },
        },
      });
      assertInSystem(existing, actor.system);
      // Not locked: nothing changes, so no change row
      if (existing.lockedAt === null) {
        return tx.user.findUniqueOrThrow({
          where: { id: userId },
          select: MANAGED_USER_SELECT,
        });
      }
      const updated = await tx.user.update({
        where: { id: userId },
        data: { lockedAt: null, failedLoginAttempts: 0 },
        select: MANAGED_USER_SELECT,
      });
      await tx.userChange.create({
        data: change(userId, actor, UserChangeAction.UNLOCKED),
      });
      return updated;
    });

    return this.mapScopedUser(user, actor.system);
  }

  /**
   * Only users who hold a role in the caller's system. A `system` query can't widen it: the
   * guard already refused a `?system=` that differs from the token's `aud`. A `role` filter is
   * checked against that system's catalog (spec 0004, AC-9).
   */
  async listUsers(
    query: ListUsersQueryDto,
    caller: Pick<AdminCaller, 'system'>,
  ): Promise<ScopedUserResponse[]> {
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
      select: MANAGED_USER_SELECT,
      orderBy: {
        createdAt: 'desc',
      },
    });

    return users.map((user) => this.mapScopedUser(user, caller.system));
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

        await tx.userChange.create({
          data: change(created.id, actor, UserChangeAction.CREATED),
        });
        return created;
      });
    } catch (error) {
      this.handlePrismaError(error);
    }

    // The user is saved: a failed or refused send only sets setupEmailSent to false. An inactive
    // user's code works once an admin activates them, while it lives (AC-15).
    const setupEmailSent = await this.trySendPasswordCode(
      user,
      VerificationPurpose.PASSWORD_SETUP,
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
  ): Promise<boolean> {
    try {
      const result = await this.issuePasswordCode(user, purpose);
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
  ) {
    return this.codes.issue({
      userId: user.id,
      purpose,
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

  /** Adds the caller's system roles only; password, name and other roles stay (AC-30). */
  private async attachExistingAccount(
    userId: string,
    roleAssignments: RoleAssignment[],
    actor: AdminCaller,
  ): Promise<ScopedUserResponse> {
    const user = await this.prisma.$transaction(async (tx) => {
      // Spec 0004, AC-13: the account row first, then everything is decided from a fresh read
      await lockAccount(tx, userId);
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
      await tx.userChange.create({
        data: change(userId, actor, UserChangeAction.ROLE_CHANGED, {
          field: 'roles',
          oldValue: rolesKey(current.roles),
          newValue: rolesKey([...current.roles, ...roleAssignments]),
        }),
      });
      return tx.user.findUniqueOrThrow({
        where: { id: userId },
        select: MANAGED_USER_SELECT,
      });
    });

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
      const { user, oldEmail } = await this.prisma.$transaction(async (tx) => {
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
        // Another system's admin keeps their own sign in details (spec 0011, AC-28)
        if (isEmailChanging) {
          assertNotAdminElsewhere(existingUser.roles, actor.system, admins);
        }
        const isNameChanging = !!newName && newName !== existingUser.name;
        const roleAssignments = requestedRoles
          ? replaceSystemRoles(existingUser.roles, requestedRoles, actor.system)
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

        const updated = await tx.user.update({
          where: { id: userId },
          data: {
            ...(isNameChanging ? { name: newName } : {}),
            // Confirmed at their next sign in (spec 0009, AC-21)
            ...(isEmailChanging
              ? { email: newEmail, emailVerified: false }
              : {}),
            ...(isActiveChanging ? { isActive: dto.isActive } : {}),
            ...(areRolesChanging
              ? {
                  roles: {
                    deleteMany: {},
                    create: roleAssignments,
                  },
                }
              : {}),
          },
          select: MANAGED_USER_SELECT,
        });

        const changes: Prisma.UserChangeCreateManyInput[] = [];
        if (isNameChanging) {
          changes.push(
            change(userId, actor, UserChangeAction.UPDATED, {
              field: 'name',
              oldValue: existingUser.name,
              newValue: newName,
            }),
          );
        }
        if (isEmailChanging) {
          changes.push(
            change(userId, actor, UserChangeAction.UPDATED, {
              field: 'email',
              oldValue: existingUser.email,
              newValue: newEmail,
            }),
          );
        }
        if (areRolesChanging) {
          changes.push(
            change(userId, actor, UserChangeAction.ROLE_CHANGED, {
              field: 'roles',
              oldValue: rolesKey(existingUser.roles),
              newValue: rolesKey(roleAssignments),
            }),
          );
        }
        if (isActiveChanging) {
          changes.push(
            change(
              userId,
              actor,
              dto.isActive
                ? UserChangeAction.ACTIVATED
                : UserChangeAction.DEACTIVATED,
            ),
          );
        }
        if (changes.length > 0) {
          await tx.userChange.createMany({ data: changes });
        }
        if (isEmailChanging) {
          // AC-2: every live code of the user dies with the old address
          await this.codes.retireAll(tx, userId);
        }
        return {
          user: updated,
          oldEmail: isEmailChanging ? existingUser.email : null,
        };
      });

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
      );
      return { ...answer, setupEmailSent };
    } catch (error) {
      if (isUniqueViolation(error)) throw emailTaken();
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
      await tx.userChange.create({
        data: change(
          userId,
          actor,
          dto.isActive
            ? UserChangeAction.ACTIVATED
            : UserChangeAction.DEACTIVATED,
        ),
      });
      // Spec 0003 AC-4: deactivation ends every live session at once
      if (!dto.isActive) {
        await this.sessions.endAllForUser(
          tx,
          userId,
          SessionEndReason.DEACTIVATED,
          { endedById: actor.id },
        );
      }
      return updated;
    });

    return this.mapScopedUser(user, actor.system);
  }

  async deleteUser(
    userId: string,
    actor: AdminCaller,
  ): Promise<{ id: string }> {
    if (actor.id === userId) throw new ConflictException(SELF_DELETE);

    await this.prisma.$transaction(async (tx) => {
      // The account row before any admin role rows (spec 0004, AC-13 lock order)
      await lockAccount(tx, userId);
      const existing = await tx.user.findFirst({
        where: { id: userId, deletedAt: null },
        select: {
          isActive: true,
          roles: { select: { role: true, system: true } },
        },
      });
      assertInSystem(existing, actor.system);
      assertNotShared(existing.roles, actor.system);
      if (existing.isActive) {
        const admins = await this.catalog.adminRoles(tx);
        for (const system of adminSystems(existing.roles, admins)) {
          await assertAnotherAdmin(tx, userId, system);
        }
      }
      await tx.user.update({
        where: { id: userId },
        data: {
          deletedAt: new Date(),
          isActive: false,
          lockedAt: null,
        },
      });
      await tx.userChange.create({
        data: change(userId, actor, UserChangeAction.DELETED),
      });
      // Spec 0003 AC-4
      await this.sessions.endAllForUser(tx, userId, SessionEndReason.DELETED, {
        endedById: actor.id,
      });
    });

    return { id: userId };
  }

  /**
   * Public (spec 0009, AC-13). Sends nothing to an unknown, inactive or deleted user, and answers
   * the same message either way, also inside the wait or over the limit. An admin of one of the
   * user's systems instead gets 429 `CODE_SEND_LIMIT` or 503 `MAIL_FAILED`, and the send is
   * recorded as RESET_SENT once it succeeded. A setup code goes out while setup is pending.
   */
  async forgotPassword(
    email: string,
    caller: OptionalCaller = null,
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
        ? { id: caller.sub, email: caller.email }
        : null;

    const purpose = user.passwordSet
      ? VerificationPurpose.PASSWORD_RESET
      : VerificationPurpose.PASSWORD_SETUP;
    let result: Awaited<ReturnType<AuthService['issuePasswordCode']>>;
    try {
      result = await this.issuePasswordCode(user, purpose);
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
    if (admin) {
      await this.prisma.userChange.create({
        data: change(user.id, admin, UserChangeAction.RESET_SENT),
      });
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
  async verifyOtp(email: string, otp: string): Promise<{ message: string }> {
    const user = await this.codeUser(email);
    if (!user) {
      throw new BadRequestException('Invalid or expired OTP');
    }
    const result = await this.codes.check({
      target: { userId: user.id, purposes: PASSWORD_CODES },
      code: otp,
      consume: false,
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
        // Spec 0003 AC-4: a code reset ends every session of the user
        await this.sessions.endAllForUser(
          tx,
          user.id,
          SessionEndReason.PASSWORD_CHANGED,
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
  ): Promise<ManagedUserResponse> {
    await this.ensureUserExists(userId);

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: {
        ...(dto.name != null ? { name: dto.name.trim() } : {}),
        ...(dto.contact != null ? { contact: dto.contact.trim() || null } : {}),
      },
      select: MANAGED_USER_SELECT,
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
  ): Promise<{ pendingEmail: string; expiresAt: string; resendAfter: number }> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: { id: true, name: true, email: true, passwordHash: true },
    });
    if (!user) throw new NotFoundException('User not found');
    if (!(await argon2.verify(user.passwordHash, dto.currentPassword))) {
      throw new BadRequestException('Current password is incorrect');
    }

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
  ): Promise<ManagedUserResponse> {
    let result: CheckResult<{ oldEmail: string; name: string }>;
    try {
      result = await this.codes.check({
        target: { userId, purposes: EMAIL_CHANGE },
        code,
        consume: true,
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
          await tx.userChange.create({
            data: change(
              userId,
              { id: userId, email: before.email },
              UserChangeAction.UPDATED,
              {
                field: 'email',
                oldValue: before.email,
                newValue: row.newEmail,
              },
            ),
          });
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
  ): Promise<ManagedUserResponse> {
    if (dto.newPassword !== dto.confirmPassword) {
      throw new BadRequestException(
        'New password and confirm password do not match',
      );
    }

    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: {
        id: true,
        passwordHash: true,
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const isCurrentPasswordValid = await argon2.verify(
      user.passwordHash,
      dto.currentPassword,
    );

    if (!isCurrentPasswordValid) {
      throw new BadRequestException('Current password is incorrect');
    }

    const passwordHash = await argon2.hash(dto.newPassword);
    const updated = await this.prisma.$transaction(async (tx) => {
      // Spec 0003 AC-4: every other session of the user ends; this one stays
      await this.sessions.endAllForUser(
        tx,
        userId,
        SessionEndReason.PASSWORD_CHANGED,
        { exceptSid: currentSid },
      );
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
  ): Promise<ManagedUserResponse> {
    await this.ensureUserExists(userId);

    const ext = path.extname(file.originalname).toLowerCase();
    const filename = `${userId}${ext}`;
    const uploadDir = path.resolve('uploads', 'profiles');

    await fs.mkdir(uploadDir, { recursive: true });

    const filePath = path.join(uploadDir, filename);
    await fs.writeFile(filePath, file.buffer);

    const profilePicture = `/uploads/profiles/${filename}`;

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: { profilePicture },
      select: MANAGED_USER_SELECT,
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

  /**
   * Spec 0009, AC-21: a user's change record, newest first, keyset paged on (createdAt, id).
   * Only for users in the caller's system (spec 0011, AC-26).
   */
  async getUserChanges(
    userId: string,
    query: ListChangesQueryDto,
    caller: AdminCaller,
  ) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, roles: { select: { role: true, system: true } } },
    });
    assertInSystem(user, caller.system);

    const limit = query.limit ?? CHANGES_PAGE_SIZE;
    const cursor = query.cursor ? decodeChangeCursor(query.cursor) : null;
    const rows = await this.prisma.userChange.findMany({
      where: {
        userId,
        ...(cursor
          ? {
              OR: [
                { createdAt: { lt: cursor.createdAt } },
                { createdAt: cursor.createdAt, id: { lt: cursor.id } },
              ],
            }
          : {}),
      },
      select: {
        id: true,
        action: true,
        field: true,
        oldValue: true,
        newValue: true,
        actorId: true,
        actorEmail: true,
        createdAt: true,
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
    });

    const page = rows.slice(0, limit);
    return {
      data: page.map((row) => ({
        ...row,
        createdAt: row.createdAt.toISOString(),
      })),
      nextCursor:
        rows.length > limit ? encodeChangeCursor(page[page.length - 1]) : null,
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

  private mapScopedUser(
    user: ManagedUserRecord,
    system: SystemType,
  ): ScopedUserResponse {
    const mapped = this.mapManagedUser(user);
    return {
      ...mapped,
      roles: mapped.roles.filter((r) => r.system === system),
      otherSystems: otherSystems(user.roles, system),
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
      isLocked: user.lockedAt !== null,
      lockedAt: user.lockedAt ? user.lockedAt.toISOString() : null,
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
