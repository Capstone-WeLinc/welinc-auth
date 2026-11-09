import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
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
import { ResetPasswordDto } from './dto/reset-password.dto';
import { SetUserStatusDto } from './dto/set-user-status.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { RoleAssignmentDto } from './dto/role-assignment.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { ListChangesQueryDto } from './dto/list-changes.query.dto';
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

/** A 6 digit setup or reset code from a secure random source (never `Math.random`). */
export function newOtp(): string {
  return crypto.randomInt(100_000, 1_000_000).toString();
}

/** Domains a development machine accepts without a DNS lookup. */
export const DEV_EMAIL_DOMAINS = [
  'welinc.com',
  'localhost',
  'test.com',
  'example.com',
];

export async function validateEmailDomain(email: string): Promise<void> {
  const domain = email.split('@')[1];
  if (!domain) {
    throw new BadRequestException('Invalid email format');
  }

  // Made up test addresses skip the mail check on your own machine only; when hosted, every
  // address must be on a domain that can receive mail, or its setup and reset codes never arrive
  if (
    process.env.NODE_ENV !== 'production' &&
    DEV_EMAIL_DOMAINS.includes(domain.toLowerCase())
  ) {
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
  contact: string | null;
  profilePicture: string | null;
  isActive: boolean;
  lockedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  roles: RoleAssignment[];
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

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokenService,
    private readonly mailService: MailService,
    config: ConfigService,
    private readonly sessions: SessionService,
    private readonly catalog: CatalogService,
  ) {
    const portalUrl = config.get<string>('PORTAL_URL');
    if (!portalUrl && config.get<string>('NODE_ENV') === 'production') {
      throw new Error('PORTAL_URL is required in production');
    }
    this.passwordLink = `${(portalUrl || 'http://localhost:8000').replace(/\/+$/, '')}/forgot-password`;
  }

  /**
   * Checks a password login: lockout (5 failures), deactivation, then the system pick (spec 0002,
   * AC-5). Answers the user and the system; the caller creates the session (spec 0003, AC-11).
   */
  /**
   * The password check shared by the portal and the mobile login: lockout, inactive accounts,
   * the failure counter. Which systems the person may enter is decided by the caller (the
   * launcher answer, spec 0007; the mobile grant, spec 0004).
   */
  async checkCredentials(dto: Pick<LoginDto, 'email' | 'password'>): Promise<{
    user: {
      id: string;
      name: string;
      email: string;
      profilePicture: string | null;
    };
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
      throw new ForbiddenException({
        message: 'Account is locked. Contact your Admin to unlock.',
        remainingAttempts: 0,
        isLocked: true,
      });
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
        throw new ForbiddenException({
          message: 'Account is locked. Contact your Admin to unlock.',
          remainingAttempts: 0,
          isLocked: true,
        });
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
      },
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

    await validateEmailDomain(dto.email);

    let passwordHash: string;
    let setupOtp: string | null = null;

    if (dto.password) {
      passwordHash = await argon2.hash(dto.password);
    } else {
      const tempPassword = crypto.randomBytes(32).toString('hex');
      passwordHash = await argon2.hash(tempPassword);
      setupOtp = newOtp();
    }

    let user: Prisma.UserGetPayload<{ select: typeof MANAGED_USER_SELECT }>;
    try {
      user = await this.prisma.$transaction(async (tx) => {
        const created = await tx.user.create({
          data: {
            name: dto.name.trim(),
            email: dto.email.trim().toLowerCase(),
            passwordHash,
            isActive: dto.isActive ?? true,
            roles: {
              create: roleAssignments,
            },
          },
          select: MANAGED_USER_SELECT,
        });

        if (setupOtp) {
          await tx.passwordResetToken.create({
            data: {
              userId: created.id,
              otp: setupOtp,
              expiresAt: new Date(Date.now() + 1 * 60 * 60 * 1000), // 1 hour
            },
          });
        }

        await tx.userChange.create({
          data: change(created.id, actor, UserChangeAction.CREATED),
        });
        return created;
      });
    } catch (error) {
      this.handlePrismaError(error);
    }

    // The user is saved: a mail failure only sets setupEmailSent to false (AC-18)
    const setupEmailSent = setupOtp
      ? await this.trySendMail('setup', {
          to: user.email,
          subject: 'WeLinc Logistics - Account Setup',
          text: `Welcome to WeLinc Logistics, ${user.name}!

Your account has been created by the administrator.
To set up your password, please use the following one-time code:

Setup Code: ${setupOtp}

Please visit the link below to set up your password:
${this.passwordLink}

This code will expire in 1 hour.`,
          html: `<p>Welcome to WeLinc Logistics, <strong>${user.name}</strong>!</p>
<p>Your account has been created by the administrator.</p>
<p>To set up your password, please use the following one-time code:</p>
<h2 style="font-size: 24px; font-weight: bold; color: #1a1f6e; letter-spacing: 2px;">${setupOtp}</h2>
<p>Please visit the link below to set up your password:</p>
<p><a href="${this.passwordLink}" style="color: #1a1f6e; font-weight: bold; text-decoration: underline;">Set up your password</a></p>
<p>This code will expire in 1 hour.</p>`,
        })
      : false;

    return { ...this.mapScopedUser(user, actor.system), setupEmailSent };
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
  ): Promise<ScopedUserResponse> {
    const userSelect = {
      id: true,
      name: true,
      email: true,
      isActive: true,
      deletedAt: true,
      roles: {
        select: {
          role: true,
          system: true,
        },
      },
    } satisfies Prisma.UserSelect;

    // Outside the transaction: only the early 404 and the slow work (DNS and the password hash).
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

    const newEmail = dto.email?.trim().toLowerCase();
    if (dto.email && newEmail && newEmail !== current.email.toLowerCase()) {
      await validateEmailDomain(dto.email);
    }
    const passwordHash = dto.password
      ? await argon2.hash(dto.password)
      : undefined;

    try {
      const user = await this.prisma.$transaction(async (tx) => {
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
        if (isEmailChanging || passwordHash) {
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
            ...(isEmailChanging ? { email: newEmail } : {}),
            ...(passwordHash ? { passwordHash } : {}),
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
        return updated;
      });

      return this.mapScopedUser(user, actor.system);
    } catch (error) {
      this.handlePrismaError(error);
    }
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
   * Admin-only: reset a user's password by userId.
   */
  async resetPassword(
    userId: string,
    dto: ResetPasswordDto,
    actor: AdminCaller,
  ): Promise<ScopedUserResponse> {
    const existing = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: { roles: { select: { role: true, system: true } } },
    });
    assertInSystem(existing, actor.system);
    assertNotAdminElsewhere(
      existing.roles,
      actor.system,
      await this.catalog.adminRoles(),
    );

    const passwordHash = await argon2.hash(dto.password);
    const user = await this.prisma.$transaction(async (tx) => {
      const updated = await tx.user.update({
        where: { id: userId },
        data: { passwordHash, failedLoginAttempts: 0, lockedAt: null },
        select: MANAGED_USER_SELECT,
      });
      // Spec 0003 AC-4: an admin password set ends every session of the user
      await this.sessions.endAllForUser(
        tx,
        userId,
        SessionEndReason.PASSWORD_CHANGED,
        { endedById: actor.id },
      );
      return updated;
    });

    return this.mapScopedUser(user, actor.system);
  }

  /**
   * Public. Sends nothing to an unknown, inactive or deleted user, with the same answer either way.
   * A new code retires the user's older unused ones. Sent by an admin of one of the user's systems,
   * it is recorded as RESET_SENT (spec 0009, AC-17, AC-20).
   */
  async forgotPassword(
    email: string,
    caller: OptionalCaller = null,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        name: true,
        email: true,
        isActive: true,
        deletedAt: true,
        roles: { select: { system: true } },
      },
    });

    // Always the same answer, to prevent user enumeration
    if (!user || !user.isActive || user.deletedAt) {
      return { message: FORGOT_PASSWORD_MESSAGE };
    }

    const otp = newOtp();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    const admins = caller ? await this.catalog.adminRoles() : null;
    const admin =
      caller &&
      admins &&
      user.roles.some((target) =>
        holdsAdmin(caller.roles, target.system, admins),
      )
        ? { id: caller.sub, email: caller.email }
        : null;

    await this.prisma.$transaction(async (tx) => {
      await tx.passwordResetToken.updateMany({
        where: { userId: user.id, usedAt: null },
        data: { usedAt: new Date() },
      });
      await tx.passwordResetToken.create({
        data: {
          userId: user.id,
          otp,
          expiresAt,
        },
      });
      if (admin) {
        await tx.userChange.create({
          data: change(user.id, admin, UserChangeAction.RESET_SENT),
        });
      }
    });

    await this.trySendMail('reset', {
      to: user.email,
      subject: 'WeLinc Logistics - Password Reset Request',
      text: `Hello, ${user.name || 'User'}!

You have requested to reset your password.
Please use the following one-time code to complete the process:

Reset Code: ${otp}

Please visit the link below to verify and reset your password:
${this.passwordLink}

This code will expire in 10 minutes.`,
      html: `<p>Hello, <strong>${user.name || 'User'}</strong>!</p>
<p>You have requested to reset your password.</p>
<p>Please use the following one-time code to complete the process:</p>
<h2 style="font-size: 24px; font-weight: bold; color: #1a1f6e; letter-spacing: 2px;">${otp}</h2>
<p>Please visit the link below to verify and reset your password:</p>
<p><a href="${this.passwordLink}" style="color: #1a1f6e; font-weight: bold; text-decoration: underline;">Reset your password</a></p>
<p>This code will expire in 10 minutes.</p>`,
    });

    return { message: FORGOT_PASSWORD_MESSAGE };
  }

  async verifyOtp(email: string, otp: string): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    const token = await this.prisma.passwordResetToken.findFirst({
      where: {
        userId: user.id,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!token || token.otp !== otp) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    return { message: 'OTP is valid' };
  }

  /**
   * Public: verify OTP and set a new password.
   */
  async otpResetPassword(
    email: string,
    otp: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (!user) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    const token = await this.prisma.passwordResetToken.findFirst({
      where: {
        userId: user.id,
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!token || token.otp !== otp) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    // Mark token as used, update password, and set emailVerified to true atomically
    const passwordHash = await argon2.hash(newPassword);
    await this.prisma.$transaction(async (tx) => {
      await tx.passwordResetToken.update({
        where: { id: token.id },
        data: { usedAt: new Date() },
      });
      await tx.user.update({
        where: { id: user.id },
        data: {
          passwordHash,
          emailVerified: true,
          // Completing a code also ends a lockout (AC-17)
          lockedAt: null,
          failedLoginAttempts: 0,
        },
      });
      // Spec 0003 AC-4: an OTP reset ends every session of the user
      await this.sessions.endAllForUser(
        tx,
        user.id,
        SessionEndReason.PASSWORD_CHANGED,
      );
    });

    return { message: 'Password has been reset successfully.' };
  }

  /** The signed in user, with only the roles of `system`, the token's `aud` (spec 0004, AC-17). */
  async getCurrentUser(
    userId: string,
    system: SystemType,
  ): Promise<ManagedUserResponse> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: {
        id: true,
        name: true,
        email: true,
        emailVerified: true,
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
          },
        },
      },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const mapped = this.mapManagedUser(user);
    return {
      ...mapped,
      roles: mapped.roles.filter((r) => r.system === system),
    };
  }

  async updateOwnProfile(
    userId: string,
    dto: UpdateProfileDto,
  ): Promise<ManagedUserResponse> {
    await this.ensureUserExists(userId);

    if (dto.email) {
      const emailLower = dto.email.trim().toLowerCase();
      const currentUser = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { email: true },
      });
      if (currentUser && currentUser.email.toLowerCase() !== emailLower) {
        await validateEmailDomain(dto.email);
      }
    }

    const user = await this.prisma.user.update({
      where: { id: userId },
      data: {
        ...(dto.name != null ? { name: dto.name.trim() } : {}),
        ...(dto.email != null ? { email: dto.email.trim().toLowerCase() } : {}),
        ...(dto.contact != null ? { contact: dto.contact.trim() || null } : {}),
      },
      select: {
        id: true,
        name: true,
        email: true,
        emailVerified: true,
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
          },
        },
      },
    });

    return this.mapManagedUser(user);
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
        select: {
          id: true,
          name: true,
          email: true,
          emailVerified: true,
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
            },
          },
        },
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
      select: {
        id: true,
        name: true,
        email: true,
        emailVerified: true,
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
          },
        },
      },
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

  /** True when sent. A failure is logged without the email's content, so no code reaches the logs. */
  private async trySendMail(
    kind: 'setup' | 'reset',
    options: { to: string; subject: string; text: string; html: string },
  ): Promise<boolean> {
    try {
      await this.mailService.sendMail(options);
      return true;
    } catch (error) {
      this.logger.error(
        `Could not send the ${kind} email to ${options.to}: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
      return false;
    }
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
