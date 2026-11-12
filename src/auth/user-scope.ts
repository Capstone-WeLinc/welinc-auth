import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { SystemType } from '@prisma/client';
import type { Actor } from './user-changes';
import type { AdminRoles } from './roles/catalog.service';
import type { RoleAssignment } from './roles/catalog.types';

// Spec 0011, AC-26 to AC-30: admin user endpoints act only inside the caller's system.

/**
 * The scope every admin account action runs in (spec 0013, AC-16): the signed in admin, the
 * system their request resolved to (the token's `aud` on bearer routes, the checked `system`
 * input on `/auth/admin/*`), and their session, which a reauth token is bound to (AC-14).
 */
export type AdminCaller = Actor & {
  system: SystemType;
  sid: string;
  /** A suite admin acting in `system` (AC-17); false or left out for a system admin. */
  suite?: boolean;
};

/**
 * Spec 0013, AC-17: a suite admin acting with no system, on the routes that allow it (lists,
 * activity, deletion requests, delete, restore and the deletion decisions).
 */
export type SuiteScope = Actor & { system: null; sid: string; suite: true };

/** Where an account action runs: one system, or (suite admins only) the whole suite. */
export type AccountScope = AdminCaller | SuiteScope;

/** 404 unless the person is in scope: any existing person for a suite wide caller. */
export function assertInScope<T extends { roles: RoleAssignment[] }>(
  user: T | null | undefined,
  system: SystemType | null,
): asserts user is T {
  if (system === null) {
    if (!user) throw new NotFoundException('User not found');
    return;
  }
  assertInSystem(user, system);
}

/** Lookups each admin may run per minute (AC-29). */
export const LOOKUP_PER_MINUTE = 30;
export const LOOKUP_LIMIT = 10;

/** 404 unless the user holds a role in `system`, so other systems' users look absent (AC-26). */
export function assertInSystem<T extends { roles: RoleAssignment[] }>(
  user: T | null | undefined,
  system: SystemType,
): asserts user is T {
  if (!user || !user.roles.some((r) => r.system === system)) {
    throw new NotFoundException('User not found');
  }
}

/** The other systems this account holds a role in, sorted, each once. */
export function otherSystems(
  roles: { system: SystemType }[],
  system: SystemType,
): SystemType[] {
  return [
    ...new Set(roles.filter((r) => r.system !== system).map((r) => r.system)),
  ].sort();
}

/** The other systems this account holds the admin role of, sorted (spec 0004, AC-14). */
export function otherAdminSystems(
  roles: RoleAssignment[],
  system: SystemType,
  admins: AdminRoles,
): SystemType[] {
  return otherSystems(
    roles.filter((r) => admins.get(r.system) === r.role),
    system,
  );
}

/** 403 when any requested role belongs to another system (AC-27). */
export function assertOwnSystemRoles(
  roles: RoleAssignment[],
  system: SystemType,
): void {
  if (roles.some((r) => r.system !== system)) {
    throw new ForbiddenException(`You can only change ${system} roles.`);
  }
}

/** The account's roles after an edit: every other system's role kept, the caller's replaced. */
export function replaceSystemRoles(
  existing: RoleAssignment[],
  requested: RoleAssignment[],
  system: SystemType,
): RoleAssignment[] {
  const kept = existing.filter((r) => r.system !== system);
  if (kept.length === 0 && requested.length === 0) {
    throw new BadRequestException(
      'An account needs at least one role. Deactivate it instead.',
    );
  }
  return [...kept, ...requested];
}

/** 403 on a password or email change for an account that is an admin elsewhere (AC-28). */
export function assertNotAdminElsewhere(
  roles: RoleAssignment[],
  system: SystemType,
  admins: AdminRoles,
): void {
  const systems = otherAdminSystems(roles, system, admins);
  if (systems.length > 0) {
    throw new ForbiddenException(
      `This account is an admin in ${systems.join(', ')}. Send a reset code instead.`,
    );
  }
}

/** 403 on deleting an account another system still uses (AC-28). */
export function assertNotShared(
  roles: RoleAssignment[],
  system: SystemType,
): void {
  const systems = otherSystems(roles, system);
  if (systems.length > 0) {
    throw new ForbiddenException(
      `This account is shared with ${systems.join(', ')}. Remove its ${system} role instead.`,
    );
  }
}

/**
 * Fixed one minute window per admin, in memory (AC-29). Each replica counts on its own, which is
 * fine for a guard against scraping: the limit only ever gets looser by the replica count.
 */
export class LookupLimiter {
  private readonly windows = new Map<
    string,
    { start: number; count: number }
  >();

  constructor(
    private readonly perMinute = LOOKUP_PER_MINUTE,
    private readonly now: () => number = Date.now,
  ) {}

  hit(adminId: string): void {
    const now = this.now();
    const window = this.windows.get(adminId);
    if (!window || now - window.start >= 60_000) {
      this.prune(now);
      this.windows.set(adminId, { start: now, count: 1 });
      return;
    }
    if (window.count >= this.perMinute) {
      throw new HttpException(
        'Too many searches. Wait a minute and try again.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
    window.count += 1;
  }

  private prune(now: number): void {
    for (const [id, window] of this.windows) {
      if (now - window.start >= 60_000) this.windows.delete(id);
    }
  }
}
