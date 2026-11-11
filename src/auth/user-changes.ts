import { ConflictException } from '@nestjs/common';
import { AccountEventType, Prisma, SystemType } from '@prisma/client';
import type { EventInput } from './events/account-events.service';
import type { RequestMeta } from './events/request-meta';
import type { AdminRoles } from './roles/catalog.service';
import type { RoleAssignment } from './roles/catalog.types';

// Spec 0009, AC-19 to AC-21: the admin safety guards. Spec 0011: account changes are ACCOUNT
// events in account_events, written in the change's transaction (AC-6, AC-7).

/** Who made a change, and from where (spec 0011, AC-3). The email is never stored. */
export type Actor = { id: string; email: string; meta?: RequestMeta };

export const SELF_DEACTIVATE = "You can't deactivate your own account.";
export const SELF_ROLE = "You can't change your own role.";
export const SELF_DELETE = "You can't delete your own account.";

/** Roles as stored in a ROLE_CHANGED row: sorted `ROLE@SYSTEM`, comma separated. */
export function rolesKey(roles: RoleAssignment[]): string {
  return roles
    .map((r) => `${r.role}@${r.system}`)
    .sort()
    .join(',');
}

/**
 * The systems this user holds the admin role of (the catalog's `isSystemAdmin`, spec 0004
 * AC-14), sorted. Callers lock each system's admin rows in this order, so two writes that touch
 * the same systems always lock them the same way and can't deadlock.
 */
export function adminSystems(
  roles: RoleAssignment[],
  admins: AdminRoles,
): SystemType[] {
  return roles
    .filter((r) => admins.get(r.system) === r.role)
    .map((r) => r.system)
    .sort();
}

/**
 * Spec 0004, AC-13: the first statement of every role write on an existing account. Locks the
 * account row, so two admins editing one account run one after the other. Lock order is always
 * this row first, then any `user_roles` rows (`assertAnotherAdmin`).
 */
export async function lockAccount(
  tx: Prisma.TransactionClient,
  userId: string,
): Promise<void> {
  await tx.$queryRaw`SELECT id FROM users WHERE id = ${userId}::uuid FOR UPDATE`;
}

/** One account change event for `userId`, made by `actor` (write it with AccountEventsService). */
export function change(
  userId: string,
  actor: Actor,
  type: AccountEventType,
  values: {
    field?: string;
    oldValue?: string | null;
    newValue?: string | null;
    reason?: string;
    system?: SystemType;
  } = {},
): EventInput {
  return {
    userId,
    actorId: actor.id,
    type,
    field: values.field ?? null,
    oldValue: values.oldValue ?? null,
    newValue: values.newValue ?? null,
    reason: values.reason ?? null,
    system: values.system ?? null,
    meta: actor.meta,
  };
}

/**
 * AC-6: one `ROLE_CHANGED` per system whose roles changed, `system` set, each side holding only
 * that system's roles in `rolesKey()` form (null for an empty side).
 */
export function roleChanges(
  userId: string,
  actor: Actor,
  before: RoleAssignment[],
  after: RoleAssignment[],
): EventInput[] {
  const systems = [...new Set([...before, ...after].map((r) => r.system))];
  return systems.sort().flatMap((system) => {
    const old = rolesKey(before.filter((r) => r.system === system)) || null;
    const now = rolesKey(after.filter((r) => r.system === system)) || null;
    if (old === now) return [];
    return [
      change(userId, actor, AccountEventType.ROLE_CHANGED, {
        field: 'roles',
        oldValue: old,
        newValue: now,
        system,
      }),
    ];
  });
}

/**
 * Inside the write's transaction: 409 unless another active, non deleted holder of `system`'s
 * admin role stays (spec 0004, AC-15). Locks that system's admin role rows first, so two admins
 * demoting or deactivating each other at once can't both pass.
 */
export async function assertAnotherAdmin(
  tx: Prisma.TransactionClient,
  targetId: string,
  system: SystemType,
): Promise<void> {
  await tx.$queryRaw`
    SELECT ur.id FROM user_roles ur
    JOIN system_roles sr ON sr.system = ur.system AND sr.code = ur.role
    WHERE sr.is_system_admin AND ur.system = ${system}::"SystemType"
    FOR UPDATE OF ur`;
  const others = await tx.user.count({
    where: {
      id: { not: targetId },
      isActive: true,
      deletedAt: null,
      roles: { some: { system, systemRole: { isSystemAdmin: true } } },
    },
  });
  if (others === 0) {
    // Spec 0012: coded LAST_ADMIN, same message, plus the system it names
    throw new ConflictException({
      statusCode: 409,
      error: 'Conflict',
      code: 'LAST_ADMIN',
      message: `This is the last ${system} admin.`,
      system,
    });
  }
}
