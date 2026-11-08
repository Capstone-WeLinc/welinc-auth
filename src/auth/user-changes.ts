import { BadRequestException, ConflictException } from '@nestjs/common';
import { Prisma, SystemType, UserChangeAction } from '@prisma/client';
import type { AdminRoles } from './roles/catalog.service';
import type { RoleAssignment } from './roles/catalog.types';

// Spec 0009, AC-19 to AC-21: the admin change record and the admin safety guards.

export type Actor = { id: string; email: string };

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

/** One UserChange row for `userId`, made by `actor`. */
export function change(
  userId: string,
  actor: Actor,
  action: UserChangeAction,
  values: {
    field?: string;
    oldValue?: string | null;
    newValue?: string | null;
  } = {},
): Prisma.UserChangeCreateManyInput {
  return {
    userId,
    actorId: actor.id,
    actorEmail: actor.email,
    action,
    field: values.field ?? null,
    oldValue: values.oldValue ?? null,
    newValue: values.newValue ?? null,
  };
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
    throw new ConflictException(`This is the last ${system} admin.`);
  }
}

export type ChangeCursor = { createdAt: Date; id: string };

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function encodeChangeCursor(row: ChangeCursor): string {
  return Buffer.from(
    `${row.createdAt.toISOString()}|${row.id}`,
    'utf8',
  ).toString('base64url');
}

export function decodeChangeCursor(cursor: string): ChangeCursor {
  const [at, id] = Buffer.from(cursor, 'base64url').toString('utf8').split('|');
  const createdAt = new Date(at ?? '');
  if (!id || !UUID_RE.test(id) || Number.isNaN(createdAt.getTime())) {
    throw new BadRequestException('Invalid cursor');
  }
  return { createdAt, id };
}
