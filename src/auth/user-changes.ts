import { BadRequestException, ConflictException } from '@nestjs/common';
import { Prisma, SystemType, UserChangeAction, UserRole } from '@prisma/client';

// Spec 0009, AC-19 to AC-21: the admin change record and the admin safety guards.

export type Actor = { id: string; email: string };

type RoleAssignment = { role: UserRole; system: SystemType };

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
 * The systems this user is an ADMIN of, sorted. Callers lock each system's admin rows in this
 * order, so two writes that touch the same systems always lock them the same way and can't
 * deadlock.
 */
export function adminSystems(roles: RoleAssignment[]): SystemType[] {
  return roles
    .filter((r) => r.role === UserRole.ADMIN)
    .map((r) => r.system)
    .sort();
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
 * Inside the write's transaction: 409 unless another active, non deleted ADMIN of `system` stays.
 * Locks that system's ADMIN role rows first, so two admins demoting or deactivating each other at
 * once can't both pass.
 */
export async function assertAnotherAdmin(
  tx: Prisma.TransactionClient,
  targetId: string,
  system: SystemType,
): Promise<void> {
  await tx.$queryRaw`
    SELECT id FROM user_roles
    WHERE role = 'ADMIN'::"UserRole" AND system = ${system}::"SystemType"
    FOR UPDATE`;
  const others = await tx.user.count({
    where: {
      id: { not: targetId },
      isActive: true,
      deletedAt: null,
      roles: { some: { role: UserRole.ADMIN, system } },
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
