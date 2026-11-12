import type { Prisma } from '@prisma/client';

/**
 * Spec 0013, AC-10: a role row counts only while it is permanent or its temporary grant has not
 * reached `expires_at`. Every place that builds a token or decides access from `user_roles`
 * filters with this, so a stopped expiry sweep never keeps a role alive.
 */
export function liveRoleWhere(
  now: Date = new Date(),
): Prisma.UserRoleAssignmentWhereInput {
  return {
    OR: [
      { temporaryGrantId: null },
      { temporaryGrant: { expiresAt: { gt: now }, endedAt: null } },
    ],
  };
}
