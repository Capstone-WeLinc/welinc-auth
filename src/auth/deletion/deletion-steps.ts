import { DeletionRequestStatus, Prisma } from '@prisma/client';
import type { AdminCaller } from '../user-scope';

// Spec 0012: the request steps that run inside AuthService's own admin transactions, after the
// users row is locked (AC-11 lock order).

type Tx = Prisma.TransactionClient;

/**
 * AC-13: an admin delete closes the person's pending request as APPROVED by that admin.
 * Answers whether it did, so the DELETED event carries the DELETION_REQUEST reason.
 */
export async function closePendingOnAdminDelete(
  tx: Tx,
  userId: string,
  actor: AdminCaller,
  now: Date,
): Promise<boolean> {
  const { count } = await tx.accountDeletionRequest.updateMany({
    where: { userId, status: DeletionRequestStatus.PENDING },
    data: {
      status: DeletionRequestStatus.APPROVED,
      decidedById: actor.id,
      decidedSystem: actor.system,
      decidedAt: now,
    },
  });
  return count === 1;
}

/** AC-14: a restore turns the APPROVED request (if any) into RESTORED. */
export async function markRestored(
  tx: Tx,
  userId: string,
  actor: AdminCaller,
  now: Date,
): Promise<void> {
  await tx.accountDeletionRequest.updateMany({
    where: { userId, status: DeletionRequestStatus.APPROVED },
    data: {
      status: DeletionRequestStatus.RESTORED,
      restoredAt: now,
      restoredById: actor.id,
    },
  });
}
