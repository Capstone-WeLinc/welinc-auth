import { DeletionRequestStatus, Prisma } from '@prisma/client';
import { closePendingOnAdminDelete, markRestored } from './deletion-steps';
import type { AdminCaller } from '../user-scope';

// covers: spec 0012 AC-13 (admin delete closes a pending request), AC-14 (restore marks it)

const NOW = new Date('2026-11-12T00:00:00.000Z');
const actor = { id: 'admin-1', system: 'VRMS' } as unknown as AdminCaller;

function fakeTx(count: number) {
  const updateMany = jest.fn().mockResolvedValue({ count });
  const tx = { accountDeletionRequest: { updateMany } };
  return { tx: tx as unknown as Prisma.TransactionClient, updateMany };
}

describe('closePendingOnAdminDelete', () => {
  it('approves the pending request in the admin name and answers true', async () => {
    const { tx, updateMany } = fakeTx(1);
    await expect(
      closePendingOnAdminDelete(tx, 'user-1', actor, NOW),
    ).resolves.toBe(true);
    expect(updateMany).toHaveBeenCalledWith({
      where: { userId: 'user-1', status: DeletionRequestStatus.PENDING },
      data: {
        status: DeletionRequestStatus.APPROVED,
        decidedById: 'admin-1',
        decidedSystem: 'VRMS',
        decidedAt: NOW,
      },
    });
  });

  it('answers false when the person had no pending request', async () => {
    const { tx } = fakeTx(0);
    await expect(
      closePendingOnAdminDelete(tx, 'user-1', actor, NOW),
    ).resolves.toBe(false);
  });
});

describe('markRestored', () => {
  it('turns only the approved request into restored, with who and when', async () => {
    const { tx, updateMany } = fakeTx(1);
    await markRestored(tx, 'user-1', actor, NOW);
    expect(updateMany).toHaveBeenCalledWith({
      where: { userId: 'user-1', status: DeletionRequestStatus.APPROVED },
      data: {
        status: DeletionRequestStatus.RESTORED,
        restoredAt: NOW,
        restoredById: 'admin-1',
      },
    });
  });

  it('resolves quietly when there is no approved request', async () => {
    const { tx } = fakeTx(0);
    await expect(
      markRestored(tx, 'user-1', actor, NOW),
    ).resolves.toBeUndefined();
  });
});
