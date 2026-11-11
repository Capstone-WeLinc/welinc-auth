/* eslint-disable @typescript-eslint/require-await, @typescript-eslint/no-unused-vars -- test doubles */
import { describe, expect, it, jest } from '@jest/globals';
import type { ConfigService } from '@nestjs/config';
import { SessionSweeper, SWEEP_BATCH } from './session-sweeper';

// covers: AC-9 (non ACCOUNT events past retention go in batches, through the sweep flag)
function setup(batches: number[], days = 365) {
  const queryRaw = jest.fn(async (..._a: unknown[]) => []);
  const executeRaw = jest.fn(async (..._a: unknown[]) => batches.shift() ?? 0);
  const tx = { $queryRaw: queryRaw, $executeRaw: executeRaw };
  const prisma = {
    $transaction: jest.fn(async (fn: (t: unknown) => unknown) => fn(tx)),
  };
  const config = { get: () => days } as unknown as ConfigService<never, true>;
  const sweeper = new SessionSweeper(
    prisma as never,
    {} as never,
    {} as never,
    config,
    { sweep: () => Promise.resolve({ erased: 0, failed: 0 }) } as never,
  );
  return { sweeper, queryRaw, executeRaw, prisma };
}

describe('SessionSweeper.sweepEvents', () => {
  it('deletes one short batch and stops', async () => {
    const { sweeper, executeRaw } = setup([7]);
    expect(await sweeper.sweepEvents(new Date('2026-11-12T00:00:00Z'))).toBe(7);
    expect(executeRaw).toHaveBeenCalledTimes(1);
  });

  it('keeps going while batches come back full and sums them', async () => {
    const { sweeper, executeRaw } = setup([SWEEP_BATCH, SWEEP_BATCH, 5]);
    expect(await sweeper.sweepEvents()).toBe(SWEEP_BATCH * 2 + 5);
    expect(executeRaw).toHaveBeenCalledTimes(3);
  });

  it('turns the sweep flag on inside every batch transaction', async () => {
    const { sweeper, queryRaw, prisma } = setup([SWEEP_BATCH, 1]);
    await sweeper.sweepEvents();
    expect(prisma.$transaction).toHaveBeenCalledTimes(2);
    expect(queryRaw).toHaveBeenCalledTimes(2);
  });

  it('never deletes ACCOUNT rows and uses the retention cutoff', async () => {
    const { sweeper, executeRaw } = setup([0], 30);
    await sweeper.sweepEvents(new Date('2026-11-12T00:00:00Z'));
    const [strings, before] = executeRaw.mock.calls[0] as unknown as [
      string[],
      Date,
    ];
    expect(strings.join('?')).toContain(`"category" <> 'ACCOUNT'`);
    expect(before.toISOString()).toBe('2026-10-13T00:00:00.000Z');
  });
});
