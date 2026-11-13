import { describe, it, expect, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import type { ThrottlerStorage } from '@nestjs/throttler';
import { LOOKUP_LIMIT, countLookupCall } from './lookup-limit';

// covers: suite spec 0014 AC-9 (one lookup:<sub> counter, 30 a minute, 429 RATE_LIMITED)

/** An in memory counter shaped like the throttler storage. */
function storage() {
  const hits = new Map<string, number>();
  const increment = jest.fn((...args: unknown[]) => {
    const key = String(args[0]);
    hits.set(key, (hits.get(key) ?? 0) + 1);
    return Promise.resolve({
      totalHits: hits.get(key)!,
      timeToExpire: 41.2,
      isBlocked: false,
      timeToBlockExpire: 0,
    });
  });
  return { increment } as unknown as ThrottlerStorage & {
    increment: typeof increment;
  };
}

describe('countLookupCall', () => {
  it('allows 30 calls a minute per admin, then answers 429 with Retry-After', async () => {
    const store = storage();
    const res = {
      setHeader: jest.fn<(name: string, value: string) => unknown>(),
    };
    for (let i = 0; i < LOOKUP_LIMIT.limit; i++) {
      await countLookupCall(store, 'admin-1', res);
    }
    const error = await countLookupCall(store, 'admin-1', res).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(HttpException);
    expect((error as HttpException).getStatus()).toBe(429);
    expect((error as HttpException).getResponse()).toMatchObject({
      code: 'RATE_LIMITED',
    });
    expect(res.setHeader).toHaveBeenCalledWith('Retry-After', '42');
    expect(store.increment).toHaveBeenLastCalledWith(
      'lookup:admin-1',
      60_000,
      30,
      0,
      'lookup',
    );
  });

  it('counts each admin on their own key', async () => {
    const store = storage();
    const res = {
      setHeader: jest.fn<(name: string, value: string) => unknown>(),
    };
    for (let i = 0; i < LOOKUP_LIMIT.limit; i++) {
      await countLookupCall(store, 'admin-1', res);
    }
    await expect(
      countLookupCall(store, 'admin-2', res),
    ).resolves.toBeUndefined();
  });
});
