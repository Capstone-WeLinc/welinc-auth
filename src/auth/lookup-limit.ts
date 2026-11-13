import { HttpStatus } from '@nestjs/common';
import type { ThrottlerStorage } from '@nestjs/throttler';
import { coded } from './errors';

/**
 * Suite spec 0014, AC-9: the cross system people lookup allows 30 calls a minute per admin,
 * counted per container in the throttler storage. The bearer route (`GET /auth/users/lookup`)
 * and the cookie route (`GET /auth/admin/users/lookup`) share one counter, so contract 0001
 * section 12's promise holds whichever route an admin uses.
 */
export const LOOKUP_LIMIT = { limit: 30, ttlMs: 60_000 };

/** Counts one lookup for `adminId` (the token's or cookie session's `sub`), or 429. */
export async function countLookupCall(
  storage: ThrottlerStorage,
  adminId: string,
  res: { setHeader(name: string, value: string): unknown },
): Promise<void> {
  const hit = await storage.increment(
    `lookup:${adminId}`,
    LOOKUP_LIMIT.ttlMs,
    LOOKUP_LIMIT.limit,
    0,
    'lookup',
  );
  if (hit.totalHits > LOOKUP_LIMIT.limit) {
    res.setHeader(
      'Retry-After',
      String(Math.max(1, Math.ceil(hit.timeToExpire))),
    );
    throw coded(
      HttpStatus.TOO_MANY_REQUESTS,
      'RATE_LIMITED',
      'Too many lookups. Wait a minute and try again.',
    );
  }
}
