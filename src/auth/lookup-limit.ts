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

/**
 * Suite spec 0019, AC-23: the Add a user email check runs as you type, so it has its own
 * counter of 60 a minute per admin, never lookup's.
 */
export const EMAIL_CHECK_LIMIT = { limit: 60, ttlMs: 60_000 };

/**
 * Suite spec 0019, AC-21b: the People filter asks for counts as chips change (250 ms after each
 * change), so the facets route has its own counter of 120 a minute per admin.
 */
export const FACETS_LIMIT = { limit: 120, ttlMs: 60_000 };

type Limit = { limit: number; ttlMs: number };
type HeaderSink = { setHeader(name: string, value: string): unknown };

async function countCall(
  storage: ThrottlerStorage,
  name: string,
  limit: Limit,
  adminId: string,
  res: HeaderSink,
  message: string,
): Promise<void> {
  const hit = await storage.increment(
    `${name}:${adminId}`,
    limit.ttlMs,
    limit.limit,
    0,
    name,
  );
  if (hit.totalHits > limit.limit) {
    res.setHeader(
      'Retry-After',
      String(Math.max(1, Math.ceil(hit.timeToExpire))),
    );
    throw coded(HttpStatus.TOO_MANY_REQUESTS, 'RATE_LIMITED', message);
  }
}

/** Counts one lookup for `adminId` (the token's or cookie session's `sub`), or 429. */
export function countLookupCall(
  storage: ThrottlerStorage,
  adminId: string,
  res: HeaderSink,
): Promise<void> {
  return countCall(
    storage,
    'lookup',
    LOOKUP_LIMIT,
    adminId,
    res,
    'Too many lookups. Wait a minute and try again.',
  );
}

/** Counts one email check for `adminId`, or 429. */
export function countEmailCheckCall(
  storage: ThrottlerStorage,
  adminId: string,
  res: HeaderSink,
): Promise<void> {
  return countCall(
    storage,
    'email-check',
    EMAIL_CHECK_LIMIT,
    adminId,
    res,
    'Too many email checks. Wait a minute and try again.',
  );
}

/** Counts one People facets call for `adminId`, or 429. */
export function countFacetsCall(
  storage: ThrottlerStorage,
  adminId: string,
  res: HeaderSink,
): Promise<void> {
  return countCall(
    storage,
    'people-facets',
    FACETS_LIMIT,
    adminId,
    res,
    'Too many filter count requests. Wait a minute and try again.',
  );
}
