import { HttpStatus } from '@nestjs/common';
import { AccountEventCategory, AccountEventType } from '@prisma/client';
import { coded } from '../errors';
import { decodeEventCursor, type EventCursor } from './event-cursor';
import { TYPE_CATEGORY } from './event-types';
import { normaliseIp } from './request-meta';

// Spec 0011, AC-11 to AC-14: the query of the three activity routes, read by hand (like the
// directory) so every bad value answers 400 `VALIDATION_FAILED` and a bad cursor
// `INVALID_CURSOR`.

export const ACTIVITY_DEFAULT_LIMIT = 50;
export const ACTIVITY_MAX_LIMIT = 100;
const MAX_LIST = 20;
const Q_MIN = 2;
const Q_MAX = 100;
/** Date filters are Asia/Manila days, a fixed +08:00 (no daylight saving). */
const MANILA = '+08:00';

export type ActivityFilters = {
  cursor: EventCursor | null;
  limit: number;
  categories?: AccountEventCategory[];
  types?: AccountEventType[];
  /** Inclusive lower bound on created_at. */
  from?: Date;
  /** Exclusive upper bound: the day after `to`, at 00:00 Manila time. */
  before?: Date;
  userId?: string;
  q?: string;
  address?: string;
};

/** Which filters a route takes beyond cursor, limit and category. */
export type ActivityRouteFilters = {
  type?: boolean;
  dates?: boolean;
  feed?: boolean;
};

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

const invalid = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);

/** One plain string, or undefined; a repeated parameter (an array) is refused. */
function single(
  raw: Record<string, unknown>,
  name: string,
): string | undefined {
  const value = raw[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw invalid(`${name} must be given once`);
  return value;
}

/** A comma separated list of known codes: at most 20, duplicates dropped. */
function codeList<T extends string>(
  value: string | undefined,
  name: string,
  known: readonly T[],
): T[] | undefined {
  if (value === undefined) return undefined;
  const parts = [...new Set(value.split(',').map((p) => p.trim()))];
  if (parts.length === 0 || parts.length > MAX_LIST || parts.includes('')) {
    throw invalid(`${name} takes 1 to ${MAX_LIST} comma separated values`);
  }
  for (const part of parts) {
    if (!known.includes(part as T)) throw invalid(`Unknown ${name}: ${part}`);
  }
  return parts as T[];
}

function day(value: string | undefined, name: string): string | undefined {
  if (value === undefined) return undefined;
  const at = new Date(`${value}T00:00:00${MANILA}`);
  // A real calendar day only: 2026-02-30 rolls over and is refused
  if (
    !DAY_RE.test(value) ||
    Number.isNaN(at.getTime()) ||
    new Date(at.getTime() + 8 * 3_600_000).toISOString().slice(0, 10) !== value
  ) {
    throw invalid(`${name} must be a date like 2026-11-12`);
  }
  return value;
}

export function parseActivityQuery(
  raw: Record<string, unknown>,
  route: ActivityRouteFilters = {},
): ActivityFilters {
  const filters: ActivityFilters = {
    cursor: null,
    limit: ACTIVITY_DEFAULT_LIMIT,
  };

  const limit = single(raw, 'limit');
  if (limit !== undefined) {
    const n = /^\d{1,3}$/.test(limit) ? Number(limit) : NaN;
    if (!(n >= 1 && n <= ACTIVITY_MAX_LIMIT)) {
      throw invalid(`limit must be 1 to ${ACTIVITY_MAX_LIMIT}`);
    }
    filters.limit = n;
  }

  filters.categories = codeList(
    single(raw, 'category'),
    'category',
    Object.values(AccountEventCategory),
  );

  if (route.type) {
    filters.types = codeList(
      single(raw, 'type'),
      'type',
      Object.values(AccountEventType),
    );
    const categories = filters.categories;
    if (filters.types && categories) {
      const stray = filters.types.find(
        (t) => !categories.includes(TYPE_CATEGORY[t]),
      );
      if (stray) {
        throw invalid(`type ${stray} is in none of the given categories`);
      }
    }
  }

  if (route.dates) {
    const from = day(single(raw, 'from'), 'from');
    const to = day(single(raw, 'to'), 'to');
    if (from && to && from > to) throw invalid('from is after to');
    if (from) filters.from = new Date(`${from}T00:00:00${MANILA}`);
    if (to) {
      filters.before = new Date(
        new Date(`${to}T00:00:00${MANILA}`).getTime() + 86_400_000,
      );
    }
  }

  if (route.feed) {
    const userId = single(raw, 'userId');
    if (userId !== undefined) {
      if (!UUID_RE.test(userId)) throw invalid('userId must be a UUID');
      filters.userId = userId.toLowerCase();
    }
    const q = single(raw, 'q');
    if (q !== undefined) {
      const trimmed = q.trim();
      if (trimmed.length < Q_MIN || trimmed.length > Q_MAX) {
        throw invalid(`q takes ${Q_MIN} to ${Q_MAX} characters`);
      }
      filters.q = trimmed;
    }
    const address = single(raw, 'address');
    if (address !== undefined) {
      const ip = normaliseIp(address);
      if (!ip) throw invalid('address must be an IP address');
      filters.address = ip;
    }
  }

  // Last, so a bad filter answers VALIDATION_FAILED before the cursor is looked at
  const cursor = single(raw, 'cursor');
  if (cursor !== undefined) filters.cursor = decodeEventCursor(cursor);

  return filters;
}
