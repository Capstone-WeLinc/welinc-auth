import { createHash } from 'node:crypto';
import { HttpStatus } from '@nestjs/common';
import { DeletionRequestStatus, Prisma } from '@prisma/client';
import { coded } from '../errors';
import { lockRunning, notLocked } from '../lockout';

// Spec 0013, AC-16, AC-23: the portal's People list, filtered by a search and the status the
// Users pages show (the first that applies: Inactive, Locked, Setup pending, Email not verified,
// Active), plus Pending deletion. Suite spec 0017, AC-5, AC-20: the three groups, three sorts,
// status lists, and keyset cursors that carry the sort and the filters they were made for.

export const PEOPLE_STATUSES = [
  'LOCKED',
  'SETUP_PENDING',
  'EMAIL_NOT_VERIFIED',
  'ACTIVE',
  'INACTIVE',
  'PENDING_DELETION',
] as const;
export type PeopleStatus = (typeof PEOPLE_STATUSES)[number];

/** One status, or a comma list read as any of them (AC-20). */
export const PEOPLE_STATUS_LIST_RE = new RegExp(
  `^(${PEOPLE_STATUSES.join('|')})(,(${PEOPLE_STATUSES.join('|')}))*$`,
);

export const PEOPLE_GROUPS = ['attention', 'active', 'inactive'] as const;
export type PeopleGroup = (typeof PEOPLE_GROUPS)[number];

export const PEOPLE_SORTS = ['name', 'lastSignedIn', 'newest'] as const;
export type PeopleSort = (typeof PEOPLE_SORTS)[number];

export const PEOPLE_DEFAULT_LIMIT = 50;
export const PEOPLE_MAX_LIMIT = 100;

/**
 * Where a page stopped: the sort it was made for, a fingerprint of its filters, the last row's
 * sort value (a name, or an ISO time; null inside the never signed in block) and its id.
 */
export type PeopleCursor = {
  sort: PeopleSort;
  filters: string;
  value: string | null;
  id: string;
};

const CURSOR_VERSION = 2;

const invalid = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);

const invalidCursor = () =>
  coded(
    HttpStatus.BAD_REQUEST,
    'INVALID_CURSOR',
    'This page link is no longer valid. Start from the first page.',
  );

/** A short stable fingerprint of the filters a cursor belongs to. */
export function filterKey(
  parts: readonly (string | null | undefined)[],
): string {
  return createHash('sha256')
    .update(JSON.stringify(parts.map((p) => p ?? '')))
    .digest('base64url')
    .slice(0, 16);
}

export function encodePeopleCursor(cursor: PeopleCursor): string {
  return Buffer.from(
    JSON.stringify([
      CURSOR_VERSION,
      cursor.sort,
      cursor.filters,
      cursor.value,
      cursor.id,
    ]),
  ).toString('base64url');
}

/**
 * 400 `INVALID_CURSOR` for anything this list did not hand out, and for a cursor made for
 * another sort or other filters (AC-20).
 */
export function decodePeopleCursor(
  raw: string,
  expected: { sort: PeopleSort; filters: string },
): PeopleCursor {
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    throw invalidCursor();
  }
  if (
    !Array.isArray(value) ||
    value.length !== 5 ||
    value[0] !== CURSOR_VERSION ||
    value[1] !== expected.sort ||
    value[2] !== expected.filters ||
    typeof value[4] !== 'string' ||
    !/^[0-9a-f-]{36}$/i.test(value[4])
  ) {
    throw invalidCursor();
  }
  const sortValue: unknown = value[3];
  const sort = expected.sort;
  const ok =
    sort === 'name'
      ? typeof sortValue === 'string'
      : sort === 'newest'
        ? isIsoTime(sortValue)
        : sortValue === null || isIsoTime(sortValue);
  if (!ok) throw invalidCursor();
  return {
    sort,
    filters: expected.filters,
    value: sortValue as string | null,
    id: value[4],
  };
}

function isIsoTime(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    !Number.isNaN(Date.parse(value))
  );
}

/** The cursor that continues after `row` in `sort` order. */
export function cursorAfter(
  sort: PeopleSort,
  filters: string,
  row: {
    id: string;
    name: string;
    createdAt: Date;
    lastSignedInAt: Date | null;
  },
): string {
  const value =
    sort === 'name'
      ? row.name
      : sort === 'newest'
        ? row.createdAt.toISOString()
        : (row.lastSignedInAt?.toISOString() ?? null);
  return encodePeopleCursor({ sort, filters, value, id: row.id });
}

export function parsePeopleLimit(raw: string | undefined): number {
  if (raw === undefined) return PEOPLE_DEFAULT_LIMIT;
  const n = /^\d{1,3}$/.test(raw) ? Number(raw) : NaN;
  if (!(n >= 1 && n <= PEOPLE_MAX_LIMIT)) {
    throw invalid(`limit must be 1 to ${PEOPLE_MAX_LIMIT}`);
  }
  return n;
}

/** `status` as given (one value or a comma list), each once, in list order. */
export function parseStatuses(raw: string | undefined): PeopleStatus[] {
  if (raw === undefined) return [];
  const asked = new Set(raw.split(','));
  return PEOPLE_STATUSES.filter((s) => asked.has(s));
}

const pendingDeletion: Prisma.UserWhereInput = {
  deletionRequests: { some: { status: DeletionRequestStatus.PENDING } },
};

/** The status filter as a where clause, in the same order the status is decided. */
export function statusWhere(status: PeopleStatus): Prisma.UserWhereInput {
  const usable = { isActive: true, ...notLocked() };
  switch (status) {
    case 'INACTIVE':
      return { isActive: false };
    case 'LOCKED':
      return { isActive: true, lockedAt: lockRunning() };
    case 'SETUP_PENDING':
      return { ...usable, passwordSet: false };
    case 'EMAIL_NOT_VERIFIED':
      return { ...usable, passwordSet: true, emailVerified: false };
    case 'ACTIVE':
      return { ...usable, passwordSet: true, emailVerified: true };
    case 'PENDING_DELETION':
      return pendingDeletion;
  }
}

/** Any of the statuses; no statuses is no filter. */
export function statusesWhere(
  statuses: readonly PeopleStatus[],
): Prisma.UserWhereInput {
  if (statuses.length === 0) return {};
  if (statuses.length === 1) return statusWhere(statuses[0]);
  return { OR: statuses.map(statusWhere) };
}

/**
 * Suite spec 0017, AC-5: each person in exactly one group. Needs attention: an active account
 * that is locked, setup pending, or pending deletion. Inactive: deactivated (whatever else holds).
 * Active: everyone else (email not verified included).
 */
export function groupWhere(group: PeopleGroup): Prisma.UserWhereInput {
  switch (group) {
    case 'attention':
      return {
        isActive: true,
        OR: [
          { lockedAt: lockRunning() },
          { passwordSet: false },
          pendingDeletion,
        ],
      };
    case 'inactive':
      return { isActive: false };
    case 'active':
      return {
        AND: [
          { isActive: true, passwordSet: true },
          notLocked(),
          { NOT: pendingDeletion },
        ],
      };
  }
}

/** Rows after the cursor in the sort's order. */
export function afterCursor(
  cursor: PeopleCursor | null,
): Prisma.UserWhereInput {
  if (!cursor) return {};
  const { id } = cursor;
  switch (cursor.sort) {
    case 'name':
      return {
        OR: [
          { name: { gt: cursor.value! } },
          { name: cursor.value!, id: { gt: id } },
        ],
      };
    case 'newest': {
      const at = new Date(cursor.value!);
      return {
        OR: [{ createdAt: { lt: at } }, { createdAt: at, id: { gt: id } }],
      };
    }
    case 'lastSignedIn': {
      // Newest first, the never signed in block last
      if (cursor.value === null) {
        return { lastSignedInAt: null, id: { gt: id } };
      }
      const at = new Date(cursor.value);
      return {
        OR: [
          { lastSignedInAt: { lt: at } },
          { lastSignedInAt: at, id: { gt: id } },
          { lastSignedInAt: null },
        ],
      };
    }
  }
}

/** AC-20's orders; each ends on `id` so the keyset is total. */
export function peopleOrder(
  sort: PeopleSort,
): Prisma.UserOrderByWithRelationInput[] {
  switch (sort) {
    case 'name':
      return [{ name: 'asc' }, { id: 'asc' }];
    case 'newest':
      return [{ createdAt: 'desc' }, { id: 'asc' }];
    case 'lastSignedIn':
      return [
        { lastSignedInAt: { sort: 'desc', nulls: 'last' } },
        { id: 'asc' },
      ];
  }
}
