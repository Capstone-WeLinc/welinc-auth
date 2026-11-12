import { HttpStatus } from '@nestjs/common';
import { DeletionRequestStatus, Prisma } from '@prisma/client';
import { coded } from '../errors';

// Spec 0013, AC-16, AC-23: the portal's People list. Keyset paged by name then id, filtered by
// a search and the status the Users pages show (the first that applies: Inactive, Locked,
// Setup pending, Email not verified, Active), plus Pending deletion.

export const PEOPLE_STATUSES = [
  'LOCKED',
  'SETUP_PENDING',
  'EMAIL_NOT_VERIFIED',
  'ACTIVE',
  'INACTIVE',
  'PENDING_DELETION',
] as const;
export type PeopleStatus = (typeof PEOPLE_STATUSES)[number];

export const PEOPLE_DEFAULT_LIMIT = 50;
export const PEOPLE_MAX_LIMIT = 100;

export type PeopleCursor = { name: string; id: string };

const invalid = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);

export function encodePeopleCursor(cursor: PeopleCursor): string {
  return Buffer.from(JSON.stringify([cursor.name, cursor.id])).toString(
    'base64url',
  );
}

/** 400 `INVALID_CURSOR` for anything this list did not hand out. */
export function decodePeopleCursor(raw: string): PeopleCursor {
  try {
    const value: unknown = JSON.parse(
      Buffer.from(raw, 'base64url').toString('utf8'),
    );
    if (
      Array.isArray(value) &&
      value.length === 2 &&
      typeof value[0] === 'string' &&
      typeof value[1] === 'string' &&
      /^[0-9a-f-]{36}$/i.test(value[1])
    ) {
      return { name: value[0], id: value[1] };
    }
  } catch {
    // falls through to the error below
  }
  throw coded(
    HttpStatus.BAD_REQUEST,
    'INVALID_CURSOR',
    'This page link is no longer valid. Start from the first page.',
  );
}

export function parsePeopleLimit(raw: string | undefined): number {
  if (raw === undefined) return PEOPLE_DEFAULT_LIMIT;
  const n = /^\d{1,3}$/.test(raw) ? Number(raw) : NaN;
  if (!(n >= 1 && n <= PEOPLE_MAX_LIMIT)) {
    throw invalid(`limit must be 1 to ${PEOPLE_MAX_LIMIT}`);
  }
  return n;
}

/** The status filter as a where clause, in the same order the status is decided. */
export function statusWhere(status: PeopleStatus): Prisma.UserWhereInput {
  const usable = { isActive: true, lockedAt: null };
  switch (status) {
    case 'INACTIVE':
      return { isActive: false };
    case 'LOCKED':
      return { isActive: true, lockedAt: { not: null } };
    case 'SETUP_PENDING':
      return { ...usable, passwordSet: false };
    case 'EMAIL_NOT_VERIFIED':
      return { ...usable, passwordSet: true, emailVerified: false };
    case 'ACTIVE':
      return { ...usable, passwordSet: true, emailVerified: true };
    case 'PENDING_DELETION':
      return {
        deletionRequests: { some: { status: DeletionRequestStatus.PENDING } },
      };
  }
}

/** Rows after the cursor in (name, id) order. */
export function afterCursor(
  cursor: PeopleCursor | null,
): Prisma.UserWhereInput {
  if (!cursor) return {};
  return {
    OR: [
      { name: { gt: cursor.name } },
      { name: cursor.name, id: { gt: cursor.id } },
    ],
  };
}
