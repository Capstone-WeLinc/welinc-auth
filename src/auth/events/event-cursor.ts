import { HttpStatus } from '@nestjs/common';
import { coded } from '../errors';

// Spec 0011, Query rules: keyset on (created_at desc, id desc). The cursor is base64url of the
// row's millisecond ISO time, `|`, and its id (safe because the column is timestamptz(3)).

export type EventCursor = { createdAt: Date; id: string };

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export const invalidCursor = () =>
  coded(HttpStatus.BAD_REQUEST, 'INVALID_CURSOR', 'This cursor is not valid');

export function encodeEventCursor(row: EventCursor): string {
  return Buffer.from(
    `${row.createdAt.toISOString()}|${row.id}`,
    'utf8',
  ).toString('base64url');
}

/** 400 `INVALID_CURSOR` for anything this route didn't hand out. */
export function decodeEventCursor(cursor: string): EventCursor {
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(cursor)) throw invalidCursor();
  const [at, id, extra] = Buffer.from(cursor, 'base64url')
    .toString('utf8')
    .split('|');
  if (extra !== undefined || !at || !id) throw invalidCursor();
  const createdAt = new Date(at);
  if (
    !ISO_RE.test(at) ||
    !UUID_RE.test(id) ||
    Number.isNaN(createdAt.getTime())
  ) {
    throw invalidCursor();
  }
  return { createdAt, id: id.toLowerCase() };
}
