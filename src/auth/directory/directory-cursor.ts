/**
 * Spec 0005 cursors. A feed cursor is base64url of `v1.<epoch>.<txid>.<seq>`: a position in
 * the feed's read order `(txid, seq)` plus the feed's epoch, so a cursor from a restored or
 * rebuilt database is refused instead of silently wrong. A page cursor of
 * `/auth/directory/users` is base64url of `v1.<last id>`. Anything else is `INVALID_CURSOR`.
 */

/** A position in the feed's read order. `(0, 0)` is before the first row. */
export type FeedPosition = { txid: bigint; seq: bigint };

export const FEED_START: FeedPosition = { txid: 0n, seq: 0n };

export class InvalidCursorError extends Error {
  constructor() {
    super('invalid directory cursor');
    this.name = 'InvalidCursorError';
  }
}

const DIGITS = /^\d{1,20}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function decode(raw: string): string {
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(raw)) throw new InvalidCursorError();
  return Buffer.from(raw, 'base64url').toString('utf8');
}

const encode = (value: string) =>
  Buffer.from(value, 'utf8').toString('base64url');

export function encodeFeedCursor(
  epoch: string,
  position: FeedPosition,
): string {
  return encode(`v1.${epoch}.${position.txid}.${position.seq}`);
}

/** Throws `InvalidCursorError` for a cursor welinc-auth did not issue or one from another epoch. */
export function decodeFeedCursor(raw: string, epoch: string): FeedPosition {
  const parts = decode(raw).split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new InvalidCursorError();
  const [, cursorEpoch, txid, seq] = parts;
  if (cursorEpoch !== epoch || !DIGITS.test(txid) || !DIGITS.test(seq)) {
    throw new InvalidCursorError();
  }
  return { txid: BigInt(txid), seq: BigInt(seq) };
}

export function encodePageCursor(lastId: string): string {
  return encode(`v1.${lastId}`);
}

/** The last user id of the previous page. */
export function decodePageCursor(raw: string): string {
  const parts = decode(raw).split('.');
  if (parts.length !== 2 || parts[0] !== 'v1' || !UUID.test(parts[1])) {
    throw new InvalidCursorError();
  }
  return parts[1];
}
