import { invalidCursor } from '../events/event-cursor';

// Spec 0012, AC-9: keyset cursors for the two admin views. `pending` keys on
// (requested_at, id), `grace` on (deleted_at, id), both ascending. The cursor carries its view,
// so one from the other view answers 400 INVALID_CURSOR.

export type DeletionView = 'pending' | 'grace';

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function encodeDeletionCursor(
  view: DeletionView,
  at: Date,
  id: string,
): string {
  return Buffer.from(`${view}|${at.toISOString()}|${id}`, 'utf8').toString(
    'base64url',
  );
}

export function decodeDeletionCursor(
  cursor: string,
  view: DeletionView,
): { at: Date; id: string } {
  if (!/^[A-Za-z0-9_-]{1,200}$/.test(cursor)) throw invalidCursor();
  const [kind, at, id, extra] = Buffer.from(cursor, 'base64url')
    .toString('utf8')
    .split('|');
  if (extra !== undefined || kind !== view || !at || !id) {
    throw invalidCursor();
  }
  const date = new Date(at);
  if (!ISO_RE.test(at) || !UUID_RE.test(id) || Number.isNaN(date.getTime())) {
    throw invalidCursor();
  }
  return { at: date, id: id.toLowerCase() };
}
