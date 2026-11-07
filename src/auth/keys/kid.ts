import { randomBytes } from 'crypto';

/**
 * A key id people can read in a log line: `<purpose>-<yyyymmdd>-<6 hex>`, for example
 * `auth-20261108-3fa9c1` (spec 0002, Decisions).
 */
export function newKid(purpose: string, now: Date = new Date()): string {
  const day = now.toISOString().slice(0, 10).replace(/-/g, '');
  return `${purpose}-${day}-${randomBytes(3).toString('hex')}`;
}
