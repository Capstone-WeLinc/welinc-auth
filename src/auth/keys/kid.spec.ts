import { describe, it, expect } from '@jest/globals';
import { newKid } from './kid';

// covers: spec 0002 Decisions (readable key id: <purpose>-<yyyymmdd>-<6 hex>)
describe('newKid', () => {
  it('builds purpose, UTC day and six hex characters', () => {
    const kid = newKid('auth', new Date('2026-11-08T10:00:00Z'));

    expect(kid).toMatch(/^auth-20261108-[0-9a-f]{6}$/);
  });

  it('uses the UTC day, not the local day, near midnight', () => {
    const kid = newKid('client', new Date('2026-11-08T23:59:59Z'));

    expect(kid.startsWith('client-20261108-')).toBe(true);
  });

  it('gives a different id on each call for the same day', () => {
    const now = new Date('2026-11-08T10:00:00Z');
    const kids = new Set(Array.from({ length: 20 }, () => newKid('auth', now)));

    expect(kids.size).toBeGreaterThan(1);
  });
});
