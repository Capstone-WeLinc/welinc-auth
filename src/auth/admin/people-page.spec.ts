import { describe, expect, it } from '@jest/globals';
import { SystemType } from '@prisma/client';
import { assertInReadScope } from '../user-scope';
import { readScope } from './admin-accounts.controller';
import type { AdminRequest } from './admin-session.guard';
import {
  afterCursor,
  decodePeopleCursor,
  encodePeopleCursor,
  groupWhere,
  parseStatuses,
} from './people-page';

// Suite spec 0017, AC-5, AC-19, AC-20

const ID = '22222222-2222-4222-8222-222222222222';

describe('readScope (AC-19)', () => {
  const req = (suiteAdmin: boolean, adminOf: SystemType[]) =>
    ({
      portalAdmin: {
        userId: 'u',
        sid: 's',
        user: { email: 'a@welinc.com' },
        standing: { suiteAdmin, adminOf },
      },
      headers: {},
      socket: {},
    }) as unknown as AdminRequest;

  it('is every system the admin holds when none is named', () => {
    expect(readScope(req(false, ['VRMS', 'VMMS']), undefined)).toEqual({
      systems: ['VRMS', 'VMMS'],
      only: null,
      suite: false,
    });
  });

  it('is the whole suite for a suite admin, even one who holds admin roles', () => {
    expect(readScope(req(true, ['VRMS']), undefined)).toEqual({
      systems: null,
      only: null,
      suite: true,
    });
  });

  it('keeps a named system, and refuses one the admin does not hold', () => {
    expect(readScope(req(false, ['VRMS']), 'VRMS')).toEqual({
      systems: ['VRMS'],
      only: 'VRMS',
      suite: false,
    });
    expect(() => readScope(req(false, ['VRMS']), 'BMS')).toThrow();
  });
});

describe('assertInReadScope (AC-19)', () => {
  const person = (systems: SystemType[], deletedAt: Date | null = null) => ({
    roles: systems.map((system) => ({ system })),
    deletedAt,
  });
  const multi = {
    systems: ['VRMS', 'VMMS'] as SystemType[],
    only: null,
    suite: false,
  };

  it('finds a person in any of the systems', () => {
    expect(() => assertInReadScope(person(['VMMS']), multi)).not.toThrow();
  });

  it('hides someone whose only roles are elsewhere, and a deleted person', () => {
    expect(() => assertInReadScope(person(['BMS']), multi)).toThrow();
    expect(() =>
      assertInReadScope(person(['VRMS'], new Date()), multi),
    ).toThrow();
  });

  it('keeps today rule for a named system, and finds anyone for a suite admin', () => {
    const named = {
      systems: ['VRMS'] as SystemType[],
      only: 'VRMS' as const,
      suite: false,
    };
    expect(() =>
      assertInReadScope(person(['VRMS'], new Date()), named),
    ).not.toThrow();
    const suite = { systems: null, only: null, suite: true };
    expect(() =>
      assertInReadScope(person([], new Date()), suite),
    ).not.toThrow();
    expect(() => assertInReadScope(null, suite)).toThrow();
  });
});

describe('People cursors (AC-20)', () => {
  const expected = { sort: 'lastSignedIn' as const, filters: 'f' };

  it('continues inside the never signed in block by id only', () => {
    const cursor = decodePeopleCursor(
      encodePeopleCursor({ ...expected, value: null, id: ID }),
      expected,
    );
    expect(afterCursor(cursor)).toEqual({
      lastSignedInAt: null,
      id: { gt: ID },
    });
  });

  it('from a sign in time, includes older times, ties after the id, and the never block', () => {
    const at = '2026-11-23T08:00:00.123Z';
    const cursor = decodePeopleCursor(
      encodePeopleCursor({ ...expected, value: at, id: ID }),
      expected,
    );
    expect(afterCursor(cursor)).toEqual({
      OR: [
        { lastSignedInAt: { lt: new Date(at) } },
        { lastSignedInAt: new Date(at), id: { gt: ID } },
        { lastSignedInAt: null },
      ],
    });
  });

  it('refuses an old style cursor, a bad time, and a name sort cursor with a null value', () => {
    const old = Buffer.from(JSON.stringify(['Pedro', ID])).toString(
      'base64url',
    );
    expect(() => decodePeopleCursor(old, expected)).toThrow();
    const bad = encodePeopleCursor({ ...expected, value: 'yesterday', id: ID });
    expect(() => decodePeopleCursor(bad, expected)).toThrow();
    const name = { sort: 'name' as const, filters: 'f' };
    const nul = encodePeopleCursor({ ...name, value: null, id: ID });
    expect(() => decodePeopleCursor(nul, name)).toThrow();
  });
});

describe('groups and statuses (AC-5, AC-20)', () => {
  it('puts deactivated accounts in Inactive whatever else holds', () => {
    expect(groupWhere('inactive')).toEqual({ isActive: false });
    expect(groupWhere('attention')).toMatchObject({ isActive: true });
  });

  it('leaves pending deletion out of Active', () => {
    const active = groupWhere('active') as { AND: unknown[] };
    expect(active.AND[2]).toEqual({
      NOT: { deletionRequests: { some: { status: 'PENDING' } } },
    });
  });

  it('reads each status once, in list order', () => {
    expect(parseStatuses('INACTIVE,LOCKED,INACTIVE')).toEqual([
      'LOCKED',
      'INACTIVE',
    ]);
    expect(parseStatuses(undefined)).toEqual([]);
  });
});
