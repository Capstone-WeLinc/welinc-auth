import { describe, it, expect } from '@jest/globals';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CATALOG } from '../../../prisma/catalog';
import {
  checkManifest,
  emailConflicts,
  isLocalDatabase,
  loadManifest,
  PRODUCTION_REFUSAL,
  RESET_REFUSAL,
  seedGuard,
  stateFields,
  type CatalogView,
  type Manifest,
  type ManifestPerson,
} from '../../../prisma/seeds/manifest';
import { checkCopy } from '../../../prisma/seed-check';
import { summaryLines } from '../../../prisma/seeds/summary';

const catalog: CatalogView = {
  systems: CATALOG.map((s) => ({
    code: s.system,
    maxRolesPerUser: s.maxRolesPerUser,
  })),
  roles: CATALOG.flatMap((s) =>
    s.roles.map((r) => ({
      system: s.system,
      code: r.code,
      isSystemAdmin: r.isSystemAdmin === true,
    })),
  ),
};

const id = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

function person(
  n: number,
  overrides: Partial<ManifestPerson> = {},
): ManifestPerson {
  return {
    id: id(n),
    email: `p${n}@welinc.com`,
    name: `Person ${n}`,
    group: 'office',
    state: 'active',
    password: 'admin',
    contact: null,
    roles: [{ system: 'VRMS', role: 'ADMIN' }],
    ...overrides,
  };
}

function manifest(people: ManifestPerson[]): Manifest {
  return { version: 1, passwords: { admin: 'admin1234' }, people };
}

// covers: spec 0006 AC-1, AC-3 (the committed manifest is valid against the catalog)
describe('people.json', () => {
  const m = loadManifest();

  it('passes every check', () => {
    expect(checkManifest(m, catalog)).toEqual([]);
  });

  it('lists people in id order', () => {
    const ids = m.people.map((p) => p.id);
    expect(ids).toEqual([...ids].sort());
  });
});

// covers: spec 0006 AC-2
describe('checkManifest', () => {
  it('accepts a valid manifest', () => {
    expect(checkManifest(manifest([person(1), person(2)]), catalog)).toEqual(
      [],
    );
  });

  it('lists every problem in one edit, not just the first', () => {
    const problems = checkManifest(
      manifest([
        person(1),
        person(2, { email: 'P1@welinc.com' }),
        person(3, { roles: [{ system: 'VRMS', role: 'DRIVER' }] }),
        person(4, {
          roles: [
            { system: 'VRMS', role: 'MECHANIC' },
            { system: 'VRMS', role: 'CHIEF_MECHANIC' },
          ],
        }),
        person(5, {
          roles: [
            { system: 'VRMS', role: 'ADMIN' },
            { system: 'VMMS', role: 'ADMIN' },
            { system: 'BMS', role: 'ADMIN' },
          ],
        }),
      ]),
      catalog,
    );
    expect(problems.some((p) => p.includes('also used by people[0]'))).toBe(
      true,
    );
    expect(problems.some((p) => p.includes('VRMS DRIVER is not in'))).toBe(
      true,
    );
    expect(problems.some((p) => p.includes('more than its limit of 1'))).toBe(
      true,
    );
    expect(problems.some((p) => p.includes('admin in every system'))).toBe(
      true,
    );
  });

  it('refuses a duplicate id, a bad id, a foreign domain, a missing password key and an unknown state', () => {
    const problems = checkManifest(
      manifest([
        person(1),
        person(1, { email: 'other@welinc.com' }),
        person(2, { id: 'not-an-id' }),
        person(3, { email: 'p3@gmail.com' }),
        person(4, { password: 'nope' }),
        person(5, { state: 'frozen' as ManifestPerson['state'] }),
      ]),
      catalog,
    );
    expect(problems).toHaveLength(5);
  });

  it('allows an admin in two systems but not three', () => {
    const two = person(1, {
      roles: [
        { system: 'VRMS', role: 'ADMIN' },
        { system: 'VMMS', role: 'ADMIN' },
      ],
    });
    expect(checkManifest(manifest([two]), catalog)).toEqual([]);
  });

  // covers: spec 0013 AC-33
  it('accepts a suite admin with no roles, refuses one with roles and a fourth', () => {
    const suite = (n: number, roles: ManifestPerson['roles'] = []) =>
      person(n, { roles, suiteAdmin: true });
    expect(checkManifest(manifest([suite(1), suite(2)]), catalog)).toEqual([]);
    expect(
      checkManifest(
        manifest([suite(1, [{ system: 'VRMS', role: 'MECHANIC' }])]),
        catalog,
      ),
    ).toEqual([expect.stringContaining('roles must be empty')]);
    expect(
      checkManifest(
        manifest([suite(1), suite(2), suite(3), suite(4)]),
        catalog,
      ),
    ).toEqual([expect.stringContaining('more than the limit of 3')]);
  });

  it('holds the seed suite admin at id 9001 with no roles', () => {
    const m = loadManifest();
    const suite = m.people.filter((p) => p.suiteAdmin === true);
    expect(suite.map((p) => [p.id, p.email, p.roles])).toEqual([
      [id(9001), 'suite.admin@welinc.com', []],
    ]);
  });
});

// covers: spec 0006 AC-5
describe('stateFields', () => {
  const now = new Date('2026-11-09T00:00:00Z');
  const earlier = new Date('2026-11-01T00:00:00Z');

  it('gives an active person a clean row', () => {
    expect(
      stateFields('active', { lockedAt: earlier, deletedAt: earlier }, now),
    ).toEqual({
      isActive: true,
      emailVerified: true,
      passwordSet: true,
      failedLoginAttempts: 0,
      lockedAt: null,
      deletedAt: null,
      erasedAt: null,
    });
  });

  it('locks with five attempts and keeps an existing lock time', () => {
    expect(stateFields('locked', undefined, now)).toMatchObject({
      failedLoginAttempts: 5,
      lockedAt: now,
    });
    expect(
      stateFields('locked', { lockedAt: earlier, deletedAt: null }, now)
        .lockedAt,
    ).toBe(earlier);
  });

  it('changes only isActive for deactivated and emailVerified for unverified', () => {
    expect(stateFields('deactivated', undefined, now)).toMatchObject({
      isActive: false,
      emailVerified: true,
      lockedAt: null,
    });
    // Spec 0009, AC-16: unverified keeps its password, so it meets the sign in step
    expect(stateFields('unverified', undefined, now)).toMatchObject({
      passwordSet: true,
      isActive: true,
      emailVerified: false,
    });
  });

  it('soft deletes, keeping an existing delete time', () => {
    expect(stateFields('deleted', undefined, now)).toMatchObject({
      isActive: false,
      deletedAt: now,
      lockedAt: null,
      failedLoginAttempts: 0,
    });
    expect(
      stateFields('deleted', { lockedAt: null, deletedAt: earlier }, now)
        .deletedAt,
    ).toBe(earlier);
  });
});

// covers: spec 0006 AC-7
describe('emailConflicts', () => {
  it('is empty when each email is free or held by the same id', () => {
    expect(
      emailConflicts(
        [person(1), person(2)],
        [{ id: id(1), email: 'p1@welinc.com' }],
      ),
    ).toEqual([]);
  });

  it('names an email held by another id, case insensitively', () => {
    expect(
      emailConflicts([person(1)], [{ id: id(9), email: 'P1@welinc.com' }]),
    ).toEqual([
      `p1@welinc.com belongs to user ${id(9)}, but the manifest gives it to ${id(1)}`,
    ]);
  });

  it('refuses two manifest people swapping emails', () => {
    const swapped = [
      person(1, { email: 'p2@welinc.com' }),
      person(2, { email: 'p1@welinc.com' }),
    ];
    expect(
      emailConflicts(swapped, [
        { id: id(1), email: 'p1@welinc.com' },
        { id: id(2), email: 'p2@welinc.com' },
      ]),
    ).toHaveLength(2);
  });
});

// covers: spec 0006 AC-9, AC-10
describe('seedGuard', () => {
  const local = 'postgresql://u:p@localhost:5432/db';
  const base = {
    nodeEnv: 'development',
    seedAllow: undefined,
    databaseUrl: local,
    reset: false,
  };

  it('runs locally', () => {
    expect(seedGuard(base)).toEqual({ ok: true, reset: false, staging: false });
  });

  it('refuses production unless SEED_ALLOW=staging', () => {
    expect(seedGuard({ ...base, nodeEnv: 'production' })).toEqual({
      ok: false,
      message: PRODUCTION_REFUSAL,
    });
    expect(
      seedGuard({ ...base, nodeEnv: 'production', seedAllow: 'yes' }),
    ).toEqual({ ok: false, message: PRODUCTION_REFUSAL });
    expect(
      seedGuard({ ...base, nodeEnv: 'production', seedAllow: 'staging' }),
    ).toEqual({ ok: true, reset: false, staging: true });
  });

  it('allows --reset only locally, outside production and staging', () => {
    expect(seedGuard({ ...base, reset: true })).toMatchObject({ ok: true });
    expect(
      seedGuard({ ...base, reset: true, nodeEnv: undefined }),
    ).toMatchObject({ ok: true });
    const refused = { ok: false, message: RESET_REFUSAL };
    expect(seedGuard({ ...base, reset: true, nodeEnv: 'staging' })).toEqual(
      refused,
    );
    expect(seedGuard({ ...base, reset: true, seedAllow: 'staging' })).toEqual(
      refused,
    );
    expect(
      seedGuard({
        ...base,
        reset: true,
        databaseUrl: 'postgresql://u:p@db.example.com:5432/db',
      }),
    ).toEqual(refused);
  });

  it('counts localhost, 127.0.0.1 and dotless compose names as local', () => {
    expect(isLocalDatabase('postgresql://u:p@127.0.0.1/db')).toBe(true);
    expect(
      isLocalDatabase('postgresql://u:p@auth-db:5432/db?schema=public'),
    ).toBe(true);
    expect(
      isLocalDatabase('postgresql://u:p@x.postgres.database.azure.com/db'),
    ).toBe(false);
    expect(isLocalDatabase(undefined)).toBe(false);
    expect(isLocalDatabase('not a url')).toBe(false);
  });
});

// covers: spec 0006 AC-13
describe('checkCopy', () => {
  const dir = mkdtempSync(join(tmpdir(), 'seed-check-'));
  const source = join(dir, 'people.json');
  writeFileSync(source, '{"version":1}\n');

  it('matches an identical copy', () => {
    const copy = join(dir, 'copy.json');
    writeFileSync(copy, '{"version":1}\n');
    expect(checkCopy(copy, source)).toEqual({
      ok: true,
      message: 'Matches people.json',
    });
  });

  it('flags a copy that differs by one byte, even only in line endings', () => {
    const copy = join(dir, 'crlf.json');
    writeFileSync(copy, '{"version":1}\r\n');
    expect(checkCopy(copy, source)).toEqual({
      ok: false,
      message: `Out of date: copy welinc-auth/prisma/seeds/people.json over ${copy}`,
    });
  });

  it('reports a missing file', () => {
    const missing = join(dir, 'missing.json');
    expect(checkCopy(missing, source)).toEqual({
      ok: false,
      message: `No file at ${missing}`,
    });
  });
});

// covers: spec 0006 AC-12
describe('summaryLines', () => {
  it('lists office accounts by system and counts the rest', () => {
    const m = manifest([
      person(1),
      person(2, {
        group: 'bulk',
        roles: [{ system: 'VRMS', role: 'MECHANIC' }],
      }),
    ]);
    const lines = summaryLines(m.people, m, false);
    expect(lines[0]).toBe('VRMS');
    expect(lines[1]).toContain('p1@welinc.com');
    expect(lines.some((l) => l.startsWith('Bulk mechanics: 1'))).toBe(true);
  });

  it('says when state accounts were skipped on staging', () => {
    const m = manifest([person(1)]);
    expect(summaryLines(m.people, m, true)).toContain(
      'Broken state accounts: skipped (SEED_ALLOW=staging)',
    );
  });
});
