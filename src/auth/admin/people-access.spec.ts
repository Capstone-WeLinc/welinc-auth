import { HttpException } from '@nestjs/common';
import { SystemType } from '@prisma/client';
import { CATALOG } from '../../../prisma/catalog';
import type { CatalogSystem } from '../roles/catalog.service';
import type { ReadScope } from '../user-scope';
import { accessKey, accessWhere, parseAccess } from './people-access';
import { statusWhere, groupWhere } from './people-page';

// covers: suite spec 0019 AC-21a (the access filter's checks, their order and normalizing; the
// ATTENTION and ACTIVE_GROUP statuses as the group rules)

const catalog: CatalogSystem[] = CATALOG.map((d) => ({
  code: d.system,
  name: d.name,
  description: d.description,
  maxRolesPerUser: d.maxRolesPerUser,
  roles: d.roles.map((r) => ({
    code: r.code,
    name: r.name,
    description: r.description,
    isSystemAdmin: r.isSystemAdmin === true,
  })),
}));

const SUITE: ReadScope = { systems: null, only: null, suite: true };
const VRMS_ADMIN: ReadScope = {
  systems: [SystemType.VRMS],
  only: null,
  suite: false,
};
const NAMED_VRMS: ReadScope = {
  systems: [SystemType.VRMS],
  only: SystemType.VRMS,
  suite: true,
};

function codeOf(run: () => unknown): { status: number; code: string } {
  try {
    run();
  } catch (e) {
    const http = e as HttpException;
    return {
      status: http.getStatus(),
      code: (http.getResponse() as { code: string }).code,
    };
  }
  throw new Error('expected a refusal');
}

describe('parseAccess checks (AC-21a)', () => {
  it.each([
    ['an empty item', 'VRMS,'],
    ['a lowercase item', 'vrms'],
    ['whitespace', 'VRMS, VMMS'],
    ['a malformed item', 'VMMS:'],
    ['two colons', 'VMMS:MECHANIC:X'],
  ])('answers 400 VALIDATION_FAILED for %s', (_, raw) => {
    expect(codeOf(() => parseAccess(raw, catalog, SUITE))).toEqual({
      status: 400,
      code: 'VALIDATION_FAILED',
    });
  });

  it('answers 400 VALIDATION_FAILED past 40 items or 600 characters', () => {
    const many = Array.from({ length: 41 }, () => 'VRMS').join(',');
    expect(codeOf(() => parseAccess(many, catalog, SUITE)).code).toBe(
      'VALIDATION_FAILED',
    );
    const forty = Array.from({ length: 40 }, () => 'VRMS').join(',');
    expect(parseAccess(forty, catalog, SUITE)).toHaveLength(1);
  });

  it('checks the shape before the length, and the length before the catalog', () => {
    const longBad = `${'VRMS,'.repeat(50)}vrms`;
    expect(codeOf(() => parseAccess(longBad, catalog, SUITE)).code).toBe(
      'VALIDATION_FAILED',
    );
    const longUnknown = Array.from({ length: 41 }, () => 'NOPE').join(',');
    expect(codeOf(() => parseAccess(longUnknown, catalog, SUITE)).code).toBe(
      'VALIDATION_FAILED',
    );
  });

  it('answers 400 UNKNOWN_ROLE for an unknown system or role', () => {
    expect(codeOf(() => parseAccess('NOPE', catalog, SUITE))).toEqual({
      status: 400,
      code: 'UNKNOWN_ROLE',
    });
    expect(codeOf(() => parseAccess('VRMS:DRIVER', catalog, SUITE)).code).toBe(
      'UNKNOWN_ROLE',
    );
  });

  it('answers 403 for a system outside the scope, unknown checks first', () => {
    expect(codeOf(() => parseAccess('VMMS', catalog, VRMS_ADMIN))).toEqual({
      status: 403,
      code: 'NOT_ADMIN_OF_SYSTEM',
    });
    expect(
      codeOf(() => parseAccess('VMMS,VRMS:NOPE', catalog, VRMS_ADMIN)).code,
    ).toBe('UNKNOWN_ROLE');
  });

  it('answers 403 for a system other than the named one, even for a suite admin', () => {
    expect(
      codeOf(() => parseAccess('BMS:DRIVER', catalog, NAMED_VRMS)).code,
    ).toBe('NOT_ADMIN_OF_SYSTEM');
    expect(parseAccess('VRMS:MECHANIC', catalog, NAMED_VRMS)).toEqual([
      { system: SystemType.VRMS, role: 'MECHANIC' },
    ]);
  });

  it('lets every catalog role in, ADMIN included', () => {
    expect(parseAccess('BMS:ADMIN', catalog, SUITE)).toEqual([
      { system: SystemType.BMS, role: 'ADMIN' },
    ]);
  });
});

describe('parseAccess normalizing (AC-21a)', () => {
  it('drops duplicates, lets a whole system absorb its roles, and sorts', () => {
    const items = parseAccess(
      'VMMS:MECHANIC,BMS:DRIVER,VMMS,BMS:DRIVER,VRMS:MECHANIC',
      catalog,
      SUITE,
    );
    expect(accessKey(items)).toBe('BMS:DRIVER,VMMS,VRMS:MECHANIC');
  });

  it('gives VMMS,VMMS:MECHANIC the same key as VMMS', () => {
    expect(accessKey(parseAccess('VMMS,VMMS:MECHANIC', catalog, SUITE))).toBe(
      accessKey(parseAccess('VMMS', catalog, SUITE)),
    );
  });

  it('never turns every role ticked into the whole system', () => {
    const all = catalog
      .find((s) => s.code === SystemType.VRMS)!
      .roles.map((r) => `VRMS:${r.code}`)
      .join(',');
    expect(parseAccess(all, catalog, SUITE).every((i) => i.role !== null)).toBe(
      true,
    );
  });
});

describe('accessWhere (AC-21a)', () => {
  it('is no filter with no items', () => {
    expect(accessWhere([])).toEqual({});
  });

  it('reads the items as any of them, one roles clause per system', () => {
    const items = parseAccess(
      'VRMS,VMMS:MECHANIC,VMMS:OPERATIONS',
      catalog,
      SUITE,
    );
    expect(accessWhere(items)).toEqual({
      OR: [
        {
          roles: {
            some: {
              system: SystemType.VMMS,
              role: { in: ['MECHANIC', 'OPERATIONS'] },
            },
          },
        },
        { roles: { some: { system: SystemType.VRMS } } },
      ],
    });
  });
});

describe('ATTENTION and ACTIVE_GROUP (AC-21a)', () => {
  // Both sides read the clock, so pin it: a millisecond tick between the calls failed the match.
  beforeEach(() =>
    jest.useFakeTimers({ now: new Date('2026-11-26T08:00:00Z') }),
  );
  afterEach(() => jest.useRealTimers());

  it('are exactly the group rules', () => {
    expect(statusWhere('ATTENTION')).toEqual(groupWhere('attention'));
    expect(statusWhere('ACTIVE_GROUP')).toEqual(groupWhere('active'));
  });
});
