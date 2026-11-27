import { describe, it, expect } from '@jest/globals';
import { SystemType } from '@prisma/client';
import { readFileSync } from 'fs';
import { join } from 'path';
import { CATALOG } from '../../../prisma/catalog';
import {
  describePlan,
  hasChanges,
  planCatalogSync,
  type CurrentRole,
  type CurrentSystem,
  type Holding,
} from './catalog-plan';
import type { SystemDefinition } from './catalog.types';
import {
  SYSTEMS_CACHE_CONTROL,
  SystemsController,
  etagOf,
  matchesEtag,
} from './systems.controller';
import type { CatalogService } from './catalog.service';
import type { PrismaService } from '../../shared/prisma.service';
import {
  CatalogService as RealCatalogService,
  liveOrder,
  roleLimitMessage,
} from './catalog.service';

// Spec 0004: the catalog files, the sync's plan and refusals (AC-1 to AC-4, AC-6), and the
// /auth/systems cache headers (AC-16).

const ALL = Object.values(SystemType);

/** The tables exactly as the files say: what the AC-6 migration leaves. */
function synced(definitions: SystemDefinition[] = CATALOG): {
  systems: CurrentSystem[];
  roles: CurrentRole[];
} {
  return {
    systems: definitions.map((d) => ({
      code: d.system,
      name: d.name,
      description: d.description,
      maxRolesPerUser: d.maxRolesPerUser,
    })),
    roles: definitions.flatMap((d) =>
      d.roles.map((r, i) => ({
        system: d.system,
        code: r.code,
        name: r.name,
        description: r.description,
        sortOrder: i,
        isSystemAdmin: r.isSystemAdmin === true,
        isBuiltIn: true,
      })),
    ),
  };
}

const holding = (
  system: SystemType,
  role: string,
  email = 'pedro@welinc.com',
  overrides: Partial<Holding> = {},
): Holding => ({
  userId: email,
  email,
  system,
  role,
  active: true,
  ...overrides,
});

/** The catalog with one system's file changed. */
function edit(
  system: SystemType,
  change: (d: SystemDefinition) => SystemDefinition,
): SystemDefinition[] {
  return CATALOG.map((d) => (d.system === system ? change(d) : d));
}

describe('catalog files', () => {
  // covers: AC-1
  it('has one file per SystemType, each with exactly one admin role listed first', () => {
    expect(CATALOG.map((d) => d.system).sort()).toEqual([...ALL].sort());
    for (const d of CATALOG) {
      expect(d.roles[0].isSystemAdmin).toBe(true);
      expect(d.roles.filter((r) => r.isSystemAdmin)).toHaveLength(1);
      expect(d.maxRolesPerUser).toBe(1);
    }
  });

  // covers: AC-21
  it('gives BMS Driver and Helper', () => {
    const bms = CATALOG.find((d) => d.system === SystemType.BMS);
    expect(bms?.roles.map((r) => r.code)).toEqual([
      'ADMIN',
      'OPERATIONS',
      'CUSTOMER_SUPPORT',
      'DRIVER',
      'HELPER',
    ]);
  });

  // covers: AC-6
  // covers: spec 0007 AC-5, AC-7 (the description migration leaves '' until the sync writes it)
  it('matches the starting catalog the migrations insert, so the first sync writes only the descriptions', () => {
    const sql = readFileSync(
      join(
        __dirname,
        '../../../prisma/migrations/20261110000000_roles_per_system/migration.sql',
      ),
      'utf8',
    );
    const systems = [
      ...sql.matchAll(/\('(\w+)', '([^']+)', (\d+|NULL), CURRENT_TIMESTAMP\)/g),
    ].map((m) => ({
      code: m[1] as SystemType,
      name: m[2],
      description: '',
      maxRolesPerUser: m[3] === 'NULL' ? null : Number(m[3]),
    }));
    const roles = [
      ...sql.matchAll(
        /\('(\w+)', '(\w+)', '([^']+)', '([^']+)', (\d+), (true|false), CURRENT_TIMESTAMP\)/g,
      ),
    ].map((m) => ({
      system: m[1] as SystemType,
      code: m[2],
      name: m[3],
      description: m[4],
      sortOrder: Number(m[5]),
      isSystemAdmin: m[6] === 'true',
      isBuiltIn: true,
    }));

    const plan = planCatalogSync(CATALOG, ALL, { systems, roles }, []);

    expect(plan.errors).toEqual([]);
    const changed = plan.systems.filter(hasChanges);
    expect(changed.map((p) => p.system)).toEqual(['VRMS', 'VMMS', 'BMS']);
    for (const p of changed) {
      expect(p.inserts).toEqual([]);
      expect(p.updates).toEqual([]);
      expect(p.deletes).toEqual([]);
      const before = systems.find((x) => x.code === p.system)!;
      expect({ ...p.systemRow, description: '' }).toEqual(before);
    }
    expect(roles).toHaveLength(12);
  });
});

describe('planCatalogSync', () => {
  // covers: AC-2
  it('reports no change per system when the tables match the files', () => {
    const plan = planCatalogSync(CATALOG, ALL, synced(), []);

    expect(plan.errors).toEqual([]);
    expect(plan.systems.map(describePlan)).toEqual([
      'VRMS: 3 roles, no change',
      'VMMS: 4 roles, no change',
      'BMS: 5 roles, no change',
    ]);
  });

  it('inserts every row into empty tables', () => {
    const plan = planCatalogSync(CATALOG, ALL, { systems: [], roles: [] }, []);

    expect(plan.errors).toEqual([]);
    const vrms = plan.systems[0];
    expect(vrms.systemRow).toEqual({
      code: 'VRMS',
      name: 'Vehicle Repair Management System',
      description: 'Repair tickets, mechanics and workshop work',
      maxRolesPerUser: 1,
    });
    expect(vrms.inserts.map((r) => [r.code, r.sortOrder])).toEqual([
      ['ADMIN', 0],
      ['CHIEF_MECHANIC', 1],
      ['MECHANIC', 2],
    ]);
  });

  it('updates names, descriptions and order, and adds a new role', () => {
    const files = edit(SystemType.VRMS, (d) => ({
      ...d,
      roles: [
        d.roles[0],
        {
          code: 'SERVICE_ADVISOR',
          name: 'Service Advisor',
          description: 'Writes up repairs',
        },
        { ...d.roles[1], description: 'Leads the shop' },
        d.roles[2],
      ],
    }));

    const plan = planCatalogSync(files, ALL, synced(), []);

    const vrms = plan.systems[0];
    expect(plan.errors).toEqual([]);
    expect(vrms.inserts.map((r) => r.code)).toEqual(['SERVICE_ADVISOR']);
    expect(vrms.updates.map((r) => [r.code, r.sortOrder])).toEqual([
      ['CHIEF_MECHANIC', 2],
      ['MECHANIC', 3],
    ]);
    expect(describePlan(vrms)).toBe(
      'VRMS: 4 roles, added SERVICE_ADVISOR; updated CHIEF_MECHANIC, MECHANIC',
    );
  });

  it('removes a role nobody holds', () => {
    const files = edit(SystemType.BMS, (d) => ({
      ...d,
      roles: d.roles.filter((r) => r.code !== 'HELPER'),
    }));

    const plan = planCatalogSync(files, ALL, synced(), []);

    expect(plan.errors).toEqual([]);
    expect(plan.systems[2].deletes).toEqual(['HELPER']);
  });

  // covers: AC-3
  describe('refusals', () => {
    const errorsFor = (files: SystemDefinition[], holdings: Holding[] = []) =>
      planCatalogSync(files, ALL, synced(), holdings).errors;

    it('refuses dropping a role someone holds, listing the holders', () => {
      const files = edit(SystemType.BMS, (d) => ({
        ...d,
        roles: d.roles.filter((r) => r.code !== 'HELPER'),
      }));

      expect(
        errorsFor(files, [holding(SystemType.BMS, 'HELPER', 'h@welinc.com')]),
      ).toEqual([
        "BMS: can't remove HELPER, 1 account holds it: h@welinc.com. Move them to another role first.",
      ]);
    });

    it('lists at most 20 holder emails', () => {
      const files = edit(SystemType.BMS, (d) => ({
        ...d,
        roles: d.roles.filter((r) => r.code !== 'HELPER'),
      }));
      const many = Array.from({ length: 23 }, (_, i) =>
        holding(
          SystemType.BMS,
          'HELPER',
          `h${String(i).padStart(2, '0')}@welinc.com`,
        ),
      );

      const [error] = errorsFor(files, many);

      expect(error).toContain('23 accounts hold it');
      expect(error).toContain('h19@welinc.com and 3 more');
      expect(error).not.toContain('h20@welinc.com');
    });

    // covers: AC-4
    it('treats a renamed code as a drop plus an add, so a held role refuses', () => {
      const files = edit(SystemType.VRMS, (d) => ({
        ...d,
        roles: d.roles.map((r) =>
          r.code === 'MECHANIC' ? { ...r, code: 'TECHNICIAN' } : r,
        ),
      }));

      expect(errorsFor(files, [holding(SystemType.VRMS, 'MECHANIC')])).toEqual([
        expect.stringContaining("VRMS: can't remove MECHANIC"),
      ]);
    });

    it.each([
      ['a bad code', { code: 'mechanic' }, 'must match'],
      ['a one letter code', { code: 'M' }, 'must match'],
      ['a code repeated', { code: 'ADMIN' }, "'ADMIN' appears twice"],
    ])('refuses %s', (_label, roleChange, message) => {
      const files = edit(SystemType.VRMS, (d) => ({
        ...d,
        roles: d.roles.map((r) =>
          r.code === 'MECHANIC' ? { ...r, ...roleChange } : r,
        ),
      }));

      expect(errorsFor(files).join('\n')).toContain(message);
    });

    it('refuses a system with no role', () => {
      const files = edit(SystemType.VMMS, (d) => ({ ...d, roles: [] }));
      expect(errorsFor(files)).toContain('VMMS: has no role.');
    });

    it('refuses no admin role, and two admin roles', () => {
      const none = edit(SystemType.VRMS, (d) => ({
        ...d,
        roles: d.roles.map((r) => ({ ...r, isSystemAdmin: false })),
      }));
      const two = edit(SystemType.VRMS, (d) => ({
        ...d,
        roles: d.roles.map((r) => ({
          ...r,
          isSystemAdmin: r.code !== 'MECHANIC',
        })),
      }));

      expect(errorsFor(none)).toContain(
        'VRMS: needs exactly one isSystemAdmin role, found 0.',
      );
      expect(errorsFor(two)).toContain(
        'VRMS: needs exactly one isSystemAdmin role, found 2.',
      );
    });

    // covers: spec 0007 AC-5
    it('refuses an empty or too long system description, listing every problem', () => {
      const files = CATALOG.map((d) =>
        d.system === SystemType.VRMS
          ? { ...d, description: '  ' }
          : d.system === SystemType.BMS
            ? { ...d, description: 'x'.repeat(201) }
            : d,
      );
      const errors = errorsFor(files).filter((e) =>
        e.includes('system description'),
      );
      expect(errors).toEqual([
        'VRMS: the system description must be 1 to 200 characters.',
        'BMS: the system description must be 1 to 200 characters.',
      ]);
    });

    it('updates a reworded system description and nothing else', () => {
      const files = edit(SystemType.VMMS, (d) => ({
        ...d,
        description: 'Fleet upkeep',
      }));
      const plan = planCatalogSync(files, ALL, synced(), []);
      expect(plan.errors).toEqual([]);
      expect(plan.systems.filter(hasChanges).map(describePlan)).toEqual([
        'VMMS: 4 roles, system details updated',
      ]);
    });

    it('refuses a limit below 1', () => {
      const files = edit(SystemType.VRMS, (d) => ({
        ...d,
        maxRolesPerUser: 0,
      }));
      expect(errorsFor(files).join()).toContain('maxRolesPerUser');
    });

    it('refuses a SystemType with no file', () => {
      const files = CATALOG.filter((d) => d.system !== SystemType.BMS);
      expect(errorsFor(files)).toContain(
        'BMS: has no catalog file in prisma/catalog/.',
      );
    });

    it('refuses a limit below what an account already holds', () => {
      const files = edit(SystemType.VRMS, (d) => ({
        ...d,
        maxRolesPerUser: 1,
      }));
      const current = synced(
        edit(SystemType.VRMS, (d) => ({ ...d, maxRolesPerUser: 2 })),
      );

      const errors = planCatalogSync(files, ALL, current, [
        holding(SystemType.VRMS, 'ADMIN', 'two@welinc.com'),
        holding(SystemType.VRMS, 'MECHANIC', 'two@welinc.com'),
      ]).errors;

      expect(errors).toEqual([
        'VRMS: maxRolesPerUser 1 is below what 1 account already holds: two@welinc.com.',
      ]);
    });

    it('refuses moving the admin flag to a role no active account holds', () => {
      const files = edit(SystemType.VMMS, (d) => ({
        ...d,
        roles: d.roles.map((r) => ({
          ...r,
          isSystemAdmin: r.code === 'OPERATIONS',
        })),
      }));

      expect(
        errorsFor(files, [
          holding(SystemType.VMMS, 'OPERATIONS', 'gone@welinc.com', {
            active: false,
          }),
        ]),
      ).toEqual([
        "VMMS: the admin flag can't move to OPERATIONS, no active account holds it.",
      ]);
      expect(
        errorsFor(files, [holding(SystemType.VMMS, 'OPERATIONS')]),
      ).toEqual([]);
    });
  });
});

describe('/auth/systems cache headers', () => {
  // covers: AC-16
  it('gives the same body the same strong tag, and a different body another', () => {
    expect(etagOf('{"a":1}')).toBe(etagOf('{"a":1}'));
    expect(etagOf('{"a":1}')).not.toBe(etagOf('{"a":2}'));
    expect(etagOf('x')).toMatch(/^"[A-Za-z0-9_-]{32}"$/);
  });

  it('matches If-None-Match lists, weak tags and *', () => {
    const tag = etagOf('body');
    expect(matchesEtag(tag, tag)).toBe(true);
    expect(matchesEtag(`"other", W/${tag}`, tag)).toBe(true);
    expect(matchesEtag('*', tag)).toBe(true);
    expect(matchesEtag('"other"', tag)).toBe(false);
    expect(matchesEtag(undefined, tag)).toBe(false);
  });
});

describe('GET /auth/systems carries the description', () => {
  // covers: spec 0007 AC-5 (`description` in each system, and the ETag moves with it)
  async function answer(description: string, ifNoneMatch?: string) {
    const catalog = {
      systems: () =>
        Promise.resolve([
          {
            code: SystemType.BMS,
            name: 'Booking Management System',
            description,
            maxRolesPerUser: 1,
            roles: [],
          },
        ]),
    };
    const prisma = {
      oAuthClient: {
        findMany: () =>
          Promise.resolve([
            { system: SystemType.BMS, webAddress: 'http://localhost:8003' },
          ]),
      },
    };
    const controller = new SystemsController(
      catalog as unknown as CatalogService,
      prisma as unknown as PrismaService,
    );
    const headers: Record<string, string> = {};
    let status = 0;
    let body = '';
    const res = {
      setHeader: (k: string, v: string) => (headers[k] = v),
      status(code: number) {
        status = code;
        return res;
      },
      type: () => res,
      send(b: string) {
        body = b;
      },
      end: () => undefined,
    };
    await controller.systems(
      { headers: { 'if-none-match': ifNoneMatch } } as never,
      res as never,
    );
    return { headers, status, body };
  }

  it('puts the description in each system and a strong tag on the answer', async () => {
    const a = await answer('Bookings, dispatch and trips');
    expect(a.status).toBe(200);
    expect(
      (JSON.parse(a.body) as { systems: { description: string }[] }).systems[0]
        .description,
    ).toBe('Bookings, dispatch and trips');
    expect(a.headers.ETag).toBe(etagOf(a.body));
  });

  it('changes the ETag when only a description changes, and answers 304 for the current tag', async () => {
    const before = await answer('Bookings, dispatch and trips');
    const after = await answer('Bookings and dispatch');
    expect(after.headers.ETag).not.toBe(before.headers.ETag);
    expect(
      (await answer('Bookings, dispatch and trips', before.headers.ETag))
        .status,
    ).toBe(304);
    expect(
      (await answer('Bookings and dispatch', before.headers.ETag)).status,
    ).toBe(200);
  });
});

describe('ROLE_LIMIT message', () => {
  it('says one role or N roles', () => {
    expect(roleLimitMessage(SystemType.VRMS, 1)).toBe(
      'VRMS allows one role per person.',
    );
    expect(roleLimitMessage(SystemType.BMS, 2)).toBe(
      'BMS allows 2 roles per person.',
    );
  });
});

describe('custom roles in the sync and the catalog reads (suite spec 0018 child 0002)', () => {
  // covers: suite spec 0018 child 0002 AC-29, AC-30
  const custom = (code: string, name: string): CurrentRole => ({
    system: SystemType.VRMS,
    code,
    name,
    description: 'Made in the portal',
    sortOrder: 0,
    isSystemAdmin: false,
    isBuiltIn: false,
  });

  it('never plans, updates or removes a custom role, live or archived, even one people hold', () => {
    const tables = synced();
    tables.roles.push(
      custom('C_TIRE_SPECIALIST', 'Tire specialist'),
      // A custom name equal to a built in name: the sync never checks names
      custom('C_MECHANIC_OLD', 'Mechanic'),
    );
    const holdings: Holding[] = [
      {
        userId: 'u1',
        email: 'tires@welinc.com',
        system: SystemType.VRMS,
        role: 'C_TIRE_SPECIALIST',
        active: true,
      },
    ];

    const plan = planCatalogSync(CATALOG, ALL, tables, holdings);

    expect(plan.errors).toEqual([]);
    expect(plan.systems.map(describePlan)).toEqual([
      'VRMS: 3 roles, no change',
      'VMMS: 4 roles, no change',
      'BMS: 5 roles, no change',
    ]);
  });

  it('refuses a catalog code starting with C_', () => {
    const vrms = CATALOG.find((d) => d.system === 'VRMS') as SystemDefinition;
    const files = CATALOG.map((d) =>
      d === vrms
        ? {
            ...d,
            roles: [
              ...d.roles,
              { code: 'C_FOREMAN', name: 'Foreman', description: 'x' },
            ],
          }
        : d,
    );

    const plan = planCatalogSync(files, ALL, synced(), []);

    expect(plan.errors).toEqual([
      "VRMS: role code 'C_FOREMAN': codes starting with C_ are kept for custom roles.",
    ]);
  });

  it('sorts live roles built in first by catalog order, then custom by name ignoring case', () => {
    const order = liveOrder([
      { name: 'zebra crew', isBuiltIn: false, sortOrder: 0 },
      { name: 'Mechanic', isBuiltIn: true, sortOrder: 2 },
      { name: 'Admin', isBuiltIn: true, sortOrder: 0 },
      { name: 'Night shift lead', isBuiltIn: false, sortOrder: 0 },
      { name: 'Chief Mechanic', isBuiltIn: true, sortOrder: 1 },
    ]);
    expect(order.map((r) => r.name)).toEqual([
      'Admin',
      'Chief Mechanic',
      'Mechanic',
      'Night shift lead',
      'zebra crew',
    ]);
  });

  it('reads live roles only, with builtIn, and answers /auth/systems with no-cache', async () => {
    const rows = [
      {
        code: SystemType.VRMS,
        name: 'VRMS',
        description: 'x',
        maxRolesPerUser: 1,
        roles: [
          {
            code: 'C_TIRES',
            name: 'Tires',
            description: 'c',
            isSystemAdmin: false,
            isBuiltIn: false,
            sortOrder: 0,
          },
          {
            code: 'ADMIN',
            name: 'Admin',
            description: 'a',
            isSystemAdmin: true,
            isBuiltIn: true,
            sortOrder: 0,
          },
        ],
      },
    ];
    let where: unknown;
    const db = {
      system: {
        findMany: (args: { select: { roles: { where: unknown } } }) => {
          where = args.select.roles.where;
          return Promise.resolve(rows);
        },
      },
    };
    const service = new RealCatalogService(db as unknown as PrismaService);
    const systems = await service.systems();

    expect(where).toEqual({ deletedAt: null });
    expect(systems[0].roles).toEqual([
      {
        code: 'ADMIN',
        name: 'Admin',
        description: 'a',
        isSystemAdmin: true,
        builtIn: true,
      },
      {
        code: 'C_TIRES',
        name: 'Tires',
        description: 'c',
        isSystemAdmin: false,
        builtIn: false,
      },
    ]);
    expect(SYSTEMS_CACHE_CONTROL).toBe('no-cache');
  });
});
