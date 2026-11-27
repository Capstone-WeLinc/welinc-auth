import { CATALOG } from '../../../prisma/catalog';
import type { SystemDefinition } from './catalog.types';
import {
  permissionFileErrors,
  planPermissionSync,
  type CurrentCell,
  type CurrentPermission,
} from './permission-plan';

// Spec 0013, AC-25: the permission half of catalog:sync.

const roles = [
  { code: 'ADMIN', name: 'Admin', description: 'a', isSystemAdmin: true },
  { code: 'MECHANIC', name: 'Mechanic', description: 'b' },
];

function system(
  permissions: SystemDefinition['permissions'],
): SystemDefinition {
  return {
    system: 'VRMS',
    name: 'VRMS',
    description: 'x',
    maxRolesPerUser: 1,
    roles,
    permissions,
  };
}

const view = {
  key: 'ticket.view',
  label: 'See tickets',
  group: 'Tickets',
  description: 'Open tickets.',
  defaults: { ADMIN: true, MECHANIC: true },
};
const locked = {
  key: 'team.manage',
  label: 'Manage the team',
  group: 'Admin',
  description: 'Reassign work.',
  defaults: { ADMIN: true, MECHANIC: false },
  lockedRoles: ['ADMIN'],
};

function row(
  p: typeof view,
  sortOrder: number,
  lockedRoles: string[] = [],
): CurrentPermission {
  return {
    system: 'VRMS',
    key: p.key,
    label: p.label,
    group: p.group,
    description: p.description,
    sortOrder,
    lockedRoles,
    defaultRoles: Object.keys(p.defaults)
      .filter((role) => (p.defaults as Record<string, boolean>)[role])
      .sort(),
  };
}

function cell(role: string, key: string, allowed: boolean): CurrentCell {
  return { system: 'VRMS', role, key, allowed };
}

describe('permissionFileErrors (AC-25)', () => {
  it('accepts every system file in the catalog', () => {
    for (const definition of CATALOG)
      expect(permissionFileErrors(definition)).toEqual([]);
  });

  it('refuses a default or a lock naming a role the system does not have', () => {
    const errors = permissionFileErrors(
      system([
        {
          ...view,
          defaults: { ADMIN: true, MECHANIC: true, DRIVER: true },
          lockedRoles: ['HELPER'],
        },
      ]),
    );
    expect(errors).toEqual([
      expect.stringContaining('the default names DRIVER'),
      expect.stringContaining('the lock names HELPER'),
    ]);
  });

  it('refuses a missing default, a repeated key and a bad key', () => {
    const errors = permissionFileErrors(
      system([
        { ...view, defaults: { ADMIN: true } },
        view,
        { ...view, key: 'Ticket' },
      ]),
    );
    expect(errors).toEqual([
      expect.stringContaining('no default for MECHANIC'),
      expect.stringContaining('listed twice'),
      expect.stringContaining('dotted lower case'),
    ]);
  });
});

describe('planPermissionSync (AC-25)', () => {
  it('inserts every missing cell with its default and bumps once', () => {
    const plan = planPermissionSync(system([view, locked]), {
      permissions: [],
      cells: [],
    });
    expect(plan.upserts.map((p) => p.key)).toEqual([
      'ticket.view',
      'team.manage',
    ]);
    expect(plan.cellInserts).toEqual([
      { role: 'ADMIN', key: 'ticket.view', allowed: true },
      { role: 'MECHANIC', key: 'ticket.view', allowed: true },
      { role: 'ADMIN', key: 'team.manage', allowed: true },
      { role: 'MECHANIC', key: 'team.manage', allowed: false },
    ]);
    expect(plan.changes).toEqual([]);
    expect(plan.bump).toBe(true);
  });

  it('never overwrites an unlocked cell, and changes nothing when the matrix matches', () => {
    const plan = planPermissionSync(system([view, locked]), {
      permissions: [row(view, 0), row(locked, 1, ['ADMIN'])],
      cells: [
        cell('ADMIN', 'ticket.view', false),
        cell('MECHANIC', 'ticket.view', false),
        cell('ADMIN', 'team.manage', true),
        cell('MECHANIC', 'team.manage', true),
      ],
    });
    expect(plan.cellResets).toEqual([]);
    expect(plan.bump).toBe(false);
  });

  it('sets a locked cell back to its default with one history row', () => {
    const plan = planPermissionSync(system([locked]), {
      permissions: [row(locked, 0, ['ADMIN'])],
      cells: [
        cell('ADMIN', 'team.manage', false),
        cell('MECHANIC', 'team.manage', false),
      ],
    });
    expect(plan.cellResets).toEqual([
      { role: 'ADMIN', key: 'team.manage', allowed: true },
    ]);
    expect(plan.changes).toEqual([
      { role: 'ADMIN', key: 'team.manage', before: false, after: true },
    ]);
    expect(plan.bump).toBe(true);
  });

  it('deletes the cells of a dropped key, one history row each with after null', () => {
    const plan = planPermissionSync(system([view]), {
      permissions: [row(view, 0), row(locked, 1, ['ADMIN'])],
      cells: [
        cell('ADMIN', 'ticket.view', true),
        cell('MECHANIC', 'ticket.view', true),
        cell('ADMIN', 'team.manage', true),
        cell('MECHANIC', 'team.manage', false),
      ],
    });
    expect(plan.deletes).toEqual(['team.manage']);
    expect(plan.cellDeletes).toEqual([
      { role: 'ADMIN', key: 'team.manage' },
      { role: 'MECHANIC', key: 'team.manage' },
    ]);
    expect(plan.changes).toEqual([
      { role: 'ADMIN', key: 'team.manage', before: true, after: null },
      { role: 'MECHANIC', key: 'team.manage', before: false, after: null },
    ]);
  });

  it('rewrites a key whose label or lock changed, without touching its cells', () => {
    const plan = planPermissionSync(
      system([{ ...view, label: 'See your tickets' }]),
      {
        permissions: [row(view, 0)],
        cells: [
          cell('ADMIN', 'ticket.view', true),
          cell('MECHANIC', 'ticket.view', true),
        ],
      },
    );
    expect(plan.upserts).toEqual([
      expect.objectContaining({
        key: 'ticket.view',
        label: 'See your tickets',
      }),
    ]);
    expect(plan.cellInserts).toEqual([]);
    expect(plan.bump).toBe(true);
  });

  it('writes default_roles from the defaults, sorted (suite spec 0018, AC-17)', () => {
    const plan = planPermissionSync(system([view, locked]), {
      permissions: [],
      cells: [],
    });
    expect(plan.upserts.map((p) => [p.key, p.defaultRoles])).toEqual([
      ['ticket.view', ['ADMIN', 'MECHANIC']],
      ['team.manage', ['ADMIN']],
    ]);
  });

  it('rewrites a key whose defaults changed, without touching its cells (AC-17)', () => {
    const plan = planPermissionSync(
      system([{ ...view, defaults: { ADMIN: true, MECHANIC: false } }]),
      {
        permissions: [row(view, 0)],
        cells: [
          cell('ADMIN', 'ticket.view', true),
          cell('MECHANIC', 'ticket.view', true),
        ],
      },
    );
    expect(plan.upserts).toEqual([
      expect.objectContaining({ key: 'ticket.view', defaultRoles: ['ADMIN'] }),
    ]);
    expect(plan.cellResets).toEqual([]);
    expect(plan.changes).toEqual([]);
    expect(plan.bump).toBe(true);
  });

  it('treats default_roles stored in another order as unchanged (AC-17)', () => {
    const plan = planPermissionSync(system([view]), {
      permissions: [{ ...row(view, 0), defaultRoles: ['MECHANIC', 'ADMIN'] }],
      cells: [
        cell('ADMIN', 'ticket.view', true),
        cell('MECHANIC', 'ticket.view', true),
      ],
    });
    expect(plan.bump).toBe(false);
  });

  it('leaves a system with no permissions list with an empty matrix', () => {
    const plan = planPermissionSync(system(undefined), {
      permissions: [],
      cells: [],
    });
    expect(plan.bump).toBe(false);
  });
});

describe('planPermissionSync and custom roles (suite spec 0018 child 0002, AC-30)', () => {
  // covers: suite spec 0018 child 0002 AC-30
  it("keeps a custom role's cells, adds none for it, and removes them only when the key leaves", () => {
    const plan = planPermissionSync(system([view]), {
      permissions: [row(view, 0), row(locked, 1, ['ADMIN'])],
      cells: [
        cell('ADMIN', 'ticket.view', true),
        cell('MECHANIC', 'ticket.view', true),
        cell('C_TIRES', 'ticket.view', false),
        cell('ADMIN', 'team.manage', true),
        cell('MECHANIC', 'team.manage', false),
        cell('C_TIRES', 'team.manage', true),
      ],
      customRoles: ['C_TIRES'],
    });

    expect(plan.cellInserts).toEqual([]);
    expect(plan.cellResets).toEqual([]);
    expect(plan.cellDeletes).toEqual([
      { role: 'ADMIN', key: 'team.manage' },
      { role: 'C_TIRES', key: 'team.manage' },
      { role: 'MECHANIC', key: 'team.manage' },
    ]);
    expect(plan.deletes).toEqual(['team.manage']);
  });

  it('still removes the cells of a role that left the file and is not custom', () => {
    const plan = planPermissionSync(system([view]), {
      permissions: [row(view, 0)],
      cells: [
        cell('ADMIN', 'ticket.view', true),
        cell('MECHANIC', 'ticket.view', true),
        cell('DRIVER', 'ticket.view', true),
      ],
      customRoles: [],
    });
    expect(plan.cellDeletes).toEqual([{ role: 'DRIVER', key: 'ticket.view' }]);
  });
});
