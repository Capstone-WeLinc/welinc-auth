/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access -- the faked database is untyped on purpose */
import { describe, it, expect, jest } from '@jest/globals';
import { SystemType } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import { encodeEventCursor } from '../events/event-cursor';
import type { MatrixService } from '../permissions/matrix.service';
import { RolesAdminService } from './roles-admin.service';

// Suite spec 0018, child 0001 AC-15 and AC-17: the Roles page reads, on a faked database.

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const T = (s: string) => new Date(`2026-11-20T08:00:${s}.000Z`);
const uuid = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

function build() {
  const db = {
    systemRole: { findMany: fn(), findUnique: fn() },
    systemPermission: { findMany: fn() },
    rolePermission: { findMany: fn() },
    userRoleAssignment: { groupBy: fn() },
    permissionChange: { findMany: fn(), findFirst: fn() },
    roleEvent: { findMany: fn() },
    $queryRaw: fn(),
  };
  const matrix = { version: fn() };
  matrix.version.mockResolvedValue(7);
  db.systemPermission.findMany.mockResolvedValue([
    {
      key: 'ticket.view',
      label: 'See tickets',
      group: 'Tickets',
      description: 'Open your tickets.',
      lockedRoles: [],
      defaultRoles: ['ADMIN', 'MECHANIC'],
    },
    {
      key: 'audit.view',
      label: 'See the audit trail',
      group: 'Records',
      description: 'Read who did what.',
      lockedRoles: ['ADMIN'],
      defaultRoles: ['ADMIN'],
    },
    {
      key: 'ticket.assign',
      label: 'Assign mechanics',
      group: 'Tickets',
      description: 'Pick who works a ticket.',
      lockedRoles: [],
      defaultRoles: ['ADMIN'],
    },
  ]);
  db.roleEvent.findMany.mockResolvedValue([]);
  db.$queryRaw.mockResolvedValue([]);
  const service = new RolesAdminService(
    db as unknown as PrismaService,
    matrix as unknown as MatrixService,
  );
  return { service, db };
}

const role = (
  code: string,
  name: string,
  sortOrder: number,
  extra: Record<string, unknown> = {},
) => ({
  code,
  name,
  description: `${name} does things`,
  isBuiltIn: true,
  isSystemAdmin: false,
  copiedFrom: null,
  sortOrder,
  ...extra,
});

describe('RolesAdminService.page (AC-17)', () => {
  it('lists live roles built in first by catalog order, then custom by name, with counts, cells and groups', async () => {
    const { service, db } = build();
    db.systemRole.findMany
      .mockResolvedValueOnce([
        role('C_ZETA', 'zeta crew', 9, {
          isBuiltIn: false,
          copiedFrom: 'MECHANIC',
        }),
        role('MECHANIC', 'Mechanic', 2),
        role('C_ALPHA', 'Alpha crew', 9, { isBuiltIn: false }),
        role('ADMIN', 'Admin', 0, { isSystemAdmin: true }),
      ])
      .mockResolvedValueOnce([{ code: 'MECHANIC', name: 'Mechanic' }]);
    db.rolePermission.findMany.mockResolvedValue([
      { role: 'ADMIN', key: 'ticket.assign' },
      { role: 'ADMIN', key: 'ticket.view' },
      { role: 'MECHANIC', key: 'ticket.view' },
    ]);
    db.userRoleAssignment.groupBy
      // Live holders, then people in their deletion grace period
      .mockResolvedValueOnce([{ role: 'MECHANIC', _count: { _all: 8 } }])
      .mockResolvedValueOnce([{ role: 'C_ZETA', _count: { _all: 2 } }]);
    db.$queryRaw.mockResolvedValue([
      { role: 'MECHANIC', created_at: T('10'), actor_name: 'Catalog sync' },
      { role: 'ADMIN', created_at: T('11'), actor_name: null },
    ]);

    const page = await service.page(SystemType.VRMS, true);

    expect(page.roles.map((r) => r.code)).toEqual([
      'ADMIN',
      'MECHANIC',
      'C_ALPHA',
      'C_ZETA',
    ]);
    expect(page).toMatchObject({
      system: SystemType.VRMS,
      supportsCustomRoles: true,
      canEdit: true,
      version: 7,
    });
    const mechanic = page.roles[1];
    expect(mechanic.peopleCount).toBe(8);
    expect(mechanic.graceCount).toBe(0);
    expect(mechanic.lastChanged).toEqual({
      at: T('10').toISOString(),
      byName: 'System',
    });
    expect(page.roles[0].lastChanged?.byName).toBe('Deleted user');
    expect(page.roles[2]).toMatchObject({
      builtIn: false,
      peopleCount: 0,
      lastChanged: null,
      copiedFrom: null,
    });
    expect(page.roles[2].graceCount).toBe(0);
    expect(page.roles[3]).toMatchObject({ peopleCount: 0, graceCount: 2 });
    // The grace count flips only the deleted filter
    expect(db.userRoleAssignment.groupBy.mock.calls[1][0].where).toMatchObject({
      system: SystemType.VRMS,
      user: { deletedAt: { not: null } },
    });
    expect(page.roles[3].copiedFrom).toEqual({
      code: 'MECHANIC',
      name: 'Mechanic',
    });
    // Cells in catalog order, an empty list for a role holding nothing
    expect(page.cells).toEqual({
      ADMIN: ['ticket.view', 'ticket.assign'],
      MECHANIC: ['ticket.view'],
      C_ALPHA: [],
      C_ZETA: [],
    });
    expect(
      page.groups.map((g) => [g.name, g.permissions.map((p) => p.key)]),
    ).toEqual([
      ['Tickets', ['ticket.view', 'ticket.assign']],
      ['Records', ['audit.view']],
    ]);
    expect(page.groups[1].permissions[0]).toEqual({
      key: 'audit.view',
      label: 'See the audit trail',
      description: 'Read who did what.',
      lockedRoles: ['ADMIN'],
      defaultRoles: ['ADMIN'],
    });
  });

  it('reads live roles only, and counts only people who are not deleted', async () => {
    const { service, db } = build();
    db.systemRole.findMany.mockResolvedValue([]);
    db.rolePermission.findMany.mockResolvedValue([]);
    db.userRoleAssignment.groupBy.mockResolvedValue([]);
    await service.page(SystemType.VRMS, false);
    expect(db.systemRole.findMany.mock.calls[0][0].where).toEqual({
      system: SystemType.VRMS,
      deletedAt: null,
    });
    expect(db.userRoleAssignment.groupBy.mock.calls[0][0].where).toMatchObject({
      system: SystemType.VRMS,
      user: { deletedAt: null },
    });
  });

  it('offers no custom roles for a system with no permission keys', async () => {
    const { service, db } = build();
    db.systemPermission.findMany.mockResolvedValue([]);
    db.systemRole.findMany.mockResolvedValue([role('ADMIN', 'Admin', 0)]);
    db.rolePermission.findMany.mockResolvedValue([]);
    db.userRoleAssignment.groupBy.mockResolvedValue([]);
    const page = await service.page(SystemType.BMS, true);
    expect(page.supportsCustomRoles).toBe(false);
    expect(page.groups).toEqual([]);
  });
});

describe('RolesAdminService.history (AC-15, AC-17)', () => {
  const change = (
    n: number,
    at: string,
    extra: Record<string, unknown> = {},
  ) => ({
    id: uuid(n),
    createdAt: T(at),
    key: 'ticket.view',
    before: false,
    after: true,
    actorName: 'Leonora Castillo',
    note: null,
    ...extra,
  });
  const event = (
    n: number,
    at: string,
    extra: Record<string, unknown> = {},
  ) => ({
    id: uuid(n),
    createdAt: T(at),
    kind: 'RENAMED',
    fromValue: 'Parts clerk',
    toValue: 'Parts and costs clerk',
    actorName: 'Leonora Castillo',
    ...extra,
  });

  it('merges permission changes and role events newest first, with labels and the sync as System', async () => {
    const { service, db } = build();
    db.systemRole.findUnique.mockResolvedValue({ isBuiltIn: true });
    db.permissionChange.findMany.mockResolvedValue([
      change(3, '30', { note: 'Costs moved to the office' }),
      change(1, '10', { actorName: 'Catalog sync', key: 'gone.key' }),
    ]);
    db.roleEvent.findMany.mockResolvedValue([event(2, '20')]);

    const { items, next } = await service.history(
      SystemType.VRMS,
      'MECHANIC',
      {},
    );

    expect(next).toBeNull();
    expect(items).toEqual([
      {
        id: uuid(3),
        at: T('30').toISOString(),
        actorName: 'Leonora Castillo',
        kind: 'PERMISSION',
        key: 'ticket.view',
        label: 'See tickets',
        before: false,
        after: true,
        note: 'Costs moved to the office',
      },
      {
        id: uuid(2),
        at: T('20').toISOString(),
        actorName: 'Leonora Castillo',
        kind: 'RENAMED',
        fromValue: 'Parts clerk',
        toValue: 'Parts and costs clerk',
      },
      expect.objectContaining({
        id: uuid(1),
        actorName: 'System',
        // A key that left the catalog keeps its key as the label
        label: 'gone.key',
      }),
    ]);
  });

  it('pages across both sources with one cursor, ties broken by id', async () => {
    const { service, db } = build();
    db.systemRole.findUnique.mockResolvedValue({ isBuiltIn: true });
    db.permissionChange.findMany.mockResolvedValue([
      change(5, '30'),
      change(4, '20'),
    ]);
    db.roleEvent.findMany.mockResolvedValue([event(6, '20')]);

    const first = await service.history(SystemType.VRMS, 'MECHANIC', {
      limit: 2,
    });
    expect(first.items.map((i) => i.id)).toEqual([uuid(5), uuid(6)]);
    expect(first.next).toBe(
      encodeEventCursor({ createdAt: T('20'), id: uuid(6) }),
    );

    await service.history(SystemType.VRMS, 'MECHANIC', {
      cursor: first.next ?? undefined,
    });
    const keyset = {
      OR: [
        { createdAt: { lt: T('20') } },
        { createdAt: T('20'), id: { lt: uuid(6) } },
      ],
    };
    expect(db.permissionChange.findMany.mock.calls[1][0].where).toMatchObject(
      keyset,
    );
    expect(db.roleEvent.findMany.mock.calls[1][0].where).toMatchObject(keyset);
  });

  it("leaves out a custom role's create and delete cell rows, never a built in role's", async () => {
    const custom = build();
    custom.db.systemRole.findUnique.mockResolvedValue({ isBuiltIn: false });
    custom.db.permissionChange.findMany.mockResolvedValue([]);
    await custom.service.history(SystemType.VRMS, 'C_TIRE_SPECIALIST', {});
    expect(
      custom.db.permissionChange.findMany.mock.calls[0][0].where,
    ).toMatchObject({ before: { not: null }, after: { not: null } });

    const builtIn = build();
    builtIn.db.systemRole.findUnique.mockResolvedValue({ isBuiltIn: true });
    builtIn.db.permissionChange.findMany.mockResolvedValue([]);
    await builtIn.service.history(SystemType.VRMS, 'MECHANIC', {});
    const where = builtIn.db.permissionChange.findMany.mock.calls[0][0].where;
    expect(where.before).toBeUndefined();
    expect(where.after).toBeUndefined();
  });

  it('answers 404 for a code that never existed, and reads a role that left the catalog', async () => {
    const { service, db } = build();
    db.systemRole.findUnique.mockResolvedValue(null);
    db.permissionChange.findFirst.mockResolvedValueOnce(null);
    await expect(
      service.history(SystemType.VRMS, 'NOPE', {}),
    ).rejects.toMatchObject({ response: { code: 'NOT_FOUND' } });

    db.permissionChange.findFirst.mockResolvedValueOnce({ id: uuid(1) });
    db.permissionChange.findMany.mockResolvedValue([change(1, '10')]);
    const { items } = await service.history(SystemType.VRMS, 'HELPER', {});
    expect(items).toHaveLength(1);
  });

  it('defaults to 25 rows and caps the limit at 100', async () => {
    const { service, db } = build();
    db.systemRole.findUnique.mockResolvedValue({ isBuiltIn: true });
    db.permissionChange.findMany.mockResolvedValue([]);
    await service.history(SystemType.VRMS, 'MECHANIC', {});
    await service.history(SystemType.VRMS, 'MECHANIC', { limit: 500 });
    expect(db.permissionChange.findMany.mock.calls[0][0].take).toBe(26);
    expect(db.permissionChange.findMany.mock.calls[1][0].take).toBe(101);
  });
});
