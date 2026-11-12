/* eslint-disable @typescript-eslint/require-await -- test doubles */
import { describe, expect, it, jest } from '@jest/globals';
import type { PrismaService } from '../../shared/prisma.service';
import type { AdminAlertsService } from '../admin/admin-alerts.service';
import { MatrixService } from './matrix.service';

// Spec 0013, AC-27: the matrix PATCH rules, on an in memory matrix.

type Cell = { role: string; key: string; allowed: boolean };

function setup() {
  const state = {
    version: 3,
    roles: ['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC'],
    permissions: [
      {
        key: 'ticket.view',
        label: 'See tickets',
        group: 'Tickets',
        description: 'd',
        lockedRoles: [] as string[],
      },
      {
        key: 'team.manage',
        label: 'Manage the team',
        group: 'Admin',
        description: 'd',
        lockedRoles: ['ADMIN'],
      },
    ],
    cells: [
      { role: 'ADMIN', key: 'ticket.view', allowed: true },
      { role: 'CHIEF_MECHANIC', key: 'ticket.view', allowed: true },
      { role: 'MECHANIC', key: 'ticket.view', allowed: false },
      { role: 'ADMIN', key: 'team.manage', allowed: true },
      { role: 'CHIEF_MECHANIC', key: 'team.manage', allowed: false },
      { role: 'MECHANIC', key: 'team.manage', allowed: false },
    ] as Cell[],
    history: [] as Record<string, unknown>[],
  };
  const db = {
    $queryRaw: jest.fn(async () => [{ version: state.version }]),
    $executeRaw: jest.fn(async () => {
      state.version += 1;
      return 1;
    }),
    permissionMatrix: {
      findUnique: jest.fn(async () => ({ version: state.version })),
    },
    systemRole: {
      findMany: jest.fn(async () =>
        state.roles.map((code) => ({ code, name: code })),
      ),
    },
    systemPermission: { findMany: jest.fn(async () => state.permissions) },
    rolePermission: {
      findMany: jest.fn(async (args: { where: { allowed?: boolean } }) =>
        state.cells.filter(
          (c) =>
            args.where.allowed === undefined ||
            c.allowed === args.where.allowed,
        ),
      ),
      upsert: jest.fn(
        async (args: {
          where: { system_role_key: { role: string; key: string } };
          update: { allowed: boolean };
        }) => {
          const { role, key } = args.where.system_role_key;
          const cell = state.cells.find(
            (c) => c.role === role && c.key === key,
          );
          if (cell) cell.allowed = args.update.allowed;
        },
      ),
    },
    permissionChange: {
      createMany: jest.fn(async (args: { data: Record<string, unknown>[] }) => {
        state.history.push(...args.data);
      }),
    },
    $transaction: jest.fn(async (fn: (tx: unknown) => Promise<unknown>) =>
      fn(db),
    ),
  };
  const alerts = {
    send: jest.fn(async (actorId: string | null, list: unknown[]) => {
      void actorId;
      void list;
    }),
  };
  const service = new MatrixService(
    db as unknown as PrismaService,
    alerts as unknown as AdminAlertsService,
  );
  const actor = { id: 'a1', name: 'Suite Admin', email: 'suite@example.com' };
  return { service, state, alerts, actor };
}

const code = (c: string) =>
  expect.objectContaining({ response: expect.objectContaining({ code: c }) });

describe('PATCH /auth/admin/permissions/:system (AC-27)', () => {
  it('saves a granted right with one history row, a bump and one alert', async () => {
    const { service, state, alerts, actor } = setup();
    const matrix = await service.update(actor, 'VRMS', {
      version: 3,
      changes: [{ role: 'MECHANIC', key: 'ticket.view', allowed: true }],
    });
    expect(matrix.version).toBe(4);
    expect(matrix.grants.MECHANIC).toEqual(['ticket.view']);
    expect(state.history).toEqual([
      expect.objectContaining({
        role: 'MECHANIC',
        key: 'ticket.view',
        before: false,
        after: true,
        actorId: 'a1',
      }),
    ]);
    expect(alerts.send).toHaveBeenCalledWith('a1', [
      expect.objectContaining({
        kind: 'PERMISSIONS_CHANGED',
        systems: ['VRMS'],
        cells: 1,
        targetId: null,
      }),
    ]);
  });

  it('answers 409 MATRIX_STALE when the version is not current, writing nothing', async () => {
    const { service, state, actor } = setup();
    await expect(
      service.update(actor, 'VRMS', {
        version: 2,
        changes: [{ role: 'MECHANIC', key: 'ticket.view', allowed: true }],
      }),
    ).rejects.toEqual(code('MATRIX_STALE'));
    expect(state.history).toEqual([]);
  });

  it('refuses a locked cell, an unknown role and an unknown key', async () => {
    const { service, actor } = setup();
    const one = (role: string, key: string) =>
      service.update(actor, 'VRMS', {
        version: 3,
        changes: [{ role, key, allowed: false }],
        note: 'because of x',
      });
    await expect(one('ADMIN', 'team.manage')).rejects.toEqual(
      code('LOCKED_CELL'),
    );
    await expect(one('DRIVER', 'ticket.view')).rejects.toEqual(
      code('UNKNOWN_ROLE'),
    );
    await expect(one('ADMIN', 'ticket.fly')).rejects.toEqual(
      code('UNKNOWN_PERMISSION'),
    );
  });

  it('needs a note of 5 to 500 characters when a right is taken away', async () => {
    const { service, actor } = setup();
    const take = (note?: string) =>
      service.update(actor, 'VRMS', {
        version: 3,
        changes: [
          { role: 'CHIEF_MECHANIC', key: 'ticket.view', allowed: false },
        ],
        note,
      });
    await expect(take()).rejects.toEqual(code('NOTE_REQUIRED'));
    await expect(take('meh')).rejects.toEqual(code('NOTE_REQUIRED'));
    await expect(take('Chiefs read the board only')).resolves.toMatchObject({
      version: 4,
    });
  });

  it('answers 200 with no bump, no row and no alert when nothing changes', async () => {
    const { service, state, alerts, actor } = setup();
    const matrix = await service.update(actor, 'VRMS', {
      version: 3,
      changes: [{ role: 'ADMIN', key: 'ticket.view', allowed: true }],
    });
    expect(matrix.version).toBe(3);
    expect(state.history).toEqual([]);
    expect(alerts.send).not.toHaveBeenCalled();
  });

  it('refuses an empty list and the same cell twice with 400 VALIDATION_FAILED', async () => {
    const { service, actor } = setup();
    await expect(
      service.update(actor, 'VRMS', { version: 3, changes: [] }),
    ).rejects.toEqual(code('VALIDATION_FAILED'));
    const cell = { role: 'MECHANIC', key: 'ticket.view', allowed: true };
    await expect(
      service.update(actor, 'VRMS', { version: 3, changes: [cell, cell] }),
    ).rejects.toEqual(code('VALIDATION_FAILED'));
  });
});
