import { describe, it, expect, jest } from '@jest/globals';
import { ConflictException, HttpException } from '@nestjs/common';
import { AccountEventType, SystemType, type Prisma } from '@prisma/client';
import {
  adminSystems,
  assertAnotherAdmin,
  change,
  roleChanges,
  rolesKey,
} from './user-changes';
import { decodeEventCursor, encodeEventCursor } from './events/event-cursor';

const ID = '3f2b8c1e-5a4d-4e6f-9a7b-1c2d3e4f5a6b';

/** Today's catalog: ADMIN is every system's admin role. */
const ADMINS = new Map([
  [SystemType.VRMS, 'ADMIN'],
  [SystemType.VMMS, 'ADMIN'],
  [SystemType.BMS, 'ADMIN'],
]);

describe('rolesKey', () => {
  // covers: AC-20
  it('sorts roles into a comma separated ROLE@SYSTEM list', () => {
    const key = rolesKey([
      { role: 'MECHANIC', system: SystemType.VRMS },
      { role: 'ADMIN', system: SystemType.VRMS },
      { role: 'ADMIN', system: SystemType.BMS },
    ]);

    expect(key).toBe('ADMIN@BMS,ADMIN@VRMS,MECHANIC@VRMS');
  });

  it('gives the same key whatever order the roles come in', () => {
    const a = { role: 'ADMIN', system: SystemType.VRMS };
    const b = { role: 'MECHANIC', system: SystemType.VRMS };

    expect(rolesKey([a, b])).toBe(rolesKey([b, a]));
  });

  it('returns an empty string when there are no roles', () => {
    expect(rolesKey([])).toBe('');
  });
});

describe('adminSystems', () => {
  it('lists only the systems where the user is ADMIN', () => {
    const systems = adminSystems(
      [
        { role: 'ADMIN', system: SystemType.VRMS },
        { role: 'MECHANIC', system: SystemType.VMMS },
        { role: 'ADMIN', system: SystemType.BMS },
      ],
      ADMINS,
    );

    expect(systems).toEqual([SystemType.BMS, SystemType.VRMS]);
  });

  it('sorts the systems whatever order the roles come in, so locks are always taken in one order', () => {
    const vrmsFirst = adminSystems(
      [
        { role: 'ADMIN', system: SystemType.VRMS },
        { role: 'ADMIN', system: SystemType.BMS },
      ],
      ADMINS,
    );
    const bmsFirst = adminSystems(
      [
        { role: 'ADMIN', system: SystemType.BMS },
        { role: 'ADMIN', system: SystemType.VRMS },
      ],
      ADMINS,
    );

    expect(vrmsFirst).toEqual(bmsFirst);
  });

  it('does not reorder the roles it was given', () => {
    const roles = [
      { role: 'ADMIN', system: SystemType.VRMS },
      { role: 'ADMIN', system: SystemType.BMS },
    ];

    adminSystems(roles, ADMINS);

    expect(roles.map((r) => r.system)).toEqual([
      SystemType.VRMS,
      SystemType.BMS,
    ]);
  });

  // covers: spec 0004 AC-14
  it('follows the catalog flag, not the ADMIN code', () => {
    const moved = new Map([[SystemType.VMMS, 'OPERATIONS']]);

    expect(
      adminSystems(
        [
          { role: 'ADMIN', system: SystemType.VMMS },
          { role: 'OPERATIONS', system: SystemType.VMMS },
        ],
        moved,
      ),
    ).toEqual([SystemType.VMMS]);
    expect(
      adminSystems([{ role: 'ADMIN', system: SystemType.VMMS }], moved),
    ).toEqual([]);
  });

  it('returns an empty list for a user with no admin role', () => {
    expect(
      adminSystems([{ role: 'MECHANIC', system: SystemType.VRMS }], ADMINS),
    ).toEqual([]);
  });
});

describe('change', () => {
  const actor = { id: 'admin-1', email: 'admin@welinc.com' };

  // covers: AC-20
  it('names the actor, never stores the email, and defaults the rest to null', () => {
    const row = change('user-1', actor, AccountEventType.CREATED);

    expect(row).toEqual({
      userId: 'user-1',
      actorId: 'admin-1',
      type: AccountEventType.CREATED,
      field: null,
      oldValue: null,
      newValue: null,
      reason: null,
      system: null,
      meta: undefined,
    });
  });

  it('keeps the field with its old and new value for an update', () => {
    const row = change('user-1', actor, AccountEventType.UPDATED, {
      field: 'name',
      oldValue: 'Ana',
      newValue: 'Anna',
    });

    expect(row).toMatchObject({
      field: 'name',
      oldValue: 'Ana',
      newValue: 'Anna',
    });
  });

  it('stores a null old value as null, not as the string "null"', () => {
    const row = change('user-1', actor, AccountEventType.UPDATED, {
      field: 'contact',
      oldValue: null,
      newValue: '0917',
    });

    expect(row.oldValue).toBeNull();
  });
});

// covers: spec 0011 AC-6 (one ROLE_CHANGED per system that changed)
describe('roleChanges', () => {
  const actor = { id: 'admin-1', email: 'admin@welinc.com' };
  const V = SystemType.VRMS;
  const B = SystemType.BMS;
  const M = SystemType.VMMS;

  it('writes one row per system that changed, only that system on each side', () => {
    const rows = roleChanges(
      'user-1',
      actor,
      [
        { role: 'MECHANIC', system: V },
        { role: 'ADMIN', system: B },
      ],
      [
        { role: 'CHIEF_MECHANIC', system: V },
        { role: 'ADMIN', system: B },
        { role: 'DRIVER', system: M },
      ],
    );
    expect(rows).toEqual([
      expect.objectContaining({
        type: AccountEventType.ROLE_CHANGED,
        system: M,
        field: 'roles',
        oldValue: null,
        newValue: 'DRIVER@VMMS',
      }),
      expect.objectContaining({
        system: V,
        oldValue: 'MECHANIC@VRMS',
        newValue: 'CHIEF_MECHANIC@VRMS',
      }),
    ]);
  });

  it('writes null for a system fully removed, and nothing when nothing changed', () => {
    const roles = [{ role: 'ADMIN', system: B }];
    expect(roleChanges('user-1', actor, roles, roles)).toEqual([]);
    expect(roleChanges('user-1', actor, roles, [])).toEqual([
      expect.objectContaining({
        system: B,
        oldValue: 'ADMIN@BMS',
        newValue: null,
      }),
    ]);
  });
});

describe('assertAnotherAdmin', () => {
  function fakeTx(otherAdmins: number) {
    const queryRaw = jest.fn(() => Promise.resolve([]));
    const count = jest.fn<(args: unknown) => Promise<number>>(() =>
      Promise.resolve(otherAdmins),
    );
    const tx = {
      $queryRaw: queryRaw,
      user: { count },
    } as unknown as Prisma.TransactionClient;
    return { tx, queryRaw, count };
  }

  // covers: AC-19
  it('throws 409 naming the system when no other admin is left', async () => {
    const { tx } = fakeTx(0);

    const run = assertAnotherAdmin(tx, ID, SystemType.VRMS);

    await expect(run).rejects.toBeInstanceOf(ConflictException);
    await expect(run).rejects.toThrow('This is the last VRMS admin.');
  });

  it('passes when at least one other admin is left', async () => {
    const { tx } = fakeTx(1);

    await expect(
      assertAnotherAdmin(tx, ID, SystemType.VRMS),
    ).resolves.toBeUndefined();
  });

  it('locks the admin role rows before it counts, so two admins cannot both pass', async () => {
    const order: string[] = [];
    const tx = {
      $queryRaw: jest.fn(() => {
        order.push('lock');
        return Promise.resolve([]);
      }),
      user: {
        count: jest.fn(() => {
          order.push('count');
          return Promise.resolve(1);
        }),
      },
    } as unknown as Prisma.TransactionClient;

    await assertAnotherAdmin(tx, ID, SystemType.VRMS);

    expect(order).toEqual(['lock', 'count']);
  });

  it('counts only other, active, non deleted admins of that system', async () => {
    const { tx, count } = fakeTx(1);

    await assertAnotherAdmin(tx, ID, SystemType.BMS);

    expect(count).toHaveBeenCalledWith({
      where: {
        id: { not: ID },
        isActive: true,
        deletedAt: null,
        roles: {
          some: { system: SystemType.BMS, systemRole: { isSystemAdmin: true } },
        },
      },
    });
  });
});

// covers: spec 0011 Query rules, AC-14 (INVALID_CURSOR)
describe('event cursor', () => {
  it('round trips a createdAt and id', () => {
    const row = { createdAt: new Date('2026-10-27T08:30:00.123Z'), id: ID };

    const decoded = decodeEventCursor(encodeEventCursor(row));

    expect(decoded.id).toBe(ID);
    expect(decoded.createdAt.toISOString()).toBe('2026-10-27T08:30:00.123Z');
  });

  it('is safe to put in a URL', () => {
    const cursor = encodeEventCursor({
      createdAt: new Date('2026-10-27T08:30:00.123Z'),
      id: ID,
    });

    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it.each([
    ['not base64 at all', '!!!'],
    ['an empty string', ''],
    [
      'a bad date',
      Buffer.from(`not-a-date|${ID}`, 'utf8').toString('base64url'),
    ],
    [
      'a bad id',
      Buffer.from('2026-10-27T08:30:00.000Z|not-a-uuid', 'utf8').toString(
        'base64url',
      ),
    ],
    [
      'a missing id',
      Buffer.from('2026-10-27T08:30:00.000Z', 'utf8').toString('base64url'),
    ],
  ])('rejects a tampered cursor: %s', (_label, cursor) => {
    const error = ((): unknown => {
      try {
        decodeEventCursor(cursor);
        return null;
      } catch (e: unknown) {
        return e;
      }
    })();
    expect(error).toBeInstanceOf(HttpException);
    expect((error as HttpException).getResponse()).toMatchObject({
      statusCode: 400,
      code: 'INVALID_CURSOR',
    });
  });
});
