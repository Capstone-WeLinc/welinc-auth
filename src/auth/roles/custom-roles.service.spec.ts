/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-return, @typescript-eslint/require-await -- the faked database is untyped on purpose */
import { describe, it, expect, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import { Prisma, RoleEventKind, SystemType } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import { CustomRolesService } from './custom-roles.service';
import type { RolesAdminService } from './roles-admin.service';

// Suite spec 0018, child 0002: create, rename and delete custom roles, on a faked database.
// covers: AC-22 (names, limit), AC-23 (copy and log), AC-24 (rename, describe),
// AC-25 (delete and holders), AC-26 (built in refusals), AC-27 (VMMS refusal)

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const ACTOR = {
  id: 'u-actor',
  name: 'Leonora Castillo',
  email: 'suite@welinc.com',
};
const VRMS = SystemType.VRMS;

type RoleRow = {
  code: string;
  name: string;
  isBuiltIn: boolean;
  deletedAt: Date | null;
};

const built = (code: string, name: string): RoleRow => ({
  code,
  name,
  isBuiltIn: true,
  deletedAt: null,
});
const custom = (
  code: string,
  name: string,
  deletedAt: Date | null = null,
): RoleRow => ({ code, name, isBuiltIn: false, deletedAt });

const BUILT_INS = [
  built('ADMIN', 'Admin'),
  built('CHIEF_MECHANIC', 'Chief Mechanic'),
  built('MECHANIC', 'Mechanic'),
];

function build(opts: {
  roles?: RoleRow[];
  /** The row `FOR UPDATE` finds for the role being read or changed; null means none. */
  locked?: { name: string; description: string; is_built_in: boolean } | null;
  keys?: string[];
  saved?: { key: string; allowed: boolean }[];
  holders?: number;
  hasSystem?: boolean;
}) {
  const db = {
    systemPermission: { findMany: fn() },
    systemRole: { findMany: fn(), create: fn(), update: fn() },
    rolePermission: { findMany: fn(), createMany: fn(), deleteMany: fn() },
    permissionChange: { createMany: fn() },
    roleEvent: { create: fn(), createMany: fn() },
    userRoleAssignment: { count: fn() },
    $queryRaw: fn(),
    $transaction: fn(),
  };
  let version = 7;
  db.$transaction.mockImplementation(async (cb: any) => cb(db));
  db.$queryRaw.mockImplementation(async (sql: Prisma.Sql) => {
    const text = sql.sql;
    if (text.includes('FROM "systems"')) {
      return opts.hasSystem === false ? [] : [{ code: VRMS }];
    }
    if (text.includes('INSERT INTO "permission_matrices"')) {
      version += 1;
      return [{ version }];
    }
    if (text.includes('FROM "permission_matrices"')) return [{ version }];
    if (text.includes('FROM "system_roles"')) {
      // create reads {code, name}; update and remove read {name, description, is_built_in}
      if (opts.locked === null) return [];
      if (text.includes('"is_built_in"')) {
        return [
          opts.locked ?? { name: 'Tire', description: '', is_built_in: false },
        ];
      }
      const source = (opts.roles ?? BUILT_INS).find(
        (r) => r.code === sql.values[1],
      );
      return source && !source.deletedAt
        ? [{ code: source.code, name: source.name }]
        : [];
    }
    return [];
  });
  db.systemPermission.findMany.mockResolvedValue(
    (opts.keys ?? ['ticket.view', 'ticket.work', 'ai.use']).map((key) => ({
      key,
    })),
  );
  db.systemRole.findMany.mockResolvedValue(opts.roles ?? BUILT_INS);
  db.rolePermission.findMany.mockResolvedValue(opts.saved ?? []);
  db.userRoleAssignment.count.mockResolvedValue(opts.holders ?? 0);

  const roles = { page: fn() };
  // The page read answers whatever role the create (or the test) just wrote
  roles.page.mockImplementation(async () => {
    const made = db.systemRole.create.mock.calls.at(-1)?.[0]?.data;
    const codes: string[] = made ? [made.code] : ['C_TIRE'];
    return {
      roles: codes.map((code) => ({ code, name: made?.name ?? 'Tire' })),
      cells: Object.fromEntries(codes.map((c) => [c, ['ticket.view']])),
    };
  });
  const service = new CustomRolesService(
    db as unknown as PrismaService,
    roles as unknown as RolesAdminService,
  );
  return { service, db, roles };
}

async function failure(promise: Promise<unknown>) {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(HttpException);
    const e = error as HttpException;
    return { status: e.getStatus(), body: e.getResponse() as any };
  }
  throw new Error('expected the call to fail');
}

describe('create', () => {
  it("copies the source's saved cells, with a missing key off, and logs one change per cell (AC-23)", async () => {
    const { service, db } = build({
      saved: [
        { key: 'ticket.view', allowed: true },
        { key: 'ticket.work', allowed: false },
      ],
    });
    const created = await service.create(ACTOR, VRMS, {
      name: '  Tire specialist ',
      from: 'MECHANIC',
    });

    expect(db.systemRole.create.mock.calls[0][0].data).toMatchObject({
      system: VRMS,
      code: 'C_TIRE_SPECIALIST',
      name: 'Tire specialist',
      isBuiltIn: false,
      isSystemAdmin: false,
      copiedFrom: 'MECHANIC',
      createdById: ACTOR.id,
    });
    const cells = db.rolePermission.createMany.mock.calls[0][0].data;
    expect(cells.map((c: any) => [c.key, c.allowed])).toEqual([
      ['ticket.view', true],
      ['ticket.work', false],
      ['ai.use', false],
    ]);
    const changes = db.permissionChange.createMany.mock.calls[0][0].data;
    expect(changes).toHaveLength(3);
    expect(changes[0]).toMatchObject({
      role: 'C_TIRE_SPECIALIST',
      before: null,
      after: true,
      note: 'Created from Mechanic',
      actorId: ACTOR.id,
    });
    expect(db.roleEvent.create.mock.calls[0][0].data).toMatchObject({
      kind: RoleEventKind.CREATED,
      fromValue: 'Mechanic',
      toValue: 'Tire specialist',
    });
    expect(created.version).toBe(8);
    expect(created.cells).toEqual(['ticket.view']);
    expect(created.role.code).toBe('C_TIRE_SPECIALIST');
  });

  it('refuses a system with no permission keys (AC-27)', async () => {
    const { service, db } = build({ keys: [] });
    const e = await failure(
      service.create(ACTOR, SystemType.VMMS, {
        name: 'Tire',
        from: 'MECHANIC',
      }),
    );
    expect(e.status).toBe(409);
    expect(e.body.code).toBe('CUSTOM_ROLES_NOT_SUPPORTED');
    expect(db.systemRole.create).not.toHaveBeenCalled();
  });

  it('answers 404 for a system the catalog never synced', async () => {
    const { service } = build({ hasSystem: false });
    const e = await failure(
      service.create(ACTOR, VRMS, { name: 'Tire', from: 'MECHANIC' }),
    );
    expect(e.status).toBe(404);
  });

  it('refuses a source role that does not exist or is archived with UNKNOWN_ROLE', async () => {
    const { service } = build({
      roles: [...BUILT_INS, custom('C_OLD', 'Old', new Date())],
    });
    for (const from of ['NOPE', 'C_OLD']) {
      const e = await failure(
        service.create(ACTOR, VRMS, { name: 'Tire', from }),
      );
      expect(e.status).toBe(400);
      expect(e.body.code).toBe('UNKNOWN_ROLE');
    }
  });

  it('refuses bad names with the message the page shows (AC-22)', async () => {
    const { service, db } = build({});
    const short = await failure(
      service.create(ACTOR, VRMS, { name: 'A', from: 'MECHANIC' }),
    );
    expect(short.body.code).toBe('VALIDATION_FAILED');
    expect(short.body.message).toBe('Name needs 2 to 40 characters.');
    const symbols = await failure(
      service.create(ACTOR, VRMS, { name: '!!', from: 'MECHANIC' }),
    );
    expect(symbols.body.message).toBe('Use letters or numbers in the name.');
    const long = await failure(
      service.create(ACTOR, VRMS, { name: 'x'.repeat(41), from: 'MECHANIC' }),
    );
    expect(long.body.message).toBe('Name needs 2 to 40 characters.');
    expect(db.systemRole.create).not.toHaveBeenCalled();
  });

  it('refuses a description over 200 characters', async () => {
    const { service } = build({});
    const e = await failure(
      service.create(ACTOR, VRMS, {
        name: 'Tire',
        description: 'x'.repeat(201),
        from: 'MECHANIC',
      }),
    );
    expect(e.body.code).toBe('VALIDATION_FAILED');
  });

  it('treats a name as taken whatever its case, built in or custom, but not an archived one (AC-22)', async () => {
    const roles = [
      ...BUILT_INS,
      custom('C_TIRE', 'Tire'),
      custom('C_GONE', 'Gone', new Date()),
    ];
    for (const name of ['chief MECHANIC', 'tire']) {
      const { service } = build({ roles });
      const e = await failure(
        service.create(ACTOR, VRMS, { name, from: 'MECHANIC' }),
      );
      expect(e.status).toBe(409);
      expect(e.body.code).toBe('ROLE_NAME_TAKEN');
      expect(e.body.message).toBe(
        `There's already a role called ${name} in VRMS.`,
      );
    }
    const { service, db } = build({ roles });
    await service.create(ACTOR, VRMS, { name: 'Gone', from: 'MECHANIC' });
    expect(db.systemRole.create.mock.calls[0][0].data.code).toBe('C_GONE_2');
  });

  it('refuses the 21st live custom role and does not count archived ones (AC-22)', async () => {
    const live = Array.from({ length: 20 }, (_, i) =>
      custom(`C_R${i}`, `Role ${i}`),
    );
    const full = build({ roles: [...BUILT_INS, ...live] });
    const e = await failure(
      full.service.create(ACTOR, VRMS, {
        name: 'One too many',
        from: 'MECHANIC',
      }),
    );
    expect(e.status).toBe(409);
    expect(e.body.code).toBe('CUSTOM_ROLE_LIMIT');
    expect(e.body.message).toBe(
      'VRMS has 20 custom roles, the most it can have. Delete one to make another.',
    );

    const archived = Array.from({ length: 19 }, (_, i) =>
      custom(`C_R${i}`, `Role ${i}`),
    );
    const room = build({
      roles: [...BUILT_INS, ...archived, custom('C_X', 'X', new Date())],
    });
    await expect(
      room.service.create(ACTOR, VRMS, { name: 'Fits', from: 'MECHANIC' }),
    ).resolves.toBeDefined();
  });

  it('never reuses a code an archived role had (AC-22)', async () => {
    const { service, db } = build({
      roles: [
        ...BUILT_INS,
        custom('C_TIRE_SPECIALIST', 'Tyre specialist', new Date()),
      ],
    });
    await service.create(ACTOR, VRMS, {
      name: 'Tire specialist',
      from: 'MECHANIC',
    });
    expect(db.systemRole.create.mock.calls[0][0].data.code).toBe(
      'C_TIRE_SPECIALIST_2',
    );
  });

  it('turns the partial unique index into ROLE_NAME_TAKEN if two creates race', async () => {
    const { service, db } = build({});
    db.systemRole.create.mockRejectedValue(
      new Prisma.PrismaClientKnownRequestError('unique', {
        code: 'P2002',
        clientVersion: 'test',
      }),
    );
    const e = await failure(
      service.create(ACTOR, VRMS, { name: 'Tire', from: 'MECHANIC' }),
    );
    expect(e.status).toBe(409);
    expect(e.body.code).toBe('ROLE_NAME_TAKEN');
  });

  it('locks the system before reading the limit, so two creates cannot both pass', async () => {
    const { service, db } = build({});
    await service.create(ACTOR, VRMS, { name: 'Tire', from: 'MECHANIC' });
    const first = (db.$queryRaw.mock.calls[0][0] as Prisma.Sql).sql;
    expect(first).toContain('FROM "systems"');
    expect(first).toContain('FOR UPDATE');
  });
});

describe('update', () => {
  const live = [...BUILT_INS, custom('C_TIRE', 'Tire')];

  it('asks for a name or a description', async () => {
    const { service } = build({});
    const e = await failure(service.update(ACTOR, VRMS, 'C_TIRE', {}));
    expect(e.status).toBe(400);
    expect(e.body.code).toBe('VALIDATION_FAILED');
  });

  it('refuses a built in role (AC-26)', async () => {
    const { service, db } = build({
      locked: { name: 'Mechanic', description: '', is_built_in: true },
    });
    const e = await failure(
      service.update(ACTOR, VRMS, 'MECHANIC', { name: 'Zed' }),
    );
    expect(e.status).toBe(400);
    expect(e.body.code).toBe('BUILT_IN_ROLE');
    expect(db.systemRole.update).not.toHaveBeenCalled();
  });

  it('answers 404 for a role that never existed or is archived', async () => {
    const { service } = build({ locked: null });
    const e = await failure(
      service.update(ACTOR, VRMS, 'C_NOPE', { name: 'Zed' }),
    );
    expect(e.status).toBe(404);
  });

  it('renames and records RENAMED, leaving the code alone (AC-24)', async () => {
    const { service, db } = build({ roles: live });
    await service.update(ACTOR, VRMS, 'C_TIRE', { name: 'Tyre specialist' });
    expect(db.systemRole.update.mock.calls[0][0]).toMatchObject({
      where: { system_code: { system: VRMS, code: 'C_TIRE' } },
      data: { name: 'Tyre specialist' },
    });
    const events = db.roleEvent.createMany.mock.calls[0][0].data;
    expect(events).toEqual([
      expect.objectContaining({
        kind: RoleEventKind.RENAMED,
        fromValue: 'Tire',
        toValue: 'Tyre specialist',
      }),
    ]);
  });

  it('checks the new name against every other live role but not itself', async () => {
    const { service, db } = build({});
    db.systemRole.findMany.mockResolvedValue([
      { name: 'Mechanic' },
      { name: 'Brakes' },
    ]);
    const taken = await failure(
      service.update(ACTOR, VRMS, 'C_TIRE', { name: 'mechanic' }),
    );
    expect(taken.body.code).toBe('ROLE_NAME_TAKEN');
    expect(db.systemRole.findMany.mock.calls[0][0].where).toMatchObject({
      NOT: { code: 'C_TIRE' },
      deletedAt: null,
    });
  });

  it('records DESCRIBED with null for an emptied description, and nothing when nothing changed', async () => {
    const { service, db } = build({
      locked: { name: 'Tire', description: 'Wheels', is_built_in: false },
    });
    await service.update(ACTOR, VRMS, 'C_TIRE', { description: '' });
    expect(db.roleEvent.createMany.mock.calls[0][0].data[0]).toMatchObject({
      kind: RoleEventKind.DESCRIBED,
      fromValue: 'Wheels',
      toValue: null,
    });

    db.systemRole.update.mockClear();
    db.roleEvent.createMany.mockClear();
    await service.update(ACTOR, VRMS, 'C_TIRE', {
      name: 'Tire',
      description: 'Wheels',
    });
    expect(db.systemRole.update).not.toHaveBeenCalled();
    expect(db.roleEvent.createMany).not.toHaveBeenCalled();
  });
});

describe('remove', () => {
  it('refuses a built in role (AC-26)', async () => {
    const { service, db } = build({
      locked: { name: 'Mechanic', description: '', is_built_in: true },
    });
    const e = await failure(service.remove(ACTOR, VRMS, 'MECHANIC'));
    expect(e.status).toBe(400);
    expect(e.body.code).toBe('BUILT_IN_ROLE');
    expect(db.systemRole.update).not.toHaveBeenCalled();
  });

  it('answers 404 for an unknown or already archived role', async () => {
    const { service } = build({ locked: null });
    const e = await failure(service.remove(ACTOR, VRMS, 'C_TIRE'));
    expect(e.status).toBe(404);
  });

  it('refuses with the holder count while people still have it (AC-25)', async () => {
    for (const [holders, text] of [
      [1, '1 person still has Tire. Give them another role first.'],
      [2, '2 people still have Tire. Give them another role first.'],
    ] as const) {
      const { service, db } = build({
        holders,
        locked: { name: 'Tire', description: '', is_built_in: false },
      });
      const e = await failure(service.remove(ACTOR, VRMS, 'C_TIRE'));
      expect(e.status).toBe(409);
      expect(e.body.code).toBe('ROLE_IN_USE');
      expect(e.body.message).toBe(text);
      expect(e.body.details).toEqual({ count: holders });
      expect(db.rolePermission.deleteMany).not.toHaveBeenCalled();
      expect(db.systemRole.update).not.toHaveBeenCalled();
    }
  });

  it('counts people who are not deleted and rows still live, so grace period holders do not block (AC-25)', async () => {
    const { service, db } = build({
      locked: { name: 'Tire', description: '', is_built_in: false },
    });
    await service.remove(ACTOR, VRMS, 'C_TIRE');
    const where = db.userRoleAssignment.count.mock.calls[0][0].where;
    expect(where).toMatchObject({
      system: VRMS,
      role: 'C_TIRE',
      user: { deletedAt: null },
    });
    expect(where.OR).toBeDefined();
  });

  it('archives it, removes and logs every cell with after null, and raises the version (AC-25)', async () => {
    const { service, db } = build({
      locked: { name: 'Tire', description: '', is_built_in: false },
      saved: [
        { key: 'ticket.view', allowed: true },
        { key: 'ticket.work', allowed: false },
      ],
    });
    const result = await service.remove(ACTOR, VRMS, 'C_TIRE');

    expect(db.rolePermission.deleteMany).toHaveBeenCalledWith({
      where: { system: VRMS, role: 'C_TIRE' },
    });
    const changes = db.permissionChange.createMany.mock.calls[0][0].data;
    expect(changes).toEqual([
      expect.objectContaining({
        key: 'ticket.view',
        before: true,
        after: null,
      }),
      expect.objectContaining({
        key: 'ticket.work',
        before: false,
        after: null,
      }),
    ]);
    expect(db.roleEvent.create.mock.calls[0][0].data).toMatchObject({
      kind: RoleEventKind.DELETED,
      fromValue: 'Tire',
    });
    const archive = db.systemRole.update.mock.calls[0][0];
    expect(archive.where).toEqual({
      system_code: { system: VRMS, code: 'C_TIRE' },
    });
    expect(archive.data.deletedAt).toBeInstanceOf(Date);
    expect(result).toEqual({ version: 8 });
  });

  it('skips the cell log for a role with no cells', async () => {
    const { service, db } = build({
      locked: { name: 'Tire', description: '', is_built_in: false },
      saved: [],
    });
    await service.remove(ACTOR, VRMS, 'C_TIRE');
    expect(db.permissionChange.createMany).not.toHaveBeenCalled();
  });
});
