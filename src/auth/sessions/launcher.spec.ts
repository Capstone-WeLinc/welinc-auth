import { describe, it, expect, jest } from '@jest/globals';
import { HttpException, Logger } from '@nestjs/common';
import { ClientKind, SystemType } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import {
  LAUNCHER_ORDER,
  LauncherService,
  buildLauncherSystems,
  buildSystemRoles,
  launcherOrder,
  webSystemCodes,
  webSystemsFor,
  withCutoffs,
  type LauncherClientRow,
} from './launcher';

// covers: spec 0007 AC-1, AC-2 (the launcher answer), AC-6 (launcher order)

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const CATALOG = [
  {
    code: SystemType.VRMS,
    name: 'Vehicle Repair Management System',
    description: 'Repair tickets, mechanics and workshop work',
    roles: [
      { code: 'MECHANIC', name: 'Mechanic', sortOrder: 2 },
      { code: 'ADMIN', name: 'Admin', sortOrder: 0 },
      { code: 'CHIEF_MECHANIC', name: 'Chief Mechanic', sortOrder: 1 },
    ],
  },
  {
    code: SystemType.BMS,
    name: 'Booking Management System',
    description: 'Bookings, dispatch and trips',
    roles: [
      { code: 'OPERATIONS', name: 'Operations', sortOrder: 1 },
      { code: 'DRIVER', name: 'Driver', sortOrder: 1 },
    ],
  },
  {
    code: SystemType.VMMS,
    name: 'Vehicle Maintenance Management System',
    description: 'Vehicles, maintenance and fleet upkeep',
    roles: [{ code: 'OPERATIONS', name: 'Operations', sortOrder: 2 }],
  },
];

const client = (
  system: SystemType,
  webAddress: string | null,
  at = 0,
  extra: Partial<LauncherClientRow> = {},
): LauncherClientRow => ({
  id: system.toLowerCase(),
  kind: ClientKind.CONFIDENTIAL,
  system,
  webAddress,
  allowedRoles: {},
  appReleased: false,
  createdAt: new Date(at),
  ...extra,
});

/** A phone app client (suite spec 0014). */
const app = (
  id: string,
  system: SystemType,
  allowedRoles: Record<string, string[]>,
  appReleased: boolean,
): LauncherClientRow => ({
  id,
  kind: ClientKind.PUBLIC_NATIVE,
  system,
  webAddress: null,
  allowedRoles,
  appReleased,
  createdAt: new Date(0),
});

describe('launcherOrder', () => {
  it('is BMS, VMMS, VRMS, distinct', () => {
    expect(LAUNCHER_ORDER).toEqual(['BMS', 'VMMS', 'VRMS']);
    expect(
      launcherOrder([
        { system: SystemType.VRMS },
        { system: SystemType.BMS },
        { system: SystemType.VRMS },
      ]),
    ).toEqual(['BMS', 'VRMS']);
    expect(launcherOrder([])).toEqual([]);
  });
});

describe('buildLauncherSystems', () => {
  const clients = [
    client(SystemType.VRMS, 'http://localhost:8001'),
    client(SystemType.VMMS, 'http://localhost:8002'),
    client(SystemType.BMS, 'http://localhost:8003'),
  ];

  it('builds a card per held system in launcher order, roles in catalog order with ties by code', () => {
    const { systems, missing } = buildLauncherSystems(
      [
        { system: SystemType.VRMS, role: 'CHIEF_MECHANIC' },
        { system: SystemType.VMMS, role: 'OPERATIONS' },
        { system: SystemType.BMS, role: 'OPERATIONS' },
        { system: SystemType.BMS, role: 'DRIVER' },
      ],
      CATALOG,
      clients,
    );
    expect(missing).toEqual([]);
    expect(systems).toEqual([
      {
        system: 'BMS',
        name: 'Booking Management System',
        description: 'Bookings, dispatch and trips',
        url: 'http://localhost:8003',
        roles: [
          { code: 'DRIVER', name: 'Driver' },
          { code: 'OPERATIONS', name: 'Operations' },
        ],
      },
      {
        system: 'VMMS',
        name: 'Vehicle Maintenance Management System',
        description: 'Vehicles, maintenance and fleet upkeep',
        url: 'http://localhost:8002',
        roles: [{ code: 'OPERATIONS', name: 'Operations' }],
      },
      {
        system: 'VRMS',
        name: 'Vehicle Repair Management System',
        description: 'Repair tickets, mechanics and workshop work',
        url: 'http://localhost:8001',
        roles: [{ code: 'CHIEF_MECHANIC', name: 'Chief Mechanic' }],
      },
    ]);
  });

  it('leaves out a held system with no usable client and names it', () => {
    const { systems, missing } = buildLauncherSystems(
      [
        { system: SystemType.VRMS, role: 'MECHANIC' },
        { system: SystemType.BMS, role: 'OPERATIONS' },
      ],
      CATALOG,
      [
        client(SystemType.VRMS, 'http://localhost:8001'),
        client(SystemType.BMS, null),
      ],
    );
    expect(systems.map((s) => s.system)).toEqual(['VRMS']);
    expect(missing).toEqual(['BMS']);
  });

  it('uses the oldest client when two match, and reports the duplicate', () => {
    const { systems, duplicates } = buildLauncherSystems(
      [{ system: SystemType.VRMS, role: 'MECHANIC' }],
      CATALOG,
      [
        client(SystemType.VRMS, 'http://new.test', 2000),
        client(SystemType.VRMS, 'http://old.test', 1000),
      ],
    );
    expect(systems[0].url).toBe('http://old.test');
    expect(duplicates).toEqual(['VRMS']);
  });

  it('returns the address exactly as stored', () => {
    const { systems } = buildLauncherSystems(
      [{ system: SystemType.VRMS, role: 'MECHANIC' }],
      CATALOG,
      [client(SystemType.VRMS, 'http://localhost:8001/')],
    );
    expect(systems[0].url).toBe('http://localhost:8001/');
  });
});

describe('LauncherService.systemsFor', () => {
  const USER = {
    id: 'u1',
    name: 'Mara Lead',
    email: 'multi.lead@welinc.com',
    profilePicture: '/uploads/u1.png',
  };

  function build(
    held: { system: SystemType; role: string }[],
    clients: LauncherClientRow[],
    suiteAdmin = false,
  ) {
    const db = {
      suiteAdmin: {
        findUnique: fn().mockResolvedValue(
          suiteAdmin ? { userId: 'u1' } : null,
        ),
      },
      userRoleAssignment: { findMany: fn().mockResolvedValue(held) },
      system: {
        findMany: fn().mockImplementation(
          (args: { where: { code: { in: string[] } } }) =>
            Promise.resolve(
              CATALOG.filter((c) => args.where.code.in.includes(c.code)),
            ),
        ),
      },
      oAuthClient: { findMany: fn().mockResolvedValue(clients) },
    };
    return {
      service: new LauncherService(db as unknown as PrismaService),
      db,
    };
  }

  async function status(promise: Promise<unknown>) {
    const error = await promise.then(
      () => null,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(HttpException);
    const http = error as HttpException;
    return [http.getStatus(), (http.getResponse() as { code: string }).code];
  }

  it('answers the user with picture and the cards, asking only for active confidential clients', async () => {
    const { service, db } = build(
      [{ system: SystemType.VRMS, role: 'MECHANIC' }],
      [client(SystemType.VRMS, 'http://localhost:8001')],
    );
    const answer = await service.systemsFor(USER);
    expect(answer.user).toEqual({
      id: 'u1',
      name: 'Mara Lead',
      email: 'multi.lead@welinc.com',
      picture: '/uploads/u1.png',
    });
    expect(answer.systems).toHaveLength(1);
    expect(db.oAuthClient.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          isActive: true,
          OR: expect.arrayContaining([
            expect.objectContaining({ kind: ClientKind.CONFIDENTIAL }),
          ]),
        }),
      }),
    );
  });

  // covers: suite spec 0013 AC-5 (a suite admin holds no system by design)
  it('answers a suite admin with no role an empty list, not 403', async () => {
    const { service, db } = build([], [], true);
    const answer = await service.systemsFor(USER);
    expect(answer.systems).toEqual([]);
    expect(answer.suiteAdmin).toBe(true);
    expect(answer.user.email).toBe('multi.lead@welinc.com');
    expect(db.suiteAdmin.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: 'u1' } }),
    );
  });

  // covers: suite spec 0019 AC-5, AC-6 (a suite admin whose only role is temporary, not ADMIN)
  it('says suiteAdmin for a suite admin who also holds a system role', async () => {
    const { service } = build(
      [{ system: SystemType.VRMS, role: 'MECHANIC' }],
      [client(SystemType.VRMS, 'http://localhost:8001')],
      true,
    );
    const answer = await service.systemsFor(USER);
    expect(answer.systems).toHaveLength(1);
    expect(answer.suiteAdmin).toBe(true);
  });

  // covers: suite spec 0019 AC-6 (the field is always sent)
  it('says suiteAdmin false for everyone else', async () => {
    const { service } = build(
      [{ system: SystemType.VRMS, role: 'MECHANIC' }],
      [client(SystemType.VRMS, 'http://localhost:8001')],
    );
    expect((await service.systemsFor(USER)).suiteAdmin).toBe(false);
  });

  it('answers 403 NO_SYSTEM_ACCESS for no role at all, without reading clients', async () => {
    const { service, db } = build([], []);
    expect(await status(service.systemsFor(USER))).toEqual([
      403,
      'NO_SYSTEM_ACCESS',
    ]);
    expect(db.oAuthClient.findMany).not.toHaveBeenCalled();
    const body = await service
      .systemsFor(USER)
      .catch((e: HttpException) => e.getResponse() as Record<string, unknown>);
    expect(body).toMatchObject({
      statusCode: 403,
      code: 'NO_SYSTEM_ACCESS',
      user: { email: 'multi.lead@welinc.com' },
    });
  });

  it('answers 403 when every held system lacks a client, and warns naming the system, never the email', async () => {
    const warn = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => {});
    const { service } = build(
      [{ system: SystemType.BMS, role: 'OPERATIONS' }],
      [],
    );
    expect(await status(service.systemsFor(USER))).toEqual([
      403,
      'NO_SYSTEM_ACCESS',
    ]);
    expect(warn).toHaveBeenCalledTimes(1);
    const line = String(warn.mock.calls[0][0]);
    expect(line).toContain('BMS');
    expect(line).not.toContain('multi.lead');
    warn.mockRestore();
  });
});

// covers: suite spec 0014 AC-4, AC-5 (web vs phone only systems)
describe('spec 0014 the web and phone split', () => {
  const VMMS_CATALOG = {
    code: SystemType.VMMS,
    name: 'Vehicle Maintenance Management System',
    description: 'Vehicles, maintenance and fleet upkeep',
    roles: [
      { code: 'ADMIN', name: 'Admin', sortOrder: 0 },
      { code: 'OPERATIONS', name: 'Operations', sortOrder: 1 },
      { code: 'MECHANIC', name: 'Mechanic', sortOrder: 3 },
    ],
  };
  const BMS_CATALOG = {
    code: SystemType.BMS,
    name: 'Booking Management System',
    description: 'Bookings, dispatch and trips',
    roles: [
      { code: 'OPERATIONS', name: 'Operations', sortOrder: 1 },
      { code: 'DRIVER', name: 'Driver', sortOrder: 3 },
    ],
  };
  const catalog = [CATALOG[0], BMS_CATALOG, VMMS_CATALOG];
  const clients = [
    client(SystemType.VRMS, 'http://localhost:8001'),
    client(SystemType.VMMS, 'http://localhost:8002', 0, {
      allowedRoles: { VMMS: ['ADMIN', 'OPERATIONS'] },
    }),
    client(SystemType.BMS, 'http://localhost:8003', 0, {
      allowedRoles: { BMS: ['ADMIN', 'CUSTOMER_SUPPORT', 'OPERATIONS'] },
    }),
    app('vmms-mobile', SystemType.VMMS, { VMMS: ['MECHANIC'] }, true),
    app('bms-mobile', SystemType.BMS, { BMS: ['DRIVER', 'HELPER'] }, false),
  ];

  it('puts a mechanic VMMS in mobileSystems with the app and its release flag', () => {
    const { systems, mobileSystems } = buildLauncherSystems(
      [
        { system: SystemType.VRMS, role: 'MECHANIC' },
        { system: SystemType.VMMS, role: 'MECHANIC' },
      ],
      catalog,
      clients,
    );
    expect(systems.map((s) => s.system)).toEqual(['VRMS']);
    expect(mobileSystems).toEqual([
      {
        system: 'VMMS',
        name: 'Vehicle Maintenance Management System',
        description: 'Vehicles, maintenance and fleet upkeep',
        roles: [{ code: 'MECHANIC', name: 'Mechanic' }],
        app: { clientId: 'vmms-mobile', released: true },
      },
    ]);
  });

  it('keeps a system on the web when one of several roles passes the web client', () => {
    const { systems, mobileSystems } = buildLauncherSystems(
      [
        { system: SystemType.BMS, role: 'DRIVER' },
        { system: SystemType.BMS, role: 'OPERATIONS' },
      ],
      catalog,
      clients,
    );
    expect(systems.map((s) => s.system)).toEqual(['BMS']);
    expect(systems[0].roles.map((r) => r.code)).toEqual([
      'OPERATIONS',
      'DRIVER',
    ]);
    expect(mobileSystems).toEqual([]);
  });

  it('keeps launcher order in mobileSystems and leaves out a role no client admits', () => {
    const { systems, mobileSystems } = buildLauncherSystems(
      [
        { system: SystemType.VMMS, role: 'MECHANIC' },
        { system: SystemType.BMS, role: 'DRIVER' },
      ],
      catalog,
      clients,
    );
    expect(systems).toEqual([]);
    expect(mobileSystems.map((m) => [m.system, m.app.released])).toEqual([
      ['BMS', false],
      ['VMMS', true],
    ]);

    const none = buildLauncherSystems(
      [{ system: SystemType.VMMS, role: 'CHIEF_MECHANIC' }],
      [
        {
          ...VMMS_CATALOG,
          roles: [{ code: 'CHIEF_MECHANIC', name: 'Chief', sortOrder: 2 }],
        },
      ],
      clients,
    );
    expect(none.systems).toEqual([]);
    expect(none.mobileSystems).toEqual([]);
  });

  it('a system left out of allowedRoles lets every role through on the web', () => {
    expect(
      webSystemCodes([{ system: SystemType.VRMS, role: 'MECHANIC' }], clients),
    ).toEqual(['VRMS']);
  });

  it('webSystemsFor lists only web openable systems for user.systems', async () => {
    const db = { oAuthClient: { findMany: fn().mockResolvedValue(clients) } };
    expect(
      await webSystemsFor(db as unknown as PrismaService, [
        { system: SystemType.VRMS, role: 'MECHANIC' },
        { system: SystemType.VMMS, role: 'MECHANIC' },
        { system: SystemType.BMS, role: 'OPERATIONS' },
      ]),
    ).toEqual(['BMS', 'VRMS']);
    expect(await webSystemsFor(db as unknown as PrismaService, [])).toEqual([]);
  });

  function service(
    held: { system: SystemType; role: string }[],
    suiteAdmin = false,
  ) {
    const db = {
      suiteAdmin: {
        findUnique: fn().mockResolvedValue(
          suiteAdmin ? { userId: 'u1' } : null,
        ),
      },
      userRoleAssignment: { findMany: fn().mockResolvedValue(held) },
      system: { findMany: fn().mockResolvedValue(catalog) },
      oAuthClient: { findMany: fn().mockResolvedValue(clients) },
    };
    return new LauncherService(db as unknown as PrismaService);
  }
  const USER = {
    id: 'u1',
    name: 'Vic Mech',
    email: 'vmms.mech@welinc.com',
    profilePicture: null,
  };

  it('answers a phone only person 200 with systems empty, never 403', async () => {
    const answer = await service([
      { system: SystemType.VMMS, role: 'MECHANIC' },
    ]).systemsFor(USER);
    expect(answer.systems).toEqual([]);
    expect(answer.mobileSystems.map((m) => m.system)).toEqual(['VMMS']);
  });

  it('answers 403 when the roles pass neither a web nor a phone client', async () => {
    const error = await service([
      { system: SystemType.VMMS, role: 'CHIEF_MECHANIC' },
    ])
      .systemsFor(USER)
      .catch((e: HttpException) => e);
    expect((error as HttpException).getStatus()).toBe(403);
  });

  it('always sends mobileSystems, empty when there is none', async () => {
    const answer = await service([
      { system: SystemType.VRMS, role: 'MECHANIC' },
    ]).systemsFor(USER);
    expect(answer.mobileSystems).toEqual([]);
    const admin = await service([], true).systemsFor(USER);
    expect(admin).toMatchObject({ systems: [], mobileSystems: [] });
  });

  // covers: suite spec 0016 AC-12a (a suite admin's empty answer carries the cutoffs too)
  it("adds the session's cutoffs to a suite admin's empty answer", async () => {
    const admin = await service([], true).answerFor(USER, {
      endedAt: null,
      idleExpiresAt: new Date('2026-11-23T10:30:00.000Z'),
      absoluteExpiresAt: new Date('2026-11-23T22:00:00.000Z'),
    });
    expect(admin).toMatchObject({
      systems: [],
      sessionExpiresAt: '2026-11-23T10:30:00.000Z',
      sessionAbsoluteExpiresAt: '2026-11-23T22:00:00.000Z',
    });
    expect(Date.parse(admin.serverTime)).not.toBeNaN();
  });
});

// covers: suite spec 0016 AC-12a (the three cutoff fields, computed as `/auth/session` does)
// covers: VRMS spec 0027 step 6a (the pure helper behind user.systemRoles)
describe('buildSystemRoles', () => {
  const catalog = [
    { system: SystemType.VRMS, code: 'MECHANIC', sortOrder: 2 },
    { system: SystemType.VRMS, code: 'ADMIN', sortOrder: 0 },
    { system: SystemType.VMMS, code: 'MECHANIC', sortOrder: 3 },
  ];

  it('follows the systems order and catalog order, keeping a system with no named role', () => {
    expect(
      buildSystemRoles(
        [
          { system: SystemType.VRMS, role: 'MECHANIC' },
          { system: SystemType.VRMS, role: 'ADMIN' },
          { system: SystemType.BMS, role: 'C_GONE' },
        ],
        [SystemType.BMS, SystemType.VRMS],
        catalog,
      ),
    ).toEqual([
      { system: SystemType.BMS, roles: [] },
      { system: SystemType.VRMS, roles: ['ADMIN', 'MECHANIC'] },
    ]);
  });

  it('never borrows a code held in another system', () => {
    expect(
      buildSystemRoles(
        [{ system: SystemType.VRMS, role: 'ADMIN' }],
        [SystemType.VMMS, SystemType.VRMS],
        catalog,
      ),
    ).toEqual([
      { system: SystemType.VMMS, roles: [] },
      { system: SystemType.VRMS, roles: ['ADMIN'] },
    ]);
  });
});

describe('withCutoffs', () => {
  const BASE = {
    user: { id: 'u1', name: 'Mara', email: 'm@welinc.com', picture: null },
    systems: [],
    mobileSystems: [],
    suiteAdmin: false,
  };
  const NOW = new Date('2026-11-23T10:00:00.000Z');

  it('answers the idle cutoff while it comes first', () => {
    expect(
      withCutoffs(
        BASE,
        {
          endedAt: null,
          idleExpiresAt: new Date('2026-11-23T10:30:00.000Z'),
          absoluteExpiresAt: new Date('2026-11-23T22:00:00.000Z'),
        },
        NOW,
      ),
    ).toEqual({
      ...BASE,
      sessionExpiresAt: '2026-11-23T10:30:00.000Z',
      sessionAbsoluteExpiresAt: '2026-11-23T22:00:00.000Z',
      serverTime: '2026-11-23T10:00:00.000Z',
    });
  });

  it('answers the 12 hour end in both fields once it comes before the idle cutoff', () => {
    const answer = withCutoffs(
      BASE,
      {
        endedAt: null,
        idleExpiresAt: new Date('2026-11-23T22:20:00.000Z'),
        absoluteExpiresAt: new Date('2026-11-23T22:00:00.000Z'),
      },
      NOW,
    );
    expect(answer.sessionExpiresAt).toBe('2026-11-23T22:00:00.000Z');
    expect(answer.sessionAbsoluteExpiresAt).toBe('2026-11-23T22:00:00.000Z');
  });

  it('never leaves the 12 hour field out, even for a session without one', () => {
    const answer = withCutoffs(
      BASE,
      {
        endedAt: null,
        idleExpiresAt: new Date('2026-11-23T10:30:00.000Z'),
        absoluteExpiresAt: null,
      },
      NOW,
    );
    expect(answer.sessionAbsoluteExpiresAt).toBe('2026-11-23T10:30:00.000Z');
  });
});
