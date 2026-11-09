import { describe, it, expect, jest } from '@jest/globals';
import { HttpException, Logger } from '@nestjs/common';
import { ClientKind, SystemType } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import {
  LAUNCHER_ORDER,
  LauncherService,
  buildLauncherSystems,
  launcherOrder,
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

const client = (system: SystemType, webAddress: string | null, at = 0) => ({
  system,
  webAddress,
  createdAt: new Date(at),
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

describe('LauncherService.answerFor', () => {
  const USER = {
    id: 'u1',
    name: 'Mara Lead',
    email: 'multi.lead@welinc.com',
    profilePicture: '/uploads/u1.png',
  };

  function build(
    held: { system: SystemType; role: string }[],
    clients: ReturnType<typeof client>[],
  ) {
    const db = {
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
    const answer = await service.answerFor(USER);
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
          kind: ClientKind.CONFIDENTIAL,
          isActive: true,
        }),
      }),
    );
  });

  it('answers 403 NO_SYSTEM_ACCESS for no role at all, without reading clients', async () => {
    const { service, db } = build([], []);
    expect(await status(service.answerFor(USER))).toEqual([
      403,
      'NO_SYSTEM_ACCESS',
    ]);
    expect(db.oAuthClient.findMany).not.toHaveBeenCalled();
  });

  it('answers 403 when every held system lacks a client, and warns naming the system, never the email', async () => {
    const warn = jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation(() => {});
    const { service } = build(
      [{ system: SystemType.BMS, role: 'OPERATIONS' }],
      [],
    );
    expect(await status(service.answerFor(USER))).toEqual([
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
