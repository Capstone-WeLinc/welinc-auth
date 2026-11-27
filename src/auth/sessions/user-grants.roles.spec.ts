import { describe, it, expect, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import { SystemType, type OAuthClient } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import type { TokenService } from '../tokens/token.service';
import type { SessionService } from './session.service';
import { UserGrantsService } from './user-grants.service';

// Spec 0004, AC-19: every user grant keeps only the roles the client allows, and refuses with
// APP_NOT_ALLOWED before any write. Driven through the native login, the grant with the least
// set up; the code exchange and the refresh call the same `rolesFor`.

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const USER = {
  id: '33333333-3333-4333-8333-333333333333',
  name: 'Ramon',
  email: 'ramon@welinc.com',
};
const NOW = new Date('2026-11-09T08:00:00.000Z');

const vmmsMobile = {
  id: 'vmms-mobile',
  system: SystemType.VMMS,
  allowedRoles: { VMMS: ['MECHANIC', 'CHIEF_MECHANIC'] },
} as unknown as OAuthClient;

const catalogNames = [
  { code: 'MECHANIC', name: 'Mechanic' },
  { code: 'CHIEF_MECHANIC', name: 'Chief Mechanic' },
];

// The catalog order rows `user.systemRoles` reads (VRMS spec 0027, step 6a)
const CATALOG_ORDER = [
  { system: SystemType.BMS, code: 'ADMIN', sortOrder: 0 },
  { system: SystemType.BMS, code: 'OPERATIONS', sortOrder: 1 },
  { system: SystemType.VMMS, code: 'ADMIN', sortOrder: 0 },
  { system: SystemType.VMMS, code: 'OPERATIONS', sortOrder: 1 },
  { system: SystemType.VMMS, code: 'CHIEF_MECHANIC', sortOrder: 2 },
  { system: SystemType.VMMS, code: 'MECHANIC', sortOrder: 3 },
  { system: SystemType.VRMS, code: 'ADMIN', sortOrder: 0 },
  { system: SystemType.VRMS, code: 'CHIEF_MECHANIC', sortOrder: 1 },
  { system: SystemType.VRMS, code: 'MECHANIC', sortOrder: 2 },
  { system: SystemType.VRMS, code: 'C_TIRES', sortOrder: 3 },
  { system: SystemType.VRMS, code: 'C_PAINT', sortOrder: 3 },
];

const webClient = (system: SystemType, allowedRoles: object = {}) => ({
  id: system.toLowerCase(),
  kind: 'CONFIDENTIAL',
  system,
  webAddress: `https://${system.toLowerCase()}.test`,
  allowedRoles,
  appReleased: false,
  createdAt: new Date(0),
});
const WEB_CLIENTS = [
  webClient(SystemType.BMS),
  webClient(SystemType.VMMS),
  webClient(SystemType.VRMS),
];

function build(held: string[]) {
  const db = {
    userRoleAssignment: {
      findMany: fn().mockResolvedValue(
        held.map((role) => ({ role, system: SystemType.VMMS })),
      ),
    },
    // Two catalog reads: role names for APP_NOT_ALLOWED (`select.name`), and the held codes'
    // order for `user.systemRoles` (`select.sortOrder`, VRMS spec 0027 step 6a)
    systemRole: {
      findMany: fn().mockImplementation((args: { select: object }) =>
        Promise.resolve(
          'sortOrder' in args.select ? CATALOG_ORDER : catalogNames,
        ),
      ),
    },
    suiteAdmin: { findUnique: fn().mockResolvedValue(null) },
    // Every system's web client, none limited (suite spec 0014 limits them per test)
    oAuthClient: { findMany: fn().mockResolvedValue(WEB_CLIENTS) },
  };
  const sessions = {
    settings: { graceSeconds: 30 },
    createMobile: fn().mockResolvedValue({
      session: {
        id: 'sid-1',
        idleExpiresAt: new Date(NOW.getTime() + 86_400_000),
        absoluteExpiresAt: null,
      },
      refreshToken: 'r'.repeat(43),
    }),
  };
  const tokens = {
    settings: { accessTokenMinutes: 15 },
    signUserToken: fn().mockResolvedValue('signed.jwt'),
  };
  const service = new UserGrantsService(
    db as unknown as PrismaService,
    tokens as unknown as TokenService,
    sessions as unknown as SessionService,
  );
  return { service, db, sessions, tokens };
}

// The mobile login's two steps (suite spec 0009, AC-11): the checks, then the session
const login = async (service: UserGrantsService, client = vmmsMobile) =>
  service.startMobile(await service.checkMobileGrant(client, USER.id), {
    user: USER,
    deviceName: null,
    meta: { ip: null, device: null, userAgent: null },
  });

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  const http = error as HttpException;
  return {
    status: http.getStatus(),
    body: http.getResponse() as { code?: string; message?: string },
  };
}

describe('spec 0004 allowed roles on user grants', () => {
  it('signs a token for a role the app allows', async () => {
    const { service, tokens } = build(['MECHANIC']);
    const answer = await login(service);
    expect(answer.user.roles).toEqual([
      { role: 'MECHANIC', system: SystemType.VMMS },
    ]);
    expect(tokens.signUserToken).toHaveBeenCalledWith(
      expect.objectContaining({
        aud: SystemType.VMMS,
        roles: [{ role: 'MECHANIC', system: SystemType.VMMS }],
      }),
    );
  });

  it('refuses an Operations account with APP_NOT_ALLOWED, naming the allowed roles in list order', async () => {
    const { service, sessions, tokens } = build(['OPERATIONS']);
    const { status, body } = await refusal(login(service));
    expect(status).toBe(403);
    expect(body.code).toBe('APP_NOT_ALLOWED');
    expect(body.message).toBe(
      'This app is for Mechanic and Chief Mechanic accounts.',
    );
    // Before any write: no session, no token
    expect(sessions.createMobile).not.toHaveBeenCalled();
    expect(tokens.signUserToken).not.toHaveBeenCalled();
  });

  it('answers NO_SYSTEM_ACCESS, not APP_NOT_ALLOWED, when no role is held at all', async () => {
    const { service, sessions } = build([]);
    const { status, body } = await refusal(login(service));
    expect(status).toBe(403);
    expect(body.code).toBe('NO_SYSTEM_ACCESS');
    expect(sessions.createMobile).not.toHaveBeenCalled();
  });

  it('lets every role through a client with no list for the system', async () => {
    const { service } = build(['OPERATIONS']);
    const portalLike = {
      ...vmmsMobile,
      id: 'vmms-web',
      allowedRoles: null,
    } as unknown as OAuthClient;
    const answer = await login(service, portalLike);
    expect(answer.user.roles).toEqual([
      { role: 'OPERATIONS', system: SystemType.VMMS },
    ]);
  });
});

// covers: spec 0007 AC-6 (user.systems in every user grant answer, never in the token)
describe('spec 0007 user.systems on user grants', () => {
  it('lists every held system in the order BMS, VMMS, VRMS, and keeps the token to aud', async () => {
    const { service, db, tokens } = build([]);
    db.userRoleAssignment.findMany.mockResolvedValue([
      { role: 'MECHANIC', system: SystemType.VRMS },
      { role: 'MECHANIC', system: SystemType.VMMS },
      { role: 'OPERATIONS', system: SystemType.BMS },
    ]);
    const answer = await login(service);
    expect(answer.user.systems).toEqual([
      SystemType.BMS,
      SystemType.VMMS,
      SystemType.VRMS,
    ]);
    expect(answer.user.roles).toEqual([
      { role: 'MECHANIC', system: SystemType.VMMS },
    ]);
    const signed = tokens.signUserToken.mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(signed).not.toHaveProperty('systems');
    expect(signed.roles).toEqual([
      { role: 'MECHANIC', system: SystemType.VMMS },
    ]);
  });
});

// covers: suite spec 0014 AC-4 (user.systems holds web openable systems only)
describe('spec 0014 user.systems leaves out phone only systems', () => {
  it('drops VMMS for a mechanic when the vmms web client admits office roles only', async () => {
    const { service, db } = build([]);
    db.userRoleAssignment.findMany.mockResolvedValue([
      { role: 'MECHANIC', system: SystemType.VRMS },
      { role: 'MECHANIC', system: SystemType.VMMS },
    ]);
    db.oAuthClient.findMany.mockResolvedValue([
      webClient(SystemType.VMMS, { VMMS: ['ADMIN', 'OPERATIONS'] }),
      webClient(SystemType.VRMS),
    ]);
    const answer = await login(service);
    expect(answer.user.systems).toEqual([SystemType.VRMS]);
    expect(answer.user.roles).toEqual([
      { role: 'MECHANIC', system: SystemType.VMMS },
    ]);
  });
});

// covers: VRMS spec 0027 step 6a (user.systemRoles and user.suiteAdmin on every user grant)
describe('spec 0027 user.systemRoles and user.suiteAdmin on user grants', () => {
  const heldRows = (rows: [SystemType, string][]) =>
    rows.map(([system, role]) => ({ system, role }));

  it('lists one entry per web system, same order, roles in catalog order with ties by code', async () => {
    const { service, db } = build([]);
    db.userRoleAssignment.findMany.mockResolvedValue(
      heldRows([
        [SystemType.VRMS, 'C_TIRES'],
        [SystemType.VMMS, 'MECHANIC'],
        [SystemType.VRMS, 'MECHANIC'],
        [SystemType.VRMS, 'C_PAINT'],
        [SystemType.VMMS, 'ADMIN'],
      ]),
    );
    const answer = await login(service);
    expect(answer.user.systems).toEqual([SystemType.VMMS, SystemType.VRMS]);
    expect(answer.user.systemRoles).toEqual([
      { system: SystemType.VMMS, roles: ['ADMIN', 'MECHANIC'] },
      { system: SystemType.VRMS, roles: ['MECHANIC', 'C_PAINT', 'C_TIRES'] },
    ]);
    expect(answer.user.suiteAdmin).toBe(false);
  });

  it('reads the rows with the live role filter, so a temporary role counts until it ends', async () => {
    const { service, db } = build(['MECHANIC']);
    // A live temporary grant comes back from the filtered read like any role
    db.userRoleAssignment.findMany.mockResolvedValue(
      heldRows([
        [SystemType.VMMS, 'MECHANIC'],
        [SystemType.BMS, 'OPERATIONS'],
      ]),
    );
    const answer = await login(service);
    const where = (
      db.userRoleAssignment.findMany.mock.calls[0][0] as {
        where: { OR: object[] };
      }
    ).where;
    // The expired one is filtered out by the query itself (spec 0013, AC-10)
    expect(where.OR).toEqual([
      { temporaryGrantId: null },
      {
        temporaryGrant: { expiresAt: { gt: expect.any(Date) }, endedAt: null },
      },
    ]);
    expect(answer.user.systemRoles).toEqual([
      { system: SystemType.BMS, roles: ['OPERATIONS'] },
      { system: SystemType.VMMS, roles: ['MECHANIC'] },
    ]);
  });

  it('leaves out a held code with no catalog row, keeping the entry with roles []', async () => {
    const { service, db } = build([]);
    db.userRoleAssignment.findMany.mockResolvedValue(
      heldRows([
        [SystemType.VMMS, 'MECHANIC'],
        [SystemType.VRMS, 'C_DELETED'],
      ]),
    );
    const answer = await login(service);
    expect(answer.user.systemRoles).toEqual([
      { system: SystemType.VMMS, roles: ['MECHANIC'] },
      { system: SystemType.VRMS, roles: [] },
    ]);
  });

  it('is not filtered by the client allowedRoles, and leaves out a phone only system', async () => {
    const { service, db } = build([]);
    db.userRoleAssignment.findMany.mockResolvedValue(
      heldRows([
        [SystemType.VMMS, 'MECHANIC'],
        [SystemType.VMMS, 'OPERATIONS'],
        [SystemType.BMS, 'OPERATIONS'],
      ]),
    );
    // BMS has no web client here, so it is phone only and has no entry
    db.oAuthClient.findMany.mockResolvedValue([webClient(SystemType.VMMS)]);
    const answer = await login(service);
    // The token keeps the roles the app allows; the entry keeps every held one
    expect(answer.user.roles).toEqual([
      { role: 'MECHANIC', system: SystemType.VMMS },
    ]);
    expect(answer.user.systemRoles).toEqual([
      { system: SystemType.VMMS, roles: ['OPERATIONS', 'MECHANIC'] },
    ]);
  });

  it('says suiteAdmin for a suite admin, read for this person, and keeps both out of the token', async () => {
    const { service, db, tokens } = build(['MECHANIC']);
    db.suiteAdmin.findUnique.mockResolvedValue({ userId: USER.id });
    const answer = await login(service);
    expect(answer.user.suiteAdmin).toBe(true);
    expect(db.suiteAdmin.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { userId: USER.id } }),
    );
    const signed = tokens.signUserToken.mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(signed).not.toHaveProperty('systemRoles');
    expect(signed).not.toHaveProperty('suiteAdmin');
  });
});
