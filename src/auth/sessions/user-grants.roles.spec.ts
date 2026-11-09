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

function build(held: string[]) {
  const db = {
    userRoleAssignment: {
      findMany: fn().mockResolvedValue(
        held.map((role) => ({ role, system: SystemType.VMMS })),
      ),
    },
    systemRole: { findMany: fn().mockResolvedValue(catalogNames) },
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

const login = (service: UserGrantsService, client = vmmsMobile) =>
  service.startMobile(client, { user: USER, deviceName: null, ip: null });

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
