import { describe, it, expect, jest } from '@jest/globals';
import { Logger } from '@nestjs/common';
import { SystemType, type OAuthClient } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import { AuthorizeService, type AuthorizeRequest } from './authorize.service';
import type { LiveSession, SessionService } from './session.service';

// covers: suite spec 0014 AC-2 (the authorize refusal for a role the web app doesn't admit)

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const REDIRECT = 'http://localhost:3000/vmms/session/callback';

function request(allowedRoles: object): AuthorizeRequest {
  return {
    client: {
      id: 'vmms',
      system: SystemType.VMMS,
      allowedRoles,
    } as unknown as OAuthClient,
    redirectUri: REDIRECT,
    state: 'st4te',
    codeChallenge: 'c'.repeat(43),
  };
}

const SESSION = { id: 'sid-1', userId: 'u1' } as unknown as LiveSession;

function build(held: string[]) {
  const db = {
    userRoleAssignment: {
      findMany: fn().mockResolvedValue(held.map((role) => ({ role }))),
    },
    authorizationCode: { create: fn().mockResolvedValue({}) },
    loginRequest: { create: fn().mockResolvedValue({}) },
  };
  const service = new AuthorizeService(
    db as unknown as PrismaService,
    {} as SessionService,
  );
  return { service, db };
}

const params = (location: string) => new URL(location).searchParams;

describe('AuthorizeService.continue, spec 0014 AC-2', () => {
  const OFFICE = { VMMS: ['ADMIN', 'OPERATIONS'] };

  it('refuses a held role the client does not admit with APP_NOT_ALLOWED and writes no code', async () => {
    const log = jest
      .spyOn(Logger.prototype, 'log')
      .mockImplementation(() => {});
    const { service, db } = build(['MECHANIC']);
    const result = await service.continue(
      request(OFFICE),
      SESSION,
      'http://portal',
    );
    expect(result.kind).toBe('redirect');
    const location = (result as { location: string }).location;
    expect(location.startsWith(REDIRECT)).toBe(true);
    const q = params(location);
    expect(q.get('error')).toBe('access_denied');
    expect(q.get('error_description')).toBe('APP_NOT_ALLOWED');
    expect(q.get('state')).toBe('st4te');
    expect(q.has('code')).toBe(false);
    expect(db.authorizationCode.create).not.toHaveBeenCalled();
    expect(String(log.mock.calls[0][0])).toContain('reason=app_not_allowed');
    log.mockRestore();
  });

  it('keeps the plain access_denied for a person with no live role there', async () => {
    const { service } = build([]);
    const result = await service.continue(
      request(OFFICE),
      SESSION,
      'http://portal',
    );
    const q = params((result as { location: string }).location);
    expect(q.get('error')).toBe('access_denied');
    expect(q.has('error_description')).toBe(false);
  });

  it('issues a code when one held role is admitted, or the client names no list', async () => {
    for (const [held, allowed] of [
      [['MECHANIC', 'OPERATIONS'], OFFICE],
      [['MECHANIC'], {}],
    ] as const) {
      const { service, db } = build([...held]);
      const result = await service.continue(
        request(allowed),
        SESSION,
        'http://portal',
      );
      expect(
        params((result as { location: string }).location).has('code'),
      ).toBe(true);
      expect(db.authorizationCode.create).toHaveBeenCalledTimes(1);
    }
  });
});
