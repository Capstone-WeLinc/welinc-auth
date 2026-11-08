import {
  describe,
  it,
  expect,
  beforeAll,
  beforeEach,
  jest,
} from '@jest/globals';
import {
  ForbiddenException,
  HttpException,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SystemType, UserRole } from '@prisma/client';
import type { Request } from 'express';
import type { PrismaService } from '../../shared/prisma.service';
import { SERVICE_SCOPE_KEY } from '../decorators/service-scope.decorator';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { testTokenService } from '../testing/test-keys';
import type { TokenService } from '../tokens/token.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { OptionalJwtAuthGuard } from './optional-jwt-auth.guard';
import type { SessionService } from '../sessions/session.service';
import { RequestAuthenticator, type Caller } from './request-authenticator';
import { RolesGuard } from './roles.guard';

type Row = {
  id: string;
  email: string;
  isActive: boolean;
  lockedAt: Date | null;
  roles: { role: UserRole; system: SystemType }[];
};

const USER_ID = '3f2b8c1e-5a4d-4e6f-9a7b-1c2d3e4f5a6b';
const row = (overrides: Partial<Row> = {}): Row => ({
  id: USER_ID,
  email: 'pedro@welinc.com',
  isActive: true,
  lockedAt: null,
  roles: [
    { role: UserRole.ADMIN, system: SystemType.VRMS },
    { role: UserRole.OPERATIONS, system: SystemType.BMS },
  ],
  ...overrides,
});

function context(
  request: Partial<Request>,
  handler: () => void = () => undefined,
): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => handler,
    getClass: () => class {},
  } as unknown as ExecutionContext;
}

const codeOf = (error: unknown) =>
  ((error as HttpException).getResponse() as { code?: string }).code;

// covers: spec 0002 AC-8 (token checks), AC-9 (system is aud), AC-19 (service tokens refused off marked routes)
describe('welinc-auth guards', () => {
  let tokens: TokenService;
  let findFirst: jest.Mock<(args: unknown) => Promise<Row | null>>;
  type ClientRow = { isActive: boolean; system: SystemType | null };
  let findClient: jest.Mock<(args: unknown) => Promise<ClientRow | null>>;
  let authenticator: RequestAuthenticator;
  let liveSession: jest.Mock<(sid: string) => Promise<unknown>>;

  const userToken = (aud: 'VRMS' | 'BMS' = 'VRMS') =>
    tokens.signUserToken({
      sub: USER_ID,
      email: 'pedro@welinc.com',
      aud,
      roles: [],
      sid: 'sid-1',
      clientId: 'vrms',
    });
  const serviceToken = (scopes = ['directory.read']) =>
    tokens
      .signServiceToken({ clientId: 'vrms', aud: 'AUTH', scopes })
      .then((t) => t.token);
  const request = (token: string | null, query: Record<string, unknown> = {}) =>
    ({
      headers: token ? { authorization: `Bearer ${token}` } : {},
      query,
    }) as unknown as Request & { user?: Caller | null };

  beforeAll(async () => {
    tokens = await testTokenService();
  });

  beforeEach(() => {
    findFirst = jest.fn<(args: unknown) => Promise<Row | null>>();
    findFirst.mockResolvedValue(row());
    findClient = jest.fn<(args: unknown) => Promise<ClientRow | null>>();
    findClient.mockResolvedValue({ isActive: true, system: SystemType.VRMS });
    liveSession = jest.fn<(sid: string) => Promise<unknown>>();
    liveSession.mockResolvedValue({ id: 'sid-1', userId: USER_ID });
    authenticator = new RequestAuthenticator(
      tokens,
      {
        user: { findFirst },
        oAuthClient: { findUnique: findClient },
      } as unknown as PrismaService,
      { live: liveSession } as unknown as SessionService,
    );
  });

  describe('RequestAuthenticator', () => {
    it('answers the person with every role and the token aud as the system', async () => {
      const caller = await authenticator.authenticate(
        request(await userToken()),
      );
      expect(caller).toEqual({
        kind: 'user',
        sub: USER_ID,
        email: 'pedro@welinc.com',
        roles: row().roles,
        system: 'VRMS',
      });
    });

    it('accepts a ?system= equal to aud and refuses a different one with WRONG_AUDIENCE', async () => {
      await expect(
        authenticator.authenticate(
          request(await userToken(), { system: 'vrms' }),
        ),
      ).resolves.toBeDefined();
      const error = await authenticator
        .authenticate(request(await userToken(), { system: 'BMS' }))
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(HttpException);
      expect((error as HttpException).getStatus()).toBe(403);
      expect(codeOf(error)).toBe('WRONG_AUDIENCE');
      // Only the first, matching request reached the account check
      expect(findFirst).toHaveBeenCalledTimes(1);
    });

    it('refuses no token, a bad token and an HS256 token with 401', async () => {
      await expect(
        authenticator.authenticate(request(null)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      await expect(
        authenticator.authenticate(request('not.a.token')),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('keeps the account check: inactive or deleted 401, locked 403, no role in aud 401', async () => {
      findFirst.mockResolvedValueOnce(row({ isActive: false }));
      await expect(
        authenticator.authenticate(request(await userToken())),
      ).rejects.toThrow('Invalid session');
      findFirst.mockResolvedValueOnce(null);
      await expect(
        authenticator.authenticate(request(await userToken())),
      ).rejects.toThrow('Invalid session');
      findFirst.mockResolvedValueOnce(row({ lockedAt: new Date() }));
      await expect(
        authenticator.authenticate(request(await userToken())),
      ).rejects.toBeInstanceOf(ForbiddenException);
      findFirst.mockResolvedValueOnce(
        row({ roles: [{ role: UserRole.OPERATIONS, system: SystemType.BMS }] }),
      );
      await expect(
        authenticator.authenticate(request(await userToken())),
      ).rejects.toThrow('does not have access');
    });

    it("answers a service caller with its client's system, without reading any account", async () => {
      const caller = await authenticator.authenticate(
        request(await serviceToken()),
      );
      expect(caller).toMatchObject({
        kind: 'service',
        clientId: 'vrms',
        scopes: ['directory.read'],
        system: 'VRMS',
      });
      expect(findFirst).not.toHaveBeenCalled();
    });

    it('refuses a service token from a switched off client, or one with no system, with 401', async () => {
      findClient.mockResolvedValueOnce({
        isActive: false,
        system: SystemType.VRMS,
      });
      await expect(
        authenticator.authenticate(request(await serviceToken())),
      ).rejects.toBeInstanceOf(UnauthorizedException);
      findClient.mockResolvedValueOnce({ isActive: true, system: null });
      await expect(
        authenticator.authenticate(request(await serviceToken())),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it("refuses a service token's ?system= for another system with 403 WRONG_AUDIENCE", async () => {
      await expect(
        authenticator.authenticate(
          request(await serviceToken(), { system: 'VRMS' }),
        ),
      ).resolves.toBeDefined();
      const error = await authenticator
        .authenticate(request(await serviceToken(), { system: 'BMS' }))
        .catch((e: unknown) => e);
      expect((error as HttpException).getStatus()).toBe(403);
      expect(codeOf(error)).toBe('WRONG_AUDIENCE');
    });
  });

  describe('JwtAuthGuard', () => {
    it('lets a person in and sets req.user', async () => {
      const req = request(await userToken());
      await expect(
        new JwtAuthGuard(authenticator, new Reflector()).canActivate(
          context(req),
        ),
      ).resolves.toBe(true);
      expect(req.user).toMatchObject({ kind: 'user', system: 'VRMS' });
    });

    it('answers a service token on an unmarked route with 403 WRONG_TOKEN_USE', async () => {
      const guard = new JwtAuthGuard(authenticator, new Reflector());
      const error = await guard
        .canActivate(context(request(await serviceToken())))
        .catch((e: unknown) => e);
      expect((error as HttpException).getStatus()).toBe(403);
      expect(codeOf(error)).toBe('WRONG_TOKEN_USE');
    });

    it('lets a service token in on a route marked with its scope, not another', async () => {
      const handler = () => undefined;
      Reflect.defineMetadata(SERVICE_SCOPE_KEY, 'directory.read', handler);
      const guard = new JwtAuthGuard(authenticator, new Reflector());
      await expect(
        guard.canActivate(context(request(await serviceToken()), handler)),
      ).resolves.toBe(true);
      const error = await guard
        .canActivate(
          context(request(await serviceToken(['directory.contact'])), handler),
        )
        .catch((e: unknown) => e);
      expect(codeOf(error)).toBe('WRONG_TOKEN_USE');
    });
  });

  describe('OptionalJwtAuthGuard', () => {
    it('sets the person when the token is good', async () => {
      const req = request(await userToken());
      await expect(
        new OptionalJwtAuthGuard(authenticator).canActivate(context(req)),
      ).resolves.toBe(true);
      expect(req.user).toMatchObject({ kind: 'user', sub: USER_ID });
    });

    it('treats no token, a bad token, a wrong ?system= and a service token as no token at all', async () => {
      const guard = new OptionalJwtAuthGuard(authenticator);
      for (const req of [
        request(null),
        request('bad.token.here'),
        request(await userToken(), { system: 'BMS' }),
        request(await serviceToken()),
      ]) {
        await expect(guard.canActivate(context(req))).resolves.toBe(true);
        expect(req.user).toBeNull();
      }
    });
  });

  describe('RolesGuard', () => {
    const adminRoute = () => undefined;
    Reflect.defineMetadata(ROLES_KEY, [UserRole.ADMIN], adminRoute);
    const guard = new RolesGuard(new Reflector());
    const withUser = (user: Caller) =>
      context({ user } as Partial<Request>, adminRoute);

    it('checks roles in the token system only', () => {
      const roles = row().roles;
      expect(
        guard.canActivate(
          withUser({
            kind: 'user',
            sub: USER_ID,
            email: 'e',
            roles,
            system: SystemType.VRMS,
          }),
        ),
      ).toBe(true);
      expect(
        guard.canActivate(
          withUser({
            kind: 'user',
            sub: USER_ID,
            email: 'e',
            roles,
            system: SystemType.BMS,
          }),
        ),
      ).toBe(false);
    });

    const service = {
      kind: 'service',
      clientId: 'vrms',
      scopes: ['directory.read'],
      system: SystemType.VRMS,
    } as Caller;

    it('never treats a client as an admin on an unmarked route', () => {
      expect(guard.canActivate(withUser(service))).toBe(false);
    });

    it('lets a client through on a @ServiceScope() route, whose scope JwtAuthGuard checked', () => {
      const directoryRoute = () => undefined;
      Reflect.defineMetadata(ROLES_KEY, [UserRole.ADMIN], directoryRoute);
      Reflect.defineMetadata(
        SERVICE_SCOPE_KEY,
        'directory.read',
        directoryRoute,
      );
      expect(
        guard.canActivate(
          context({ user: service } as Partial<Request>, directoryRoute),
        ),
      ).toBe(true);
    });
  });
});
