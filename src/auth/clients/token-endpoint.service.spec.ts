import {
  describe,
  it,
  expect,
  beforeAll,
  beforeEach,
  jest,
} from '@jest/globals';
import { HttpException, Logger } from '@nestjs/common';
import { ThrottlerStorageService } from '@nestjs/throttler';
import { Prisma } from '@prisma/client';
import { decodeJwt } from 'jose';
import type { PrismaService } from '../../shared/prisma.service';
import { TEST_ISSUER, testTokenService } from '../testing/test-keys';
import {
  signAssertion,
  testClient,
  type TestClient,
} from '../testing/test-clients';
import type { TokenService } from '../tokens/token.service';
import type { UserGrantsService } from '../sessions/user-grants.service';
import {
  ASSERTION_TYPE,
  ClientRateLimitedError,
  TokenEndpointService,
} from './token-endpoint.service';

type Row = {
  id: string;
  isActive: boolean;
  jwks: unknown;
  grants: string[];
  serviceScopes: Record<string, string[]>;
};

async function oauth(promise: Promise<unknown>) {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  const http = error as HttpException;
  return {
    status: http.getStatus(),
    error: (http.getResponse() as { error: string }).error,
  };
}

// covers: spec 0002 AC-14 (fields and answer), AC-16 (grant, audience, scope), AC-17 (jti),
// AC-18 (per client limit), AC-27 (log lines)
describe('TokenEndpointService', () => {
  let tokens: TokenService;
  let vrms: TestClient;
  let analytics: TestClient;
  let rows: Record<string, Row>;
  let used: Set<string>;
  let create: jest.Mock<
    (args: {
      data: { clientId: string; jti: string; expiresAt: Date };
    }) => Promise<unknown>
  >;
  let deleteMany: jest.Mock<(args: unknown) => Promise<{ count: number }>>;
  let service: TokenEndpointService;
  let logs: string[];

  beforeAll(async () => {
    tokens = await testTokenService();
    vrms = await testClient('vrms');
    analytics = await testClient('vmms-analytics');
  });

  beforeEach(() => {
    rows = {
      vrms: {
        ...vrms.row,
        grants: ['authorization_code', 'refresh_token', 'client_credentials'],
        serviceScopes: { AUTH: ['directory.read', 'directory.contact'] },
      },
      'vmms-analytics': {
        ...analytics.row,
        grants: ['client_credentials'],
        serviceScopes: { AUTH: ['directory.read'] },
      },
    };
    used = new Set();
    // Behaves like the primary key: a second row for the same client and jti fails with P2002
    create = jest.fn(
      (args: { data: { clientId: string; jti: string; expiresAt: Date } }) => {
        const key = `${args.data.clientId}|${args.data.jti}`;
        if (used.has(key)) {
          return Promise.reject(
            new Prisma.PrismaClientKnownRequestError(
              'Unique constraint failed',
              { code: 'P2002', clientVersion: 'test' },
            ),
          );
        }
        used.add(key);
        return Promise.resolve({});
      },
    );
    deleteMany = jest
      .fn<(args: unknown) => Promise<{ count: number }>>()
      .mockResolvedValue({ count: 3 });
    const prisma = {
      oAuthClient: {
        findUnique: ({ where }: { where: { id: string } }) =>
          Promise.resolve(rows[where.id] ?? null),
      },
      clientAssertionJti: { create, deleteMany },
    } as unknown as PrismaService;
    service = new TokenEndpointService(
      prisma,
      tokens,
      new ThrottlerStorageService(),
      {} as UserGrantsService,
    );
    logs = [];
    jest
      .spyOn(Logger.prototype, 'log')
      .mockImplementation((m: unknown) => void logs.push(String(m)));
    jest
      .spyOn(Logger.prototype, 'warn')
      .mockImplementation((m: unknown) => void logs.push(String(m)));
  });

  afterEach(() => jest.restoreAllMocks());

  const form = async (
    client: TestClient,
    extra: Record<string, unknown> = {},
    assertion?: string,
  ) => ({
    grant_type: 'client_credentials',
    client_assertion_type: ASSERTION_TYPE,
    client_assertion: assertion ?? (await signAssertion(client)),
    audience: 'AUTH',
    scope: 'directory.read',
    ...extra,
  });

  it('issues a 5 minute service token and echoes the scopes', async () => {
    const answer = await service.grant(
      await form(vrms, { scope: 'directory.read directory.contact' }),
      '10.0.0.1',
    );
    expect(answer).toMatchObject({
      token_type: 'Bearer',
      expires_in: 300,
      scope: 'directory.read directory.contact',
    });
    expect(answer).not.toHaveProperty('refresh_token');
    expect(decodeJwt(answer.access_token)).toMatchObject({
      iss: TEST_ISSUER,
      sub: 'client:vrms',
      aud: 'AUTH',
      client_id: 'vrms',
      token_use: 'service',
      scope: 'directory.read directory.contact',
    });
    expect(logs.join('\n')).toMatch(
      /issued service token client=vrms aud=AUTH scope="directory.read directory.contact" kid=auth-test-current jti=/,
    );
    expect(logs.join('\n')).not.toContain(answer.access_token);
  });

  it('answers invalid_request for a missing, repeated or empty field, or the wrong assertion type', async () => {
    const good = await form(vrms);
    for (const bad of [
      { ...good, audience: undefined },
      { ...good, scope: ['directory.read', 'directory.contact'] },
      { ...good, scope: ' ' },
      { ...good, client_assertion_type: 'urn:other' },
    ]) {
      expect(await oauth(service.grant(bad, 'ip'))).toEqual({
        status: 400,
        error: 'invalid_request',
      });
    }
  });

  it('ignores unknown fields', async () => {
    await expect(
      service.grant({ ...(await form(vrms)), extra: 'x' }, 'ip'),
    ).resolves.toBeDefined();
  });

  it('answers invalid_client for a bad assertion and logs the reason with the address', async () => {
    const now = Math.floor(Date.now() / 1000);
    const assertion = await signAssertion(vrms, { iat: now, exp: now + 61 });
    expect(
      await oauth(service.grant(await form(vrms, {}, assertion), '10.1.2.3')),
    ).toEqual({ status: 401, error: 'invalid_client' });
    expect(logs.join('\n')).toContain(
      'refused assertion client=vrms reason=lifetime_too_long ip=10.1.2.3',
    );
    expect(logs.join('\n')).not.toContain(assertion);
  });

  it('checks grant, then audience, then scope, all after the assertion', async () => {
    expect(
      await oauth(
        service.grant(await form(vrms, { grant_type: 'password' }), 'ip'),
      ),
    ).toEqual({ status: 400, error: 'unsupported_grant_type' });
    rows.vrms.grants = ['authorization_code'];
    expect(await oauth(service.grant(await form(vrms), 'ip'))).toEqual({
      status: 400,
      error: 'unauthorized_client',
    });
    rows.vrms.grants = ['client_credentials'];
    expect(
      await oauth(service.grant(await form(vrms, { audience: 'VMMS' }), 'ip')),
    ).toEqual({ status: 400, error: 'invalid_target' });
    expect(
      await oauth(
        service.grant(
          await form(analytics, { scope: 'directory.contact' }),
          'ip',
        ),
      ),
    ).toEqual({ status: 400, error: 'invalid_scope' });
  });

  it('records the jti only after every check passed, with the assertion exp', async () => {
    const now = Math.floor(Date.now() / 1000);
    const assertion = await signAssertion(analytics, {
      exp: now + 45,
      claims: { jti: 'only-once' },
    });
    // A refused scope doesn't use the jti up
    await oauth(
      service.grant(
        await form(analytics, { scope: 'directory.contact' }, assertion),
        'ip',
      ),
    );
    expect(create).not.toHaveBeenCalled();
    await service.grant(await form(analytics, {}, assertion), 'ip');
    expect(create).toHaveBeenCalledWith({
      data: {
        clientId: 'vmms-analytics',
        jti: 'only-once',
        expiresAt: new Date((now + 45) * 1000),
      },
    });
  });

  it('gives one token for the same assertion sent twice, even at the same moment', async () => {
    const same = await form(vrms);
    const results = await Promise.allSettled([
      service.grant(same, 'ip'),
      service.grant(same, 'ip'),
    ]);
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    const refused = results.find(
      (r) => r.status === 'rejected',
    ) as PromiseRejectedResult;
    expect((refused.reason as HttpException).getStatus()).toBe(401);
    expect(logs.join('\n')).toContain('reason=jti_reused');
    expect(await oauth(service.grant(same, 'ip'))).toEqual({
      status: 401,
      error: 'invalid_client',
    });
  });

  // spec 0003 AC-43 raised the per client limit from 60 to 600 a minute
  it('answers the 601st request from one client in a minute with a rate limit', async () => {
    for (let i = 0; i < 600; i++) await service.grant(await form(vrms), 'ip');
    const error = await service
      .grant(await form(vrms), 'ip')
      .catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ClientRateLimitedError);
    expect((error as ClientRateLimitedError).retryAfterSeconds).toBeGreaterThan(
      0,
    );
    // Another client keeps its own count
    await expect(
      service.grant(await form(analytics), 'ip'),
    ).resolves.toBeDefined();
  });

  it('does not count refused assertions against the client', async () => {
    const forged = await signAssertion(vrms, { key: analytics.privateKey });
    for (let i = 0; i < 70; i++)
      await oauth(service.grant(await form(vrms, {}, forged), 'ip'));
    await expect(service.grant(await form(vrms), 'ip')).resolves.toBeDefined();
  });

  it('sweeps replay rows more than a minute past their expiry', async () => {
    const now = Date.parse('2026-11-08T10:00:00Z');
    await expect(service.sweepJtis(now)).resolves.toBe(3);
    expect(deleteMany).toHaveBeenCalledWith({
      where: { expiresAt: { lt: new Date(now - 60_000) } },
    });
  });
});
