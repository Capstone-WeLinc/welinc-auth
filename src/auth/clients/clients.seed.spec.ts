import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import type { PrismaClient } from '@prisma/client';
import {
  CLIENTS,
  jwksEnvName,
  parseClientJwks,
  seedClients,
} from '../../../prisma/seeds/clients.seed';
import { testClient, type TestClient } from '../testing/test-clients';

type Upsert = {
  where: { id: string };
  create: Record<string, unknown>;
  update: Record<string, unknown>;
};

// covers: spec 0002 AC-13 (the seven clients, updated in place, jwks from env only when set)
describe('seedClients', () => {
  let vrms: TestClient;
  beforeAll(async () => {
    vrms = await testClient('vrms');
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  async function run(env: Record<string, string>) {
    const upsert = jest
      .fn<(args: Upsert) => Promise<unknown>>()
      .mockResolvedValue({});
    await seedClients(
      { oAuthClient: { upsert } } as unknown as PrismaClient,
      env,
    );
    return Object.fromEntries(
      upsert.mock.calls.map(([args]) => [args.where.id, args]),
    );
  }

  it('upserts the seven clients of the contract', async () => {
    const calls = await run({});
    expect(Object.keys(calls).sort()).toEqual(
      [
        'bms',
        'bms-analytics',
        'portal',
        'vmms',
        'vmms-analytics',
        'vmms-mobile',
        'vrms',
      ].sort(),
    );
    expect(calls.vrms.update).toEqual({
      kind: 'CONFIDENTIAL',
      system: 'VRMS',
      grants: ['authorization_code', 'refresh_token', 'client_credentials'],
      userAudiences: ['VRMS'],
      serviceScopes: { AUTH: ['directory.read', 'directory.contact'] },
    });
    expect(calls['vmms-analytics'].update).toMatchObject({
      kind: 'SERVICE',
      serviceScopes: { AUTH: ['directory.read'] },
    });
    expect(calls.portal.update).toMatchObject({
      system: null,
      grants: ['sso'],
    });
  });

  it('sets jwks only from a set env value, and never touches isActive on an update', async () => {
    const jwks = JSON.stringify({ keys: [vrms.publicJwk] });
    const calls = await run({ CLIENT_VRMS_JWKS: jwks });
    expect(calls.vrms.create).toMatchObject({
      id: 'vrms',
      jwks: { keys: [vrms.publicJwk] },
    });
    expect(calls.vrms.update).toMatchObject({
      jwks: { keys: [vrms.publicJwk] },
    });
    expect(calls.bms.update).not.toHaveProperty('jwks');
    for (const call of Object.values(calls)) {
      expect(call.update).not.toHaveProperty('isActive');
      expect(call.create).not.toHaveProperty('isActive');
    }
  });

  it('names the env value after the client id', () => {
    expect(jwksEnvName('vmms-analytics')).toBe('CLIENT_VMMS_ANALYTICS_JWKS');
    expect(CLIENTS).toHaveLength(7);
  });

  it('refuses a private key, bad JSON and a key that is not ES256', async () => {
    expect(() =>
      parseClientJwks(
        'X',
        JSON.stringify({ keys: [{ ...vrms.publicJwk, d: 'secret' }] }),
      ),
    ).toThrow(/private key/);
    expect(() => parseClientJwks('X', '{')).toThrow(/valid JSON/);
    expect(() =>
      parseClientJwks(
        'X',
        JSON.stringify({ keys: [{ ...vrms.publicJwk, alg: 'RS256' }] }),
      ),
    ).toThrow(/ES256/);
    await expect(run({ CLIENT_VRMS_JWKS: '{' })).rejects.toThrow(
      'CLIENT_VRMS_JWKS is not valid JSON',
    );
  });
});
