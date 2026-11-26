import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import type { PrismaClient } from '@prisma/client';
import { CATALOG } from '../../../prisma/catalog';
import {
  CLIENTS,
  checkAllowedRoles,
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
    const catalog = CATALOG.flatMap((d) =>
      d.roles.map((r) => ({ system: d.system, code: r.code })),
    );
    await seedClients(
      {
        oAuthClient: { upsert },
        systemRole: { findMany: () => Promise.resolve(catalog) },
      } as unknown as PrismaClient,
      env,
    );
    return Object.fromEntries(
      upsert.mock.calls.map(([args]) => [args.where.id, args]),
    );
  }

  it('upserts the eight clients of the contract', async () => {
    const calls = await run({});
    expect(Object.keys(calls).sort()).toEqual(
      [
        'bms',
        'bms-analytics',
        'bms-mobile',
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
      // Spec 0013, AC-26: VRMS also reads its permission matrix; VRMS spec 0029, AC-26: VMMS
      // and BMS
      serviceScopes: {
        AUTH: ['directory.read', 'permissions.read'],
        VMMS: [
          'fleet.read',
          'fleet.repair-status.write',
          'repair.referral-status.write',
        ],
        BMS: ['schedule.read', 'repair.update.write'],
      },
      allowedRoles: {},
      appReleased: false,
      webAddress: 'http://localhost:8001',
      redirectUris: ['http://localhost:3000/vrms/session/callback'],
    });
    // Suite spec 0014, AC-1: the VMMS and BMS web apps admit office roles only
    expect(calls.vmms.update).toMatchObject({
      serviceScopes: {
        AUTH: ['directory.read', 'directory.contact'],
        VRMS: [
          'repair.referral.write',
          'repair.status.read',
          'repair.history.read',
          'fleet.change.write',
        ],
        BMS: ['fleet.availability.write', 'fleet.change.write'],
      },
      allowedRoles: { VMMS: ['ADMIN', 'OPERATIONS'] },
    });
    expect(calls.bms.update).toMatchObject({
      serviceScopes: {
        AUTH: ['directory.read', 'directory.contact'],
        VMMS: ['fleet.read'],
        VRMS: ['repair.status.read', 'repair.expedite.write'],
      },
      allowedRoles: { BMS: ['ADMIN', 'CUSTOMER_SUPPORT', 'OPERATIONS'] },
    });
    // Suite spec 0014, AC-6: only the VMMS app has shipped
    expect(calls['vmms-mobile'].update).toMatchObject({ appReleased: true });
    expect(calls['bms-mobile'].update).toMatchObject({ appReleased: false });
    expect(calls['vmms-analytics'].update).toMatchObject({
      kind: 'SERVICE',
      serviceScopes: { AUTH: ['directory.read'] },
    });
    expect(calls.portal.update).toMatchObject({
      system: null,
      grants: ['sso'],
    });
  });

  // covers: spec 0004 AC-18
  it('limits the mobile apps to their roles, per audience', async () => {
    const calls = await run({});
    expect(calls['vmms-mobile'].update.allowedRoles).toEqual({
      VMMS: ['MECHANIC', 'CHIEF_MECHANIC'],
      VRMS: ['MECHANIC', 'CHIEF_MECHANIC'],
    });
    expect(calls['bms-mobile'].update).toMatchObject({
      kind: 'PUBLIC_NATIVE',
      system: 'BMS',
      grants: ['mobile_login', 'refresh_token'],
      userAudiences: ['BMS'],
      allowedRoles: { BMS: ['DRIVER', 'HELPER'] },
    });
  });

  it('refuses an allowed role the catalog does not have, and an empty catalog', () => {
    const catalog = [{ system: 'BMS' as const, code: 'DRIVER' }];
    expect(() => checkAllowedRoles(CLIENTS, [])).toThrow(
      'Run npm run db:deploy first.',
    );
    expect(() => checkAllowedRoles(CLIENTS, catalog)).toThrow(
      "bms-mobile: BMS has no role 'HELPER'",
    );
  });

  // covers: spec 0003 (the registry's web and redirect addresses come from env)
  it('builds each callback from API_PUBLIC_URL and the web address from env', async () => {
    const calls = await run({
      API_PUBLIC_URL: 'https://api.welinc.app/',
      CLIENT_VRMS_WEB_ADDRESS: 'https://vrms.welinc.app',
      PORTAL_URL: 'https://portal.welinc.app',
    });
    expect(calls.vrms.update).toMatchObject({
      webAddress: 'https://vrms.welinc.app',
      redirectUris: ['https://api.welinc.app/vrms/session/callback'],
    });
    expect(calls.portal.update).toMatchObject({
      webAddress: 'https://portal.welinc.app',
      redirectUris: [],
    });
    expect(calls['vmms-mobile'].update).toMatchObject({
      webAddress: null,
      redirectUris: [],
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
    expect(CLIENTS).toHaveLength(8);
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
