import { describe, expect, it } from '@jest/globals';
import {
  addressesFor,
  checkAllowedRoles,
  CLIENTS,
  jwksEnvName,
  parseClientJwks,
  webAddressEnvName,
} from '../../../prisma/seeds/clients.seed';

// covers: spec 0006 AC-11 (the seed fills the client registry the same way `seed:clients` does),
// plus the client rules from specs 0002 to 0004 that the seed enforces before it writes.

const publicKey = {
  kty: 'EC',
  crv: 'P-256',
  kid: 'k1',
  alg: 'ES256',
  x: 'x',
  y: 'y',
};

describe('env names', () => {
  it('upper cases the client id and swaps hyphens', () => {
    expect(jwksEnvName('vmms-analytics')).toBe('CLIENT_VMMS_ANALYTICS_JWKS');
    expect(webAddressEnvName('vrms')).toBe('CLIENT_VRMS_WEB_ADDRESS');
  });
});

describe('CLIENTS', () => {
  it('has unique ids', () => {
    const ids = CLIENTS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('addressesFor', () => {
  const vrms = CLIENTS.find((c) => c.id === 'vrms')!;
  const portal = CLIENTS.find((c) => c.id === 'portal')!;

  it('uses the local address and the local gateway when no env is set', () => {
    const a = addressesFor(vrms, {});
    expect(a.webAddress).toBe(vrms.localWebAddress);
    expect(a.redirectUris).toEqual([
      `http://localhost:3000${vrms.callbackPath}`,
    ]);
  });

  it('takes the web address and gateway from env, trimming slashes', () => {
    const a = addressesFor(vrms, {
      CLIENT_VRMS_WEB_ADDRESS: ' https://vrms.example.com/// ',
      API_PUBLIC_URL: 'https://api.example.com/',
    });
    expect(a.webAddress).toBe('https://vrms.example.com');
    expect(a.redirectUris).toEqual([
      `https://api.example.com${vrms.callbackPath}`,
    ]);
  });

  it('reads the portal address from PORTAL_URL', () => {
    expect(
      addressesFor(portal, { PORTAL_URL: 'https://portal.example.com/' })
        .webAddress,
    ).toBe('https://portal.example.com');
  });

  it('gives a client with no callback no redirect address', () => {
    const service = CLIENTS.find((c) => !c.callbackPath)!;
    expect(addressesFor(service, {}).redirectUris).toEqual([]);
  });
});

describe('parseClientJwks', () => {
  it('accepts one or two public keys', () => {
    expect(parseClientJwks('X', JSON.stringify({ keys: [publicKey] }))).toEqual(
      {
        keys: [publicKey],
      },
    );
    expect(() =>
      parseClientJwks('X', JSON.stringify({ keys: [publicKey, publicKey] })),
    ).not.toThrow();
  });

  it('refuses bad JSON, no keys and three keys', () => {
    expect(() => parseClientJwks('X', 'nope')).toThrow('X is not valid JSON');
    expect(() => parseClientJwks('X', '{"keys":[]}')).toThrow(
      'one or two keys',
    );
    expect(() =>
      parseClientJwks(
        'X',
        JSON.stringify({ keys: [publicKey, publicKey, publicKey] }),
      ),
    ).toThrow('one or two keys');
  });

  it('refuses a private key', () => {
    expect(() =>
      parseClientJwks(
        'X',
        JSON.stringify({ keys: [{ ...publicKey, d: 'secret' }] }),
      ),
    ).toThrow('holds a private key');
  });

  it('refuses a key that is not EC P-256 ES256 with a kid', () => {
    for (const bad of [
      { ...publicKey, kty: 'RSA' },
      { ...publicKey, crv: 'P-384' },
      { ...publicKey, alg: 'RS256' },
      { ...publicKey, kid: undefined },
    ]) {
      expect(() =>
        parseClientJwks('X', JSON.stringify({ keys: [bad] })),
      ).toThrow('public EC P-256 key');
    }
  });
});

describe('checkAllowedRoles', () => {
  const catalog = [
    { system: 'VRMS' as const, code: 'ADMIN' },
    { system: 'VRMS' as const, code: 'MECHANIC' },
  ];
  const client = (allowedRoles: Record<string, string[]>) =>
    ({ ...CLIENTS[0], id: 'c', allowedRoles }) as (typeof CLIENTS)[number];

  it('passes when every allowed role is in the catalog', () => {
    expect(() =>
      checkAllowedRoles([client({ VRMS: ['ADMIN'] })], catalog),
    ).not.toThrow();
  });

  it('names every role that is not, before anything is written', () => {
    expect(() =>
      checkAllowedRoles([client({ VRMS: ['ADMIN', 'DRIVER'] })], catalog),
    ).toThrow("c: VRMS has no role 'DRIVER'");
  });

  it('refuses an empty catalog with a hint to migrate', () => {
    expect(() => checkAllowedRoles([], [])).toThrow('npm run db:deploy');
  });
});
