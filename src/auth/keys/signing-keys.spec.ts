import { describe, it, expect } from '@jest/globals';
import { exportJWK, generateKeyPair } from 'jose';
import { testSigningJwk } from '../testing/test-keys';
import { publicJwk, SigningKeyRing, SigningKeysError } from './signing-keys';

const load = (value: unknown) =>
  SigningKeyRing.load(
    typeof value === 'string' ? value : JSON.stringify(value),
  );

// covers: spec 0002 AC-2 (refuse to start on a bad key set), AC-3 (public part only)
describe('SigningKeyRing.load', () => {
  it('loads one current key and publishes only its public part', async () => {
    const current = await testSigningJwk('auth-a', 'current');
    const next = await testSigningJwk('auth-b', 'next');
    const ring = await load({ keys: [current, next] });

    expect(ring.current.kid).toBe('auth-a');
    expect(ring.publicSet.keys.map((key) => key.kid)).toEqual([
      'auth-a',
      'auth-b',
    ]);
    for (const key of ring.publicSet.keys) {
      expect(key).not.toHaveProperty('d');
      expect(key).not.toHaveProperty('status');
      expect(key).toMatchObject({
        kty: 'EC',
        crv: 'P-256',
        alg: 'ES256',
        use: 'sig',
      });
    }
  });

  it.each([
    ['missing', undefined, /missing/],
    ['empty', '', /missing/],
    ['not JSON', '{nope', /not valid JSON/],
    ['no keys list', {}, /non empty "keys"/],
  ])('refuses a value that is %s', async (_name, value, message) => {
    await expect(
      SigningKeyRing.load(
        value === undefined
          ? undefined
          : typeof value === 'string'
            ? value
            : JSON.stringify(value),
      ),
    ).rejects.toThrow(message);
  });

  it('refuses no current key and two current keys', async () => {
    const a = await testSigningJwk('auth-a', 'next');
    const b = await testSigningJwk('auth-b', 'current');
    const c = await testSigningJwk('auth-c', 'current');
    await expect(load({ keys: [a] })).rejects.toThrow(/exactly one.*found 0/);
    await expect(load({ keys: [b, c] })).rejects.toThrow(
      /exactly one.*found 2/,
    );
  });

  it('refuses a public only key, a wrong alg or use, a bad status and a shared kid', async () => {
    const key = await testSigningJwk('auth-a');
    const publicOnly = { ...key, d: undefined };
    await expect(load({ keys: [publicOnly] })).rejects.toThrow(/public key/);
    await expect(load({ keys: [{ ...key, alg: 'ES384' }] })).rejects.toThrow(
      /alg "ES256"/,
    );
    await expect(load({ keys: [{ ...key, use: 'enc' }] })).rejects.toThrow(
      /use "sig"/,
    );
    await expect(load({ keys: [{ ...key, status: 'old' }] })).rejects.toThrow(
      /status "old"/,
    );
    const twin = await testSigningJwk('auth-a', 'next');
    await expect(load({ keys: [key, twin] })).rejects.toThrow(/share the kid/);
  });

  it('refuses a key that is not EC P-256', async () => {
    const { privateKey } = await generateKeyPair('RS256', {
      extractable: true,
    });
    const rsa = {
      ...(await exportJWK(privateKey)),
      kid: 'auth-rsa',
      alg: 'ES256',
      status: 'current',
    };
    await expect(load({ keys: [rsa] })).rejects.toThrow(/EC P-256/);
  });

  it('fails the self test when the private part does not match the public part', async () => {
    const key = await testSigningJwk('auth-a');
    const other = await testSigningJwk('auth-b');
    await expect(load({ keys: [{ ...key, d: other.d }] })).rejects.toThrow(
      /does not match its public part|self test/,
    );
  });

  it('never puts key material in the error message', async () => {
    const key = await testSigningJwk('auth-a');
    const error = await load({ keys: [{ ...key, alg: 'HS256' }] }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(SigningKeysError);
    expect((error as Error).message).not.toContain(key.d!);
    expect((error as Error).message).not.toContain(key.x!);
  });
});

describe('publicJwk', () => {
  it('strips the private member and the rotation bookkeeping', async () => {
    const key = {
      ...(await testSigningJwk('auth-a', 'retired')),
      addedAt: '2026-11-01T00:00:00Z',
      retiredAt: '2026-11-08T00:00:00Z',
    };
    expect(Object.keys(publicJwk(key)).sort()).toEqual(
      ['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y'].sort(),
    );
  });
});
