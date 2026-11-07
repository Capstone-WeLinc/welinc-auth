import { describe, it, expect } from '@jest/globals';
import {
  TEST_ISSUER,
  TEST_SETTINGS,
  testRing,
  testSigningJwk,
} from './testing/test-keys';
import { WellKnownController } from './well-known.controller';

// covers: spec 0002 AC-3 (public keys only), AC-4 (RFC 8414 metadata)
describe('WellKnownController', () => {
  it('publishes every key, public part only', async () => {
    const ring = await testRing(
      await testSigningJwk('auth-a', 'current'),
      await testSigningJwk('auth-b', 'next'),
      {
        ...(await testSigningJwk('auth-c', 'retired')),
        retiredAt: '2026-11-08T00:00:00Z',
      },
    );
    const { keys } = new WellKnownController(ring, TEST_SETTINGS).jwks();
    expect(keys.map((key) => key.kid)).toEqual(['auth-a', 'auth-b', 'auth-c']);
    expect(JSON.stringify(keys)).not.toMatch(/"d"|status|addedAt|retiredAt/);
  });

  it('derives the metadata from the issuer', async () => {
    const meta = new WellKnownController(
      await testRing(),
      TEST_SETTINGS,
    ).metadata();
    expect(meta).toEqual({
      issuer: TEST_ISSUER,
      token_endpoint: `${TEST_ISSUER}/token`,
      jwks_uri: `${TEST_ISSUER}/.well-known/jwks.json`,
      grant_types_supported: ['client_credentials'],
      token_endpoint_auth_methods_supported: ['private_key_jwt'],
      token_endpoint_auth_signing_alg_values_supported: ['ES256'],
    });
  });
});
