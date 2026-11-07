import { exportJWK, generateKeyPair } from 'jose';
import type { SigningKeyJwk, KeyStatus } from '../keys/signing-keys';
import { SigningKeyRing } from '../keys/signing-keys';
import { TokenService } from '../tokens/token.service';
import type { TokenSettings } from '../tokens/token-config';

/** Test only: made fresh each run, never written to any env file (spec 0002, task 1a). */
export const TEST_ISSUER = 'http://localhost:3000/auth';

export const TEST_SETTINGS: TokenSettings = {
  issuer: TEST_ISSUER,
  accessTokenMinutes: 15,
  serviceTokenMinutes: 5,
};

export async function testSigningJwk(
  kid: string,
  status: KeyStatus = 'current',
): Promise<SigningKeyJwk> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  return {
    ...(await exportJWK(privateKey)),
    kid,
    alg: 'ES256',
    use: 'sig',
    status,
  };
}

export async function testRing(
  ...keys: SigningKeyJwk[]
): Promise<SigningKeyRing> {
  const set =
    keys.length > 0 ? keys : [await testSigningJwk('auth-test-current')];
  return SigningKeyRing.load(JSON.stringify({ keys: set }));
}

export async function testTokenService(
  ring?: SigningKeyRing,
): Promise<TokenService> {
  return new TokenService(ring ?? (await testRing()), TEST_SETTINGS);
}
