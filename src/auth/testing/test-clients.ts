import {
  exportJWK,
  generateKeyPair,
  SignJWT,
  type CryptoKey,
  type JWK,
} from 'jose';
import { TEST_ISSUER } from './test-keys';

/** Test only: a client key pair and assertions signed with it, the way a backend signs them. */
export type TestClient = {
  id: string;
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JWK;
  row: { id: string; isActive: boolean; jwks: unknown };
};

export async function testClient(
  id = 'vrms',
  kid = `${id}-test-1`,
): Promise<TestClient> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', {
    extractable: true,
  });
  const publicJwk = {
    ...(await exportJWK(publicKey)),
    kid,
    alg: 'ES256',
    use: 'sig',
  };
  return {
    id,
    kid,
    privateKey,
    publicJwk,
    row: { id, isActive: true, jwks: { keys: [publicJwk] } },
  };
}

let counter = 0;

/** A valid assertion unless `claims`, `header` or `times` say otherwise. */
export function signAssertion(
  client: TestClient,
  options: {
    claims?: Record<string, unknown>;
    header?: Record<string, unknown>;
    iat?: number;
    exp?: number;
    key?: CryptoKey;
  } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: client.id,
    sub: client.id,
    aud: `${TEST_ISSUER}/token`,
    jti: `jti-${Date.now()}-${counter++}`,
    iat: options.iat ?? now,
    exp: options.exp ?? now + 60,
    ...options.claims,
  })
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'JWT',
      kid: client.kid,
      ...options.header,
    })
    .sign(options.key ?? client.privateKey);
}
