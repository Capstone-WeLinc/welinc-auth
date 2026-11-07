import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { newKid } from '../src/auth/keys/kid';

/** A fresh ES256 key pair as JWKs, both carrying `kid`, `alg` and `use`. */
export async function newKeyPair(
  purpose: string,
): Promise<{ kid: string; privateJwk: JWK; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', {
    extractable: true,
  });
  const kid = newKid(purpose);
  const meta = { kid, alg: 'ES256', use: 'sig' };
  return {
    kid,
    privateJwk: { ...(await exportJWK(privateKey)), ...meta },
    publicJwk: { ...(await exportJWK(publicKey)), ...meta },
  };
}
