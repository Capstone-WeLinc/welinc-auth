import {
  createLocalJWKSet,
  importJWK,
  jwtVerify,
  SignJWT,
  type CryptoKey,
  type JSONWebKeySet,
  type JWK,
} from 'jose';

/** The states a signing key moves through (spec 0002, State transitions). */
export const KEY_STATUSES = ['current', 'next', 'retired'] as const;
export type KeyStatus = (typeof KEY_STATUSES)[number];

/** One private JWK from `AUTH_SIGNING_KEYS`, with the extra members the rotation script writes. */
export type SigningKeyJwk = JWK & {
  kid: string;
  status: KeyStatus;
  addedAt?: string;
  retiredAt?: string;
};

export type SigningKeySet = { keys: SigningKeyJwk[] };

/** Members that never leave welinc-auth: the private part and the rotation bookkeeping. */
const PRIVATE_MEMBERS = ['d', 'status', 'addedAt', 'retiredAt'] as const;

/** Raised for any problem with `AUTH_SIGNING_KEYS`. The message names the problem, never a key. */
export class SigningKeysError extends Error {
  constructor(problem: string) {
    super(`AUTH_SIGNING_KEYS: ${problem}`);
    this.name = 'SigningKeysError';
  }
}

/**
 * Parses and checks `AUTH_SIGNING_KEYS` without importing any key (spec 0002, AC-2). Shared by
 * the service at startup and by the keys scripts, so both refuse the same bad sets.
 */
export function parseSigningKeys(raw: string | undefined): SigningKeySet {
  if (!raw || raw.trim() === '') {
    throw new SigningKeysError('missing. Run `npm run keys:dev` locally.');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SigningKeysError('not valid JSON');
  }

  const keys = (parsed as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new SigningKeysError(
      'must be an object with a non empty "keys" list',
    );
  }

  const seen = new Set<string>();
  keys.forEach((key: unknown, index) => {
    const where = `key ${index + 1}`;
    if (typeof key !== 'object' || key === null) {
      throw new SigningKeysError(`${where} is not an object`);
    }
    const jwk = key as Record<string, unknown>;
    const kid = jwk['kid'];
    if (typeof kid !== 'string' || kid === '') {
      throw new SigningKeysError(`${where} has no kid`);
    }
    const named = `key "${kid}"`;
    if (seen.has(kid)) {
      throw new SigningKeysError(`two keys share the kid "${kid}"`);
    }
    seen.add(kid);
    if (
      jwk['kty'] !== 'EC' ||
      jwk['crv'] !== 'P-256' ||
      typeof jwk['x'] !== 'string' ||
      typeof jwk['y'] !== 'string'
    ) {
      throw new SigningKeysError(`${named} is not an EC P-256 key`);
    }
    if (typeof jwk['d'] !== 'string' || jwk['d'] === '') {
      throw new SigningKeysError(
        `${named} is a public key, a private key is needed`,
      );
    }
    if (jwk['alg'] !== 'ES256') {
      throw new SigningKeysError(`${named} must have alg "ES256"`);
    }
    if (jwk['use'] !== undefined && jwk['use'] !== 'sig') {
      throw new SigningKeysError(`${named} must have use "sig"`);
    }
    if (!KEY_STATUSES.includes(jwk['status'] as KeyStatus)) {
      throw new SigningKeysError(
        `${named} has status "${String(jwk['status'])}", expected one of ${KEY_STATUSES.join(', ')}`,
      );
    }
  });

  const set = { keys: keys as SigningKeyJwk[] };
  const current = set.keys.filter((key) => key.status === 'current').length;
  if (current !== 1) {
    throw new SigningKeysError(
      `exactly one key must have status "current", found ${current}`,
    );
  }
  return set;
}

/** The public part of a private JWK, as published in the JWKS (spec 0002, AC-3). */
export function publicJwk(key: SigningKeyJwk): JWK {
  const copy: Record<string, unknown> = { ...key };
  for (const member of PRIVATE_MEMBERS) delete copy[member];
  return { ...copy, alg: 'ES256', use: 'sig' };
}

export type LoadedSigningKey = {
  kid: string;
  status: KeyStatus;
  privateKey: CryptoKey;
};

/**
 * welinc-auth's signing keys, imported and self tested. Built once at startup: `load` throws a
 * `SigningKeysError` on any problem, which stops the service before it listens.
 */
export class SigningKeyRing {
  private constructor(
    readonly keys: LoadedSigningKey[],
    readonly current: LoadedSigningKey,
    /** What `GET /auth/.well-known/jwks.json` answers. */
    readonly publicSet: JSONWebKeySet,
    /** Verifies welinc-auth's own tokens in memory, with no HTTP call (AC-8). */
    readonly verifyKeys: ReturnType<typeof createLocalJWKSet>,
  ) {}

  static async load(raw: string | undefined): Promise<SigningKeyRing> {
    const set = parseSigningKeys(raw);
    const publicSet: JSONWebKeySet = { keys: set.keys.map(publicJwk) };
    const verifyKeys = createLocalJWKSet(publicSet);

    const loaded: LoadedSigningKey[] = [];
    for (const jwk of set.keys) {
      let privateKey: CryptoKey;
      try {
        privateKey = (await importJWK(
          { ...publicJwk(jwk), d: jwk.d },
          'ES256',
        )) as CryptoKey;
      } catch {
        throw new SigningKeysError(
          `key "${jwk.kid}" could not be imported: it is damaged or its private part does not match its public part`,
        );
      }
      await selfTest(jwk.kid, privateKey, verifyKeys);
      loaded.push({ kid: jwk.kid, status: jwk.status, privateKey });
    }

    const current = loaded.find((key) => key.status === 'current')!;
    return new SigningKeyRing(loaded, current, publicSet, verifyKeys);
  }
}

/** Signs and checks a throwaway token, which catches a private part that doesn't match its public part. */
async function selfTest(
  kid: string,
  privateKey: CryptoKey,
  verifyKeys: ReturnType<typeof createLocalJWKSet>,
): Promise<void> {
  try {
    const token = await new SignJWT({ selfTest: true })
      .setProtectedHeader({ alg: 'ES256', kid })
      .setIssuedAt()
      .setExpirationTime('1m')
      .sign(privateKey);
    await jwtVerify(token, verifyKeys, { algorithms: ['ES256'] });
  } catch {
    throw new SigningKeysError(
      `key "${kid}" failed the self test: its private part doesn't match its public part`,
    );
  }
}
