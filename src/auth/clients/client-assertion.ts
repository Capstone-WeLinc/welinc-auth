import {
  compactVerify,
  createLocalJWKSet,
  decodeJwt,
  decodeProtectedHeader,
  type JSONWebKeySet,
} from 'jose';
import { CLOCK_LEEWAY_SECONDS } from '../tokens/token-config';

/** The longest life a client assertion may have, in seconds (spec 0001 section 5). */
export const MAX_ASSERTION_SECONDS = 60;

/** Why an assertion was refused. Logged, never sent to the caller (AC-27). */
export type AssertionRefusal =
  | 'malformed'
  | 'unknown_client'
  | 'client_inactive'
  | 'client_id_mismatch'
  | 'bad_header'
  | 'unknown_kid'
  | 'bad_signature'
  | 'sub_mismatch'
  | 'bad_audience'
  | 'expired'
  | 'iat_missing'
  | 'iat_in_future'
  | 'not_yet_valid'
  | 'lifetime_too_long'
  | 'bad_jti'
  | 'jti_reused';

export class AssertionRefusedError extends Error {
  constructor(
    readonly reason: AssertionRefusal,
    /** The client id the assertion claimed, for the log line; may be anything a caller sent. */
    readonly claimedClient: string,
  ) {
    super(`client assertion refused: ${reason}`);
    this.name = 'AssertionRefusedError';
  }
}

export type AssertionClient = {
  id: string;
  isActive: boolean;
  jwks: unknown;
};

export type CheckedAssertion = {
  clientId: string;
  jti: string;
  /** The assertion's `exp`, which becomes the replay row's `expiresAt` (AC-17). */
  expiresAt: Date;
  kid: string;
};

/** A claimed id made safe for a log line: printable, short. */
export function logSafe(value: unknown): string {
  if (typeof value !== 'string' || value === '') return '-';
  return value.replace(/[^\w.:@-]/g, '?').slice(0, 64);
}

function clientKeys(jwks: unknown): JSONWebKeySet | null {
  const keys = (jwks as { keys?: unknown } | null)?.keys;
  return Array.isArray(keys) && keys.length > 0
    ? (jwks as JSONWebKeySet)
    : null;
}

/**
 * Checks a `private_key_jwt` client assertion in the order of spec 0002, AC-15; the first failure
 * throws. `findClient` loads the registry row for the claimed `iss`.
 */
export async function checkAssertion(
  assertion: string,
  options: {
    issuer: string;
    /** The optional `client_id` form field, which must equal `iss` (AC-14). */
    clientIdField?: string;
    findClient: (id: string) => Promise<AssertionClient | null>;
    nowSeconds?: number;
  },
): Promise<CheckedAssertion> {
  // 1. Read the claims without trusting them; iss must name an active client with keys
  let claims: ReturnType<typeof decodeJwt>;
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    claims = decodeJwt(assertion);
    header = decodeProtectedHeader(assertion);
  } catch {
    throw new AssertionRefusedError(
      'malformed',
      logSafe(options.clientIdField),
    );
  }
  const iss = claims.iss;
  const claimed = logSafe(iss ?? options.clientIdField);
  const refuse = (reason: AssertionRefusal) =>
    new AssertionRefusedError(reason, claimed);

  if (typeof iss !== 'string' || iss === '') throw refuse('malformed');
  if (options.clientIdField !== undefined && options.clientIdField !== iss) {
    throw refuse('client_id_mismatch');
  }
  const client = await options.findClient(iss);
  if (!client) throw refuse('unknown_client');
  const keys = clientKeys(client.jwks);
  if (!client.isActive || !keys) throw refuse('client_inactive');

  // 2. ES256, typ JWT, and a kid the client registered
  if (header.alg !== 'ES256' || header.typ !== 'JWT')
    throw refuse('bad_header');
  if (
    typeof header.kid !== 'string' ||
    !keys.keys.some((key) => key.kid === header.kid)
  ) {
    throw refuse('unknown_kid');
  }

  // 3. The signature, with that key
  try {
    await compactVerify(assertion, createLocalJWKSet(keys), {
      algorithms: ['ES256'],
    });
  } catch {
    throw refuse('bad_signature');
  }

  // 4. sub equals iss
  if (claims.sub !== iss) throw refuse('sub_mismatch');

  // 5. aud is the single string <issuer>/token
  if (claims.aud !== `${options.issuer}/token`) throw refuse('bad_audience');

  // 6. Time: exp in the future, iat present and not later than now, nbf not later than now,
  // at most 60 s of life. The leeway applies to each comparison with the clock.
  const now = options.nowSeconds ?? Math.floor(Date.now() / 1000);
  const { exp, iat, nbf } = claims;
  if (typeof exp !== 'number' || exp <= now - CLOCK_LEEWAY_SECONDS)
    throw refuse('expired');
  if (typeof iat !== 'number') throw refuse('iat_missing');
  if (iat > now + CLOCK_LEEWAY_SECONDS) throw refuse('iat_in_future');
  if (
    nbf !== undefined &&
    (typeof nbf !== 'number' || nbf > now + CLOCK_LEEWAY_SECONDS)
  ) {
    throw refuse('not_yet_valid');
  }
  if (exp - iat > MAX_ASSERTION_SECONDS) throw refuse('lifetime_too_long');

  // 7. A jti of 1 to 128 characters
  const jti = claims.jti;
  if (typeof jti !== 'string' || jti.length < 1 || jti.length > 128)
    throw refuse('bad_jti');

  return {
    clientId: iss,
    jti,
    expiresAt: new Date(exp * 1000),
    kid: header.kid,
  };
}
