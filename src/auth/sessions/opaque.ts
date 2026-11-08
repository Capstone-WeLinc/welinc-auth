import {
  createCipheriv,
  createDecipheriv,
  createHash,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
} from 'crypto';

/**
 * Opaque values (spec 0001 section 5): refresh tokens, SSO handles, login requests and codes.
 * Each is 256 random bits, base64url. Only its SHA-256 is stored.
 */
export function newOpaque(): string {
  return randomBytes(32).toString('base64url');
}

/** SHA-256 hex, the stored form of every opaque value. */
export function hashOpaque(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/** A value as callers send it: base64url, 43 characters (32 bytes). Anything else can't match. */
export function isOpaqueShape(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

/** PKCE S256 (RFC 7636): the verifier is 43 to 128 unreserved characters. */
export function isPkceVerifier(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9._~-]{43,128}$/.test(value);
}

/** The S256 challenge is 43 base64url characters (AC-13). */
export function isPkceChallenge(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
}

export function pkceMatches(verifier: string, challenge: string): boolean {
  const computed = Buffer.from(
    createHash('sha256').update(verifier, 'ascii').digest('base64url'),
  );
  const expected = Buffer.from(challenge);
  return (
    computed.length === expected.length && timingSafeEqual(computed, expected)
  );
}

const GRACE_INFO = 'welinc-refresh-grace';
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

function graceKey(presentedToken: string, rowId: string): Buffer {
  return Buffer.from(
    hkdfSync(
      'sha256',
      Buffer.from(presentedToken, 'utf8'),
      Buffer.from(rowId, 'utf8'),
      Buffer.from(GRACE_INFO, 'utf8'),
      32,
    ),
  );
}

/**
 * The grace cipher (spec 0003, rotation step 4): the child token, AES-256-GCM, with the key
 * HKDF-SHA256(the old token, salt = the old row's id). Only the holder of the old token can open
 * it; the database alone can't. Layout: nonce (12) | ciphertext | tag (16).
 */
export function sealGrace(
  childToken: string,
  presentedToken: string,
  rowId: string,
): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(
    'aes-256-gcm',
    graceKey(presentedToken, rowId),
    nonce,
  );
  const body = Buffer.concat([
    cipher.update(childToken, 'utf8'),
    cipher.final(),
  ]);
  return Buffer.concat([nonce, body, cipher.getAuthTag()]);
}

/** Opens the grace cipher, or null when it doesn't open with this token. */
export function openGrace(
  sealed: Uint8Array,
  presentedToken: string,
  rowId: string,
): string | null {
  const data = Buffer.from(sealed);
  if (data.length <= NONCE_BYTES + TAG_BYTES) return null;
  try {
    const decipher = createDecipheriv(
      'aes-256-gcm',
      graceKey(presentedToken, rowId),
      data.subarray(0, NONCE_BYTES),
    );
    decipher.setAuthTag(data.subarray(data.length - TAG_BYTES));
    return Buffer.concat([
      decipher.update(data.subarray(NONCE_BYTES, data.length - TAG_BYTES)),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return null;
  }
}
