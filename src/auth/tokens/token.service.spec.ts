import { describe, it, expect, beforeAll } from '@jest/globals';
import { createHmac } from 'crypto';
import {
  decodeProtectedHeader,
  decodeJwt,
  SignJWT,
  type JWTPayload,
} from 'jose';
import type { SigningKeyRing } from '../keys/signing-keys';
import {
  TEST_ISSUER,
  testRing,
  testSigningJwk,
  testTokenService,
} from '../testing/test-keys';
import { TokenRejectedError, TokenService } from './token.service';

const b64 = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');

async function reason(promise: Promise<unknown>): Promise<string> {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(TokenRejectedError);
  return (error as TokenRejectedError).reason;
}

// covers: spec 0002 AC-1 (ES256, kid, typ), AC-6 (login claims), AC-8 (what welinc-auth accepts)
describe('TokenService', () => {
  let ring: SigningKeyRing;
  let tokens: TokenService;

  /** Signs with the ring's current key, so only the claims or header under test are wrong. */
  const signRaw = (
    claims: JWTPayload,
    header: Record<string, unknown> = {},
    exp: string | number = '5m',
  ) =>
    new SignJWT({ iss: TEST_ISSUER, ...claims })
      .setProtectedHeader({
        alg: 'ES256',
        kid: ring.current.kid,
        typ: 'at+jwt',
        ...header,
      })
      .setSubject('user-1')
      .setIssuedAt()
      .setExpirationTime(exp)
      .setJti('jti-1')
      .sign(ring.current.privateKey);

  const userClaims = {
    aud: 'VRMS',
    client_id: 'portal',
    token_use: 'user',
    email: 'pedro@welinc.com',
    roles: [{ role: 'MECHANIC', system: 'VRMS' }],
  };

  beforeAll(async () => {
    ring = await testRing(await testSigningJwk('auth-test-a'));
    tokens = await testTokenService(ring);
  });

  // spec 0003 AC-1: every user token carries its sid and the client that got it
  it('signs a user token with ES256, the current kid, its sid and client', async () => {
    const token = await tokens.signUserToken({
      sub: 'user-1',
      email: 'pedro@welinc.com',
      aud: 'VRMS',
      roles: [{ role: 'MECHANIC', system: 'VRMS' }],
      sid: 'sid-1',
      clientId: 'vrms',
    });

    expect(decodeProtectedHeader(token)).toEqual({
      alg: 'ES256',
      kid: 'auth-test-a',
      typ: 'at+jwt',
    });
    const claims = decodeJwt(token);
    expect(claims).toMatchObject({
      iss: TEST_ISSUER,
      sub: 'user-1',
      aud: 'VRMS',
      client_id: 'vrms',
      sid: 'sid-1',
      token_use: 'user',
      email: 'pedro@welinc.com',
      roles: [{ role: 'MECHANIC', system: 'VRMS' }],
    });
    expect(claims.exp! - claims.iat!).toBe(15 * 60);
    expect(claims.jti).toMatch(/^[0-9a-f-]{36}$/);

    await expect(tokens.verify(token)).resolves.toMatchObject({
      tokenUse: 'user',
      aud: 'VRMS',
      sub: 'user-1',
      sid: 'sid-1',
    });
  });

  it('signs and accepts a service token for AUTH', async () => {
    const { token, expiresIn } = await tokens.signServiceToken({
      clientId: 'vrms',
      aud: 'AUTH',
      scopes: ['directory.read'],
    });
    expect(expiresIn).toBe(300);
    expect(decodeJwt(token)).toMatchObject({
      sub: 'client:vrms',
      token_use: 'service',
      scope: 'directory.read',
    });
    await expect(tokens.verify(token)).resolves.toMatchObject({
      tokenUse: 'service',
      clientId: 'vrms',
      scopes: ['directory.read'],
    });
  });

  it('refuses an HS256 token signed with the old shared secret', async () => {
    const header = b64({ alg: 'HS256', typ: 'JWT' });
    const body = b64({
      sub: 'user-1',
      iss: TEST_ISSUER,
      aud: 'VRMS',
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    const sig = createHmac('sha256', 'dev_secret_key_change_in_production')
      .update(`${header}.${body}`)
      .digest('base64url');
    await reason(tokens.verify(`${header}.${body}.${sig}`));
  });

  it('refuses alg none and an HS256 token keyed with the public key', async () => {
    const body = b64({
      ...userClaims,
      sub: 'user-1',
      iss: TEST_ISSUER,
      jti: 'j',
      exp: Math.floor(Date.now() / 1000) + 60,
    });
    await reason(
      tokens.verify(`${b64({ alg: 'none', typ: 'at+jwt' })}.${body}.`),
    );

    const header = b64({ alg: 'HS256', kid: ring.current.kid, typ: 'at+jwt' });
    const publicKey = JSON.stringify(ring.publicSet.keys[0]);
    const sig = createHmac('sha256', publicKey)
      .update(`${header}.${body}`)
      .digest('base64url');
    await reason(tokens.verify(`${header}.${body}.${sig}`));
  });

  it('refuses a token from another issuer, of the wrong typ, or signed by an unknown key', async () => {
    await reason(
      tokens.verify(await signRaw({ ...userClaims, iss: 'http://evil/auth' })),
    );
    await reason(tokens.verify(await signRaw(userClaims, { typ: 'JWT' })));

    const stranger = await testRing(await testSigningJwk('auth-test-a'));
    const forged = await new SignJWT(userClaims)
      .setProtectedHeader({ alg: 'ES256', kid: 'auth-test-a', typ: 'at+jwt' })
      .setIssuer(TEST_ISSUER)
      .setSubject('user-1')
      .setIssuedAt()
      .setExpirationTime('5m')
      .setJti('j')
      .sign(stranger.current.privateKey);
    await reason(tokens.verify(forged));
  });

  it('allows 5 s of clock leeway on exp, not more', async () => {
    const now = Math.floor(Date.now() / 1000);
    await expect(
      tokens.verify(await signRaw(userClaims, {}, now - 3)),
    ).resolves.toBeDefined();
    await reason(tokens.verify(await signRaw(userClaims, {}, now - 10)));
  });

  it('refuses an aud list, a user token for AUTH, a service token for a system and no token_use', async () => {
    expect(
      await reason(
        tokens.verify(await signRaw({ ...userClaims, aud: ['VRMS', 'BMS'] })),
      ),
    ).toBe('aud_not_single');
    expect(
      await reason(
        tokens.verify(await signRaw({ ...userClaims, aud: 'AUTH' })),
      ),
    ).toBe('bad_audience');
    expect(
      await reason(
        tokens.verify(
          await signRaw({
            aud: 'VRMS',
            client_id: 'vrms',
            token_use: 'service',
            scope: 'x',
          }),
        ),
      ),
    ).toBe('bad_audience');
    const noUse = { ...userClaims, token_use: undefined };
    expect(await reason(tokens.verify(await signRaw(noUse)))).toBe(
      'no_token_use',
    );
  });
});
