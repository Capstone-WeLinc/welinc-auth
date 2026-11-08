import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { jwtVerify, SignJWT, type JWTPayload } from 'jose';
import type { SigningKeyRing } from '../keys/signing-keys';
import {
  AUTH_AUDIENCE,
  CLOCK_LEEWAY_SECONDS,
  SIGNING_KEY_RING,
  TOKEN_SETTINGS,
  USER_AUDIENCES,
  type TokenSettings,
  type UserAudience,
} from './token-config';

export type TokenRole = { role: string; system: string };

/** A checked user access token (spec 0001 section 5). */
export type VerifiedUserToken = {
  tokenUse: 'user';
  sub: string;
  email: string;
  aud: UserAudience;
  clientId: string;
  roles: TokenRole[];
  jti: string;
  /** The session id (spec 0003, AC-1). Absent only on the S2 interim token, which no route accepts. */
  sid: string | null;
  /** Expiry, seconds since the epoch. */
  exp: number;
};

/** A checked service access token, `aud: AUTH` (spec 0001 section 5). */
export type VerifiedServiceToken = {
  tokenUse: 'service';
  sub: string;
  clientId: string;
  scopes: string[];
  jti: string;
};

export type VerifiedToken = VerifiedUserToken | VerifiedServiceToken;

/** Any token welinc-auth won't accept. The reason is for logs and tests, never for the caller. */
export class TokenRejectedError extends Error {
  constructor(readonly reason: string) {
    super(`token rejected: ${reason}`);
    this.name = 'TokenRejectedError';
  }

  /** A good token past its `exp`: answered 401 `TOKEN_EXPIRED` (spec 0003, AC-27). */
  get expired(): boolean {
    return this.reason === 'ERR_JWT_EXPIRED';
  }
}

/** The one place welinc-auth signs and checks access tokens (spec 0002, AC-1, AC-6, AC-8). */
@Injectable()
export class TokenService {
  constructor(
    @Inject(SIGNING_KEY_RING) private readonly ring: SigningKeyRing,
    @Inject(TOKEN_SETTINGS) readonly settings: TokenSettings,
  ) {}

  /** A user access token for one system, from one session (spec 0001 section 5, spec 0003 AC-1). */
  async signUserToken(input: {
    sub: string;
    email: string;
    aud: UserAudience;
    roles: TokenRole[];
    sid: string;
    clientId: string;
  }): Promise<string> {
    return this.sign(
      {
        client_id: input.clientId,
        sid: input.sid,
        token_use: 'user',
        email: input.email,
        roles: input.roles,
      },
      input.sub,
      input.aud,
      this.settings.accessTokenMinutes,
    );
  }

  /** A client credentials token (AC-14). */
  async signServiceToken(input: {
    clientId: string;
    aud: string;
    scopes: string[];
  }): Promise<{ token: string; jti: string; expiresIn: number }> {
    const jti = randomUUID();
    const token = await this.sign(
      {
        client_id: input.clientId,
        token_use: 'service',
        scope: input.scopes.join(' '),
      },
      `client:${input.clientId}`,
      input.aud,
      this.settings.serviceTokenMinutes,
      jti,
    );
    return { token, jti, expiresIn: this.settings.serviceTokenMinutes * 60 };
  }

  /** The `kid` that signs new tokens, for log lines (AC-27). */
  get currentKid(): string {
    return this.ring.current.kid;
  }

  private sign(
    claims: JWTPayload,
    sub: string,
    aud: string,
    lifeMinutes: number,
    jti: string = randomUUID(),
  ): Promise<string> {
    return new SignJWT(claims)
      .setProtectedHeader({
        alg: 'ES256',
        kid: this.ring.current.kid,
        typ: 'at+jwt',
      })
      .setIssuer(this.settings.issuer)
      .setSubject(sub)
      .setAudience(aud)
      .setIssuedAt()
      .setExpirationTime(`${lifeMinutes}m`)
      .setJti(jti)
      .sign(this.ring.current.privateKey);
  }

  /**
   * Checks a bearer token against welinc-auth's own public keys in memory (AC-8). Only ES256,
   * `typ: at+jwt`, this issuer and a single string `aud`; a user token for a system, or a
   * service token for `AUTH`. Anything else throws `TokenRejectedError`.
   */
  async verify(token: string): Promise<VerifiedToken> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, this.ring.verifyKeys, {
        algorithms: ['ES256'],
        typ: 'at+jwt',
        issuer: this.settings.issuer,
        clockTolerance: CLOCK_LEEWAY_SECONDS,
        requiredClaims: ['exp', 'sub', 'aud', 'jti'],
      }));
    } catch (error) {
      throw new TokenRejectedError(
        (error as { code?: string }).code ?? 'invalid',
      );
    }

    const { aud, sub, jti } = payload;
    if (typeof aud !== 'string') throw new TokenRejectedError('aud_not_single');
    if (typeof sub !== 'string' || typeof jti !== 'string') {
      throw new TokenRejectedError('bad_claims');
    }
    const clientId = payload['client_id'];
    if (typeof clientId !== 'string')
      throw new TokenRejectedError('no_client_id');

    if (payload['token_use'] === 'user') {
      if (!USER_AUDIENCES.includes(aud as UserAudience)) {
        throw new TokenRejectedError('bad_audience');
      }
      const email = payload['email'];
      const roles = payload['roles'];
      const sid = payload['sid'];
      if (typeof email !== 'string' || !Array.isArray(roles)) {
        throw new TokenRejectedError('bad_claims');
      }
      return {
        tokenUse: 'user',
        sub,
        email,
        aud: aud as UserAudience,
        clientId,
        roles: roles as TokenRole[],
        jti,
        sid: typeof sid === 'string' && sid !== '' ? sid : null,
        exp: payload.exp as number,
      };
    }

    if (payload['token_use'] === 'service') {
      if (aud !== AUTH_AUDIENCE) throw new TokenRejectedError('bad_audience');
      const scope = payload['scope'];
      if (typeof scope !== 'string') throw new TokenRejectedError('bad_claims');
      return {
        tokenUse: 'service',
        sub,
        clientId,
        scopes: scope.split(' ').filter(Boolean),
        jti,
      };
    }

    throw new TokenRejectedError('no_token_use');
  }
}
