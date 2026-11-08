import {
  HttpStatus,
  Injectable,
  Logger,
  type OnModuleDestroy,
  type OnModuleInit,
} from '@nestjs/common';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import {
  ClientKind,
  Prisma,
  SystemType,
  type OAuthClient,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { TokenService } from '../tokens/token.service';
import {
  AssertionRefusedError,
  checkAssertion,
  logSafe,
  type CheckedAssertion,
} from './client-assertion';
import { invalidClient, oauthError } from './oauth-error';
import { ADDRESS_LIMIT } from './address-throttler.guard';
import { isIP } from 'net';
import {
  UserGrantsService,
  type UserTokenAnswer,
} from '../sessions/user-grants.service';

export const ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** The per client limit, counted after the assertion passes (spec 0003 AC-43; was 60). */
export const CLIENT_LIMIT = { limit: 600, ttlMs: 60_000 };

/** A public native client's refresh: 30 a minute per address (spec 0003, AC-29, AC-38). */
export const PUBLIC_REFRESH_LIMIT = { limit: 30, ttlMs: 60_000 };

/** The grants `/auth/token` knows; each client row lists the ones it may use. */
const GRANTS = ['client_credentials', 'authorization_code', 'refresh_token'];

/**
 * `X-WeLinc-User-Address` (spec 0003 AC-43): the user's address as a system backend saw it.
 * Kept only when it is a plain IP address.
 */
export function userAddressOf(header: unknown): string | null {
  const value: unknown = Array.isArray(header)
    ? (header as unknown[])[0]
    : header;
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length <= 45 && isIP(trimmed) !== 0 ? trimmed : null;
}
/** How often expired replay rows are deleted, and how long past `expiresAt` they're kept (AC-17). */
export const JTI_SWEEP_MS = 10 * 60_000;
export const JTI_GRACE_MS = 60_000;

/** A form field read safely: absent, a repeated field (an array) or an object are all refused. */
export type Form = Record<string, unknown>;

export function field(form: Form, name: string, required: true): string;
export function field(
  form: Form,
  name: string,
  required: false,
): string | undefined;
export function field(
  form: Form,
  name: string,
  required: boolean,
): string | undefined {
  const value = form[name];
  if (value === undefined && !required) return undefined;
  if (typeof value !== 'string' || (required && value === '')) {
    throw oauthError(
      HttpStatus.BAD_REQUEST,
      'invalid_request',
      Array.isArray(value)
        ? `${name} is repeated`
        : `${name} is missing or malformed`,
    );
  }
  return value;
}

export type TokenAnswer = {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  scope: string;
};

/** Raised when the per client limit is used up; the controller turns it into a 429. */
export class ClientRateLimitedError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super('client rate limited');
  }
}

/** Raised when refused assertions from one address pass the address limit. */
export class AddressRateLimitedError extends ClientRateLimitedError {}

/**
 * `POST /auth/token`: client credentials (spec 0002, AC-14 to AC-17, AC-27) and the user grants
 * (spec 0003): the code exchange and refresh token rotation.
 */
@Injectable()
export class TokenEndpointService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger('TokenEndpoint');
  private sweeper: NodeJS.Timeout | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokenService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
    private readonly userGrants: UserGrantsService,
  ) {}

  onModuleInit() {
    this.sweeper = setInterval(() => void this.sweepJtis(), JTI_SWEEP_MS);
    this.sweeper.unref();
  }

  onModuleDestroy() {
    if (this.sweeper) clearInterval(this.sweeper);
  }

  /** Deletes replay rows more than a minute past their expiry (AC-17). */
  async sweepJtis(now = Date.now()): Promise<number> {
    try {
      const { count } = await this.prisma.clientAssertionJti.deleteMany({
        where: { expiresAt: { lt: new Date(now - JTI_GRACE_MS) } },
      });
      return count;
    } catch (error) {
      this.logger.warn(
        `could not sweep used assertion ids: ${(error as Error).message}`,
      );
      return 0;
    }
  }

  /**
   * Every grant (spec 0002 AC-14 to AC-18, spec 0003 AC-7 to AC-15, AC-43). The client proves
   * itself first with its assertion; only then does the grant type pick the path.
   * `userAddressHeader` is `X-WeLinc-User-Address`, trusted only once the assertion passes.
   */
  async grant(
    form: Form,
    address: string,
    userAddressHeader?: unknown,
  ): Promise<TokenAnswer | UserTokenAnswer> {
    const grantType = field(form, 'grant_type', true);
    if (
      form['client_assertion'] === undefined &&
      form['client_assertion_type'] === undefined
    ) {
      // A public native client (`vmms-mobile`) holds no secret: it names itself (AC-29)
      return this.publicGrant(form, grantType, address);
    }
    const { checked, client } = await this.proveClient(form, address);
    const clientId = checked.clientId;
    const refuseGrant = (error: string, description: string) => {
      this.logger.warn(
        `refused grant client=${clientId} reason=${error} ip=${logSafe(address)}`,
      );
      return oauthError(HttpStatus.BAD_REQUEST, error, description);
    };
    if (!GRANTS.includes(grantType)) {
      throw refuseGrant(
        'unsupported_grant_type',
        `Supported grants: ${GRANTS.join(', ')}`,
      );
    }
    if (!client.grants.includes(grantType)) {
      throw refuseGrant(
        'unauthorized_client',
        `This client may not use ${grantType}`,
      );
    }

    if (grantType === 'client_credentials') {
      return this.clientCredentials(form, checked, refuseGrant);
    }

    // The user grants record the jti before acting, so an assertion can't be used twice
    await this.recordJti(checked, address);
    const userAddress = userAddressOf(userAddressHeader);
    if (grantType === 'authorization_code') {
      return this.userGrants.exchangeCode(
        client,
        {
          code: field(form, 'code', true),
          redirectUri: field(form, 'redirect_uri', true),
          verifier: field(form, 'code_verifier', true),
        },
        userAddress,
      );
    }
    if (field(form, 'audience', false) !== undefined) {
      // Only a public native client may name an audience (spec 0003, AC-29)
      throw refuseGrant(
        'invalid_target',
        'This client may not name an audience',
      );
    }
    return this.userGrants.refresh(
      client,
      { refreshToken: field(form, 'refresh_token', true) },
      userAddress,
    );
  }

  /**
   * The refresh grant for a public native client (spec 0003, AC-29, AC-38): no assertion, so
   * every call counts 30 a minute per address before anything is looked up. The client may name
   * an `audience` its row lists; the user's roles there are checked by the grant itself.
   * `last_seen_ip` is the request's own address.
   */
  private async publicGrant(
    form: Form,
    grantType: string,
    address: string,
  ): Promise<UserTokenAnswer> {
    const hit = await this.storage.increment(
      `public-refresh:${address}`,
      PUBLIC_REFRESH_LIMIT.ttlMs,
      PUBLIC_REFRESH_LIMIT.limit,
      0,
      'public-refresh',
    );
    if (hit.totalHits > PUBLIC_REFRESH_LIMIT.limit) {
      this.logger.warn(`rate limited public refresh ip=${logSafe(address)}`);
      throw new AddressRateLimitedError(
        Math.max(1, Math.ceil(hit.timeToExpire)),
      );
    }

    const clientId = field(form, 'client_id', true);
    const client = await this.publicClient(clientId);
    if (!client) {
      this.refused(logSafe(clientId), 'not_a_public_client', address);
      throw invalidClient();
    }
    const refuseGrant = (error: string, description: string) => {
      this.logger.warn(
        `refused grant client=${client.id} reason=${error} ip=${logSafe(address)}`,
      );
      return oauthError(HttpStatus.BAD_REQUEST, error, description);
    };
    if (grantType !== 'refresh_token' || !client.grants.includes(grantType)) {
      throw refuseGrant(
        'unauthorized_client',
        `This client may not use ${logSafe(grantType)}`,
      );
    }

    const audience = field(form, 'audience', false);
    if (
      audience !== undefined &&
      !(
        client.userAudiences.includes(audience) &&
        (Object.values(SystemType) as string[]).includes(audience)
      )
    ) {
      throw refuseGrant(
        'invalid_target',
        `This client may not ask for ${logSafe(audience)}`,
      );
    }
    return this.userGrants.refresh(
      client,
      {
        refreshToken: field(form, 'refresh_token', true),
        audience: audience as SystemType | undefined,
      },
      isIP(address) !== 0 ? address : null,
    );
  }

  /**
   * An active public native client (spec 0001 section 4), by the id it names. These clients
   * hold no secret, so this proves nothing about the caller: their routes rely on the user's
   * password or refresh token, plus the per address limits.
   */
  async publicClient(clientId: unknown): Promise<OAuthClient | null> {
    if (typeof clientId !== 'string' || clientId.length > 64) return null;
    const client = await this.prisma.oAuthClient.findUnique({
      where: { id: clientId },
    });
    return client?.kind === ClientKind.PUBLIC_NATIVE && client.isActive
      ? client
      : null;
  }

  /**
   * A confidential client proving itself outside `/auth/token` (spec 0003, AC-42, AC-43):
   * `/auth/logout` and `/auth/session/activity` with the same form fields. The assertion's
   * `jti` is used up here, so it can't be replayed.
   */
  async assertClient(form: Form, address: string): Promise<OAuthClient> {
    const { checked, client } = await this.proveClient(form, address);
    await this.recordJti(checked, address);
    return client;
  }

  /**
   * The client proves who it is (spec 0002 AC-15; every failure looks the same from outside),
   * then counts against its per client limit (spec 0003 AC-43). The jti is not recorded here.
   */
  private async proveClient(
    form: Form,
    address: string,
  ): Promise<{ checked: CheckedAssertion; client: OAuthClient }> {
    const assertionType = field(form, 'client_assertion_type', true);
    const assertion = field(form, 'client_assertion', true);
    const clientIdField = field(form, 'client_id', false);
    if (assertionType !== ASSERTION_TYPE) {
      throw oauthError(
        HttpStatus.BAD_REQUEST,
        'invalid_request',
        `client_assertion_type must be ${ASSERTION_TYPE}`,
      );
    }

    const issuer = this.tokens.settings.issuer;
    let checked: CheckedAssertion;
    try {
      checked = await checkAssertion(assertion, {
        issuer,
        clientIdField,
        findClient: (id) =>
          this.prisma.oAuthClient.findUnique({ where: { id } }),
      });
    } catch (error) {
      if (error instanceof AssertionRefusedError) {
        this.refused(error.claimedClient, error.reason, address);
        // Spec 0003 AC-43: a refused assertion counts against the per address limit
        await this.countAddress(address);
        throw invalidClient();
      }
      throw error;
    }
    const clientId = checked.clientId;

    // AC-43: assertion callers skip the per address limit and get a per client one
    const hit = await this.storage.increment(
      `client:${clientId}`,
      CLIENT_LIMIT.ttlMs,
      CLIENT_LIMIT.limit,
      0,
      'client',
    );
    if (hit.totalHits > CLIENT_LIMIT.limit) {
      this.logger.warn(
        `rate limited client=${clientId} ip=${logSafe(address)}`,
      );
      throw new ClientRateLimitedError(
        Math.max(1, Math.ceil(hit.timeToExpire)),
      );
    }

    const client = (await this.prisma.oAuthClient.findUnique({
      where: { id: clientId },
    }))!;
    return { checked, client };
  }

  private async clientCredentials(
    form: Form,
    checked: CheckedAssertion,
    refuseGrant: (error: string, description: string) => Error,
  ): Promise<TokenAnswer> {
    const clientId = checked.clientId;
    const audience = field(form, 'audience', true);
    const scopeField = field(form, 'scope', true);
    const scopes = scopeField.split(' ').filter(Boolean);
    if (scopes.length === 0) {
      throw oauthError(
        HttpStatus.BAD_REQUEST,
        'invalid_request',
        'scope is empty',
      );
    }
    // AC-16: audience and scope, against the registry row
    const client = (await this.prisma.oAuthClient.findUnique({
      where: { id: clientId },
    }))!;
    const allowed = (client.serviceScopes as Record<string, unknown>)[audience];
    if (!Array.isArray(allowed)) {
      throw refuseGrant(
        'invalid_target',
        `This client may not call ${logSafe(audience)}`,
      );
    }
    const missing = scopes.find((scope) => !allowed.includes(scope));
    if (missing !== undefined) {
      throw refuseGrant(
        'invalid_scope',
        `This client may not ask for ${logSafe(missing)}`,
      );
    }

    // AC-17: record the jti last, so a refused grant doesn't use it up
    await this.recordJti(checked, '');

    const { token, jti, expiresIn } = await this.tokens.signServiceToken({
      clientId,
      aud: audience,
      scopes,
    });
    // AC-27: one line per token issued, never the token itself
    this.logger.log(
      `issued service token client=${clientId} aud=${audience} scope="${scopes.join(' ')}" kid=${this.tokens.currentKid} jti=${jti}`,
    );
    return {
      access_token: token,
      token_type: 'Bearer',
      expires_in: expiresIn,
      scope: scopes.join(' '),
    };
  }

  /** The primary key settles two requests at the same moment: one row, one token (AC-17). */
  private async recordJti(checked: CheckedAssertion, address: string) {
    try {
      await this.prisma.clientAssertionJti.create({
        data: {
          clientId: checked.clientId,
          jti: checked.jti,
          expiresAt: checked.expiresAt,
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        this.refused(checked.clientId, 'jti_reused', address);
        throw invalidClient();
      }
      throw error;
    }
  }

  /** The per address count for a request whose assertion failed (AC-43). */
  private async countAddress(address: string) {
    const hit = await this.storage.increment(
      `address:${address}`,
      ADDRESS_LIMIT.ttl,
      ADDRESS_LIMIT.limit,
      0,
      'address',
    );
    if (hit.totalHits > ADDRESS_LIMIT.limit) {
      throw new AddressRateLimitedError(
        Math.max(1, Math.ceil(hit.timeToExpire)),
      );
    }
  }

  private refused(client: string, reason: string, address: string) {
    this.logger.warn(
      `refused assertion client=${client} reason=${reason} ip=${logSafe(address)}`,
    );
  }
}
