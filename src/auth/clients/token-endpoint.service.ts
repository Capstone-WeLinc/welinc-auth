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
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { TokenService } from '../tokens/token.service';
import {
  AssertionRefusedError,
  checkAssertion,
  logSafe,
  type CheckedAssertion,
} from './client-assertion';
import { invalidClient, oauthError } from './oauth-error';

export const ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** The per client limit, counted after the assertion passes (spec 0002, AC-18). */
export const CLIENT_LIMIT = { limit: 60, ttlMs: 60_000 };
/** How often expired replay rows are deleted, and how long past `expiresAt` they're kept (AC-17). */
export const JTI_SWEEP_MS = 10 * 60_000;
export const JTI_GRACE_MS = 60_000;

/** A form field read safely: absent, a repeated field (an array) or an object are all refused. */
type Form = Record<string, unknown>;

function field(form: Form, name: string, required: true): string;
function field(form: Form, name: string, required: false): string | undefined;
function field(
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

/**
 * `POST /auth/token`, the client credentials grant (spec 0002, AC-14 to AC-17, AC-27). S3 and S4
 * add the user grants.
 */
@Injectable()
export class TokenEndpointService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger('TokenEndpoint');
  private sweeper: NodeJS.Timeout | null = null;

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokenService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
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

  async grant(form: Form, address: string): Promise<TokenAnswer> {
    const grantType = field(form, 'grant_type', true);
    const assertionType = field(form, 'client_assertion_type', true);
    const assertion = field(form, 'client_assertion', true);
    const audience = field(form, 'audience', true);
    const scopeField = field(form, 'scope', true);
    const clientIdField = field(form, 'client_id', false);
    if (assertionType !== ASSERTION_TYPE) {
      throw oauthError(
        HttpStatus.BAD_REQUEST,
        'invalid_request',
        `client_assertion_type must be ${ASSERTION_TYPE}`,
      );
    }
    const scopes = scopeField.split(' ').filter(Boolean);
    if (scopes.length === 0) {
      throw oauthError(
        HttpStatus.BAD_REQUEST,
        'invalid_request',
        'scope is empty',
      );
    }

    // AC-15: the client proves who it is first; every failure looks the same from outside
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
        throw invalidClient();
      }
      throw error;
    }
    const clientId = checked.clientId;

    // AC-18: the per client count, only once the assertion is known to be the client's
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

    // AC-16: grant, audience and scope, against the registry row
    const client = (await this.prisma.oAuthClient.findUnique({
      where: { id: clientId },
    }))!;
    const refuseGrant = (error: string, description: string) => {
      this.logger.warn(
        `refused grant client=${clientId} reason=${error} ip=${logSafe(address)}`,
      );
      return oauthError(HttpStatus.BAD_REQUEST, error, description);
    };
    if (grantType !== 'client_credentials') {
      throw refuseGrant(
        'unsupported_grant_type',
        'Only client_credentials is supported',
      );
    }
    if (!client.grants.includes('client_credentials')) {
      throw refuseGrant(
        'unauthorized_client',
        'This client may not use client_credentials',
      );
    }
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

    // AC-17: record the jti last, so a refused grant doesn't use it up. The primary key settles
    // two requests at the same moment: one row, one token.
    try {
      await this.prisma.clientAssertionJti.create({
        data: { clientId, jti: checked.jti, expiresAt: checked.expiresAt },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        this.refused(clientId, 'jti_reused', address);
        throw invalidClient();
      }
      throw error;
    }

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

  private refused(client: string, reason: string, address: string) {
    this.logger.warn(
      `refused assertion client=${client} reason=${reason} ip=${logSafe(address)}`,
    );
  }
}
