import { Injectable, Logger } from '@nestjs/common';
import { ClientKind, type OAuthClient } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { logSafe } from '../clients/client-assertion';
import {
  hashOpaque,
  isOpaqueShape,
  isPkceChallenge,
  newOpaque,
} from './opaque';
import { LOGIN_CODE_SECONDS, LOGIN_REQUEST_SECONDS } from './session-config';
import { SessionService, type LiveSession } from './session.service';

export const MAX_STATE_LENGTH = 512;
export const MAX_REDIRECT_LENGTH = 2048;

/** The checked authorize parameters, as a login request keeps them. */
export type AuthorizeRequest = {
  client: OAuthClient;
  redirectUri: string;
  state: string;
  codeChallenge: string;
};

/** Where `/auth/authorize` sends the browser, or the error page it shows instead. */
export type AuthorizeResult =
  | { kind: 'redirect'; location: string }
  | { kind: 'error'; message: string };

function single(query: Record<string, unknown>, name: string): string | null {
  const value = query[name];
  return typeof value === 'string' ? value : null;
}

function withParams(base: string, params: Record<string, string>): string {
  const url = new URL(base);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  return url.toString();
}

/** `/auth/authorize` and `/auth/authorize/resume` (spec 0003, AC-13 to AC-15). */
@Injectable()
export class AuthorizeService {
  private readonly logger = new Logger('Authorize');

  constructor(
    private readonly prisma: PrismaService,
    private readonly sessions: SessionService,
  ) {}

  /**
   * Checks the query against the registry (AC-13). Any failure is an error page that never
   * redirects, because a bad `redirect_uri` must never receive the browser.
   */
  async check(
    query: Record<string, unknown>,
  ): Promise<AuthorizeRequest | { error: string }> {
    const clientId = single(query, 'client_id');
    const redirectUri = single(query, 'redirect_uri');
    const state = single(query, 'state');
    const challenge = single(query, 'code_challenge');
    const method = single(query, 'code_challenge_method');
    const responseType = query['response_type'];

    if (!clientId || !redirectUri || redirectUri.length > MAX_REDIRECT_LENGTH) {
      return { error: 'This sign in link is not valid.' };
    }
    const client = await this.prisma.oAuthClient.findUnique({
      where: { id: clientId },
    });
    if (
      !client ||
      !client.isActive ||
      client.kind !== ClientKind.CONFIDENTIAL ||
      !client.system ||
      !client.grants.includes('authorization_code')
    ) {
      this.logger.warn(
        `authorize refused client=${logSafe(clientId)} reason=unknown_client`,
      );
      return { error: 'This sign in link names an app WeLinc does not know.' };
    }
    if (!client.redirectUris.includes(redirectUri)) {
      this.logger.warn(
        `authorize refused client=${client.id} reason=redirect_mismatch`,
      );
      return {
        error: 'This sign in link points to an address WeLinc does not allow.',
      };
    }
    if (
      !state ||
      state.length > MAX_STATE_LENGTH ||
      !isPkceChallenge(challenge) ||
      method !== 'S256' ||
      (responseType !== undefined && responseType !== 'code')
    ) {
      this.logger.warn(
        `authorize refused client=${client.id} reason=bad_parameters`,
      );
      return { error: 'This sign in link is missing a required part.' };
    }
    return { client, redirectUri, state, codeChallenge: challenge };
  }

  /**
   * Continues a checked request (AC-13): a code for a live SSO session with a role in the
   * client's system, `access_denied` without one, and a login request when there's no session.
   */
  async continue(
    request: AuthorizeRequest,
    session: LiveSession | null,
    portalUrl: string,
  ): Promise<AuthorizeResult> {
    if (!session) {
      const id = newOpaque();
      await this.prisma.loginRequest.create({
        data: {
          idHash: hashOpaque(id),
          clientId: request.client.id,
          redirectUri: request.redirectUri,
          state: request.state,
          codeChallenge: request.codeChallenge,
          expiresAt: new Date(Date.now() + LOGIN_REQUEST_SECONDS * 1000),
        },
      });
      return {
        kind: 'redirect',
        location: withParams(`${portalUrl}/login`, { request: id }),
      };
    }

    const role = await this.prisma.userRoleAssignment.findFirst({
      where: { userId: session.userId, system: request.client.system! },
      select: { id: true },
    });
    if (!role) {
      this.logger.log(
        `authorize denied client=${request.client.id} sid=${session.id} reason=no_system_access`,
      );
      return {
        kind: 'redirect',
        location: withParams(request.redirectUri, {
          error: 'access_denied',
          state: request.state,
        }),
      };
    }

    const code = newOpaque();
    await this.prisma.authorizationCode.create({
      data: {
        codeHash: hashOpaque(code),
        clientId: request.client.id,
        sessionId: session.id,
        redirectUri: request.redirectUri,
        codeChallenge: request.codeChallenge,
        expiresAt: new Date(Date.now() + LOGIN_CODE_SECONDS * 1000),
      },
    });
    return {
      kind: 'redirect',
      location: withParams(request.redirectUri, { code, state: request.state }),
    };
  }

  /**
   * `/auth/authorize/resume` (AC-14). Used once, only with a live SSO session; a browser with
   * no session goes back to the portal's form with the same request.
   */
  async resume(
    requestId: unknown,
    session: LiveSession | null,
    portalUrl: string,
  ): Promise<AuthorizeResult> {
    const expired: AuthorizeResult = {
      kind: 'redirect',
      location: withParams(`${portalUrl}/`, { error: 'LOGIN_REQUEST_EXPIRED' }),
    };
    if (!isOpaqueShape(requestId)) return expired;
    const idHash = hashOpaque(requestId);
    const row = await this.prisma.loginRequest.findUnique({
      where: { idHash },
      include: { client: true },
    });
    if (!row || row.usedAt || row.expiresAt <= new Date()) return expired;
    if (!session) {
      return {
        kind: 'redirect',
        location: withParams(`${portalUrl}/login`, { request: requestId }),
      };
    }
    const { count } = await this.prisma.loginRequest.updateMany({
      where: { idHash, usedAt: null },
      data: { usedAt: new Date() },
    });
    if (count === 0 || !row.client.isActive) return expired;
    return this.continue(
      {
        client: row.client,
        redirectUri: row.redirectUri,
        state: row.state,
        codeChallenge: row.codeChallenge,
      },
      session,
      portalUrl,
    );
  }
}

/** The authorize error page (AC-13): everything it shows is escaped. */
export function errorPage(message: string): string {
  const escaped = message.replace(
    /[&<>"']/g,
    (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[
        c
      ]!,
  );
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign in problem · WeLinc</title><style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1f2937}h1{font-size:1.25rem}</style></head><body><h1>We couldn't start your sign in</h1><p>${escaped}</p><p>Open the app again from its usual address, or ask your admin for help.</p></body></html>`;
}
