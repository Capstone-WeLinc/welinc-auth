import {
  Controller,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import { SessionEndReason, type OAuthClient } from '@prisma/client';
import type { Request, Response } from 'express';
import { coded } from '../errors';
import { oauthError } from '../clients/oauth-error';
import {
  ClientRateLimitedError,
  TokenEndpointService,
  field,
  userAddressOf,
  type Form,
} from '../clients/token-endpoint.service';
import { csrfRejected, passesCsrf } from './csrf';
import { SESSION_SETTINGS, type SessionSettings } from './session-config';
import { SessionService } from './session.service';
import { clearSsoCookie, readSsoCookie } from './sso-cookie';

/** `/auth/session/activity` accepts and ignores more than 2 pings a minute per `sid` (AC-38). */
export const ACTIVITY_LIMIT = { limit: 2, ttlMs: 60_000 };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const sessionEnded = () =>
  coded(HttpStatus.UNAUTHORIZED, 'SESSION_ENDED', 'The session has ended');

function isForm(req: Request): boolean {
  return (
    req.is('application/x-www-form-urlencoded') ===
    'application/x-www-form-urlencoded'
  );
}

function bodyOf(req: Request): Form {
  return typeof req.body === 'object' && req.body !== null
    ? (req.body as Form)
    : {};
}

/**
 * Logout and activity (spec 0003, AC-2, AC-3, AC-17, AC-38, AC-42, AC-43). Each takes one of two
 * forms: a confidential client's assertion in form fields (as `/auth/token` takes it) plus the
 * user's `refresh_token` (logout also takes `sid`), or the portal's SSO cookie in a JSON POST
 * behind the CSRF check. The bodies are read through `@Req()`, so the global ValidationPipe
 * leaves them alone. Neither route runs reuse detection: only the refresh grant does.
 */
@Controller('auth')
export class SessionEndController {
  constructor(
    private readonly sessions: SessionService,
    private readonly endpoint: TokenEndpointService,
    @Inject(SESSION_SETTINGS) private readonly settings: SessionSettings,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  /**
   * Ends a session (AC-24, AC-42). Always 204 once the caller is known: an unknown, foreign or
   * already ended token ends nothing and says nothing about why.
   */
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    if (isForm(req)) {
      // The refresh token form wins over a cookie sent alongside it (AC-42)
      const form = bodyOf(req);
      const client = await this.client(form, req, res);
      const sessionId = await this.sessionForLogout(client, form);
      if (sessionId) {
        await this.sessions.endNow(sessionId, SessionEndReason.LOGOUT, {
          clientId: client.id,
        });
      }
      return;
    }

    const body = bodyOf(req);
    if (body['refreshToken'] !== undefined) {
      // A public native client (AC-30): no cookie and no CSRF check, the token is the proof
      await this.mobileLogout(body);
      return;
    }

    if (!passesCsrf(req, this.settings.portalOrigin)) throw csrfRejected();
    const session = await this.sessions.liveBySsoHandle(
      readSsoCookie(req, this.settings),
    );
    if (session) {
      await this.sessions.endNow(session.id, SessionEndReason.LOGOUT, {
        clientId: 'portal',
      });
    }
    clearSsoCookie(res, this.settings);
  }

  /**
   * An activity ping (AC-2, AC-3, AC-42): moves the session's idle cutoff. A used token inside
   * its grace window still counts; past grace it answers 401 and ends nothing. A third ping in a
   * minute for one `sid` is accepted and ignored (AC-38).
   */
  @Post('session/activity')
  @HttpCode(HttpStatus.NO_CONTENT)
  async activity(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    let sessionId: string;
    let lastSeenIp: string | null;
    if (isForm(req)) {
      const form = bodyOf(req);
      const client = await this.client(form, req, res);
      const found = await this.sessions.byRefreshToken(
        client.id,
        field(form, 'refresh_token', true),
      );
      if (!found || (found.used && !found.inGrace)) throw sessionEnded();
      sessionId = found.sessionId;
      // AC-43: trusted only because the assertion passed
      lastSeenIp = userAddressOf(req.headers['x-welinc-user-address']);
    } else {
      if (!passesCsrf(req, this.settings.portalOrigin)) throw csrfRejected();
      const session = await this.sessions.liveBySsoHandle(
        readSsoCookie(req, this.settings),
      );
      if (!session) throw sessionEnded();
      sessionId = session.id;
      lastSeenIp = req.ip ?? null;
    }

    const hit = await this.storage.increment(
      `activity:${sessionId}`,
      ACTIVITY_LIMIT.ttlMs,
      ACTIVITY_LIMIT.limit,
      0,
      'activity',
    );
    if (hit.totalHits > ACTIVITY_LIMIT.limit) {
      // Still a live check, so a cutoff is never hidden behind the limit (AC-3)
      if (!(await this.sessions.live(sessionId))) throw sessionEnded();
      return;
    }
    if (!(await this.sessions.recordActivity(sessionId, lastSeenIp))) {
      throw sessionEnded();
    }
  }

  /**
   * `{ refreshToken, clientId }` from a public native client (AC-30): ends the session behind any
   * of that client's token rows. An unknown client or token, or an ended session, ends nothing,
   * and the answer is 204 all the same.
   */
  private async mobileLogout(body: Form): Promise<void> {
    const client = await this.endpoint.publicClient(body['clientId']);
    if (!client) return;
    const found = await this.sessions.byRefreshToken(
      client.id,
      body['refreshToken'],
    );
    if (found) {
      await this.sessions.endNow(found.sessionId, SessionEndReason.LOGOUT, {
        clientId: client.id,
      });
    }
  }

  /** The session a confidential client may end: by any of its refresh token rows, or by `sid`. */
  private async sessionForLogout(
    client: OAuthClient,
    form: Form,
  ): Promise<string | null> {
    const token = field(form, 'refresh_token', false);
    const sid = field(form, 'sid', false);
    if (token === undefined && sid === undefined) {
      throw oauthError(
        HttpStatus.BAD_REQUEST,
        'invalid_request',
        'Send refresh_token or sid',
      );
    }
    // The refresh token wins; the sid is the fallback when it matches no row (AC-24, AC-42)
    if (token !== undefined) {
      const found = await this.sessions.byRefreshToken(client.id, token);
      if (found) return found.sessionId;
    }
    // Only a sid this client has held a refresh token in (AC-42)
    if (sid === undefined || !UUID.test(sid)) return null;
    return (await this.sessions.clientHoldsSession(client.id, sid))
      ? sid
      : null;
  }

  /** The assertion, as `/auth/token` checks it, with the same 429 answer. */
  private async client(
    form: Form,
    req: Request,
    res: Response,
  ): Promise<OAuthClient> {
    try {
      return await this.endpoint.assertClient(form, req.ip ?? '');
    } catch (error) {
      if (error instanceof ClientRateLimitedError) {
        res.setHeader('Retry-After', String(error.retryAfterSeconds));
        throw oauthError(
          HttpStatus.TOO_MANY_REQUESTS,
          'rate_limited',
          'Too many requests for this client. Try again later.',
        );
      }
      throw error;
    }
  }
}
