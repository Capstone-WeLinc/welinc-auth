import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { AuthService } from '../auth.service';
import { TokenEndpointService } from '../clients/token-endpoint.service';
import { MobileLoginDto } from '../dto/mobile-login.dto';
import { oauthError } from '../clients/oauth-error';
import { coded } from '../errors';
import { UserGrantsService } from './user-grants.service';

/** `/auth/mobile/login` allows 5 a minute per address (spec 0003, AC-28, AC-38). */
export const MOBILE_LOGIN_LIMIT = { limit: 5, ttlMs: 60_000 };

/** The device label as stored: trimmed, at most 100 characters, null when empty. */
export function deviceNameOf(raw: string): string | null {
  const trimmed = raw.trim().slice(0, 100);
  return trimmed === '' ? null : trimmed;
}

/**
 * The native login (spec 0001 section 8, spec 0003 AC-28). It answers tokens in the body, in
 * camel case, and never sets a cookie. It shares the per account lockout with the portal login.
 * Refresh is `/auth/token` with `client_id`; logout is `/auth/logout` with `{ refreshToken }`.
 */
@Controller('auth/mobile')
export class MobileController {
  constructor(
    private readonly auth: AuthService,
    private readonly endpoint: TokenEndpointService,
    private readonly grants: UserGrantsService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: MobileLoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    // Counted before anything else, so guessing passwords costs the same as a bad request
    const hit = await this.storage.increment(
      `mobile-login:${req.ip ?? 'unknown'}`,
      MOBILE_LOGIN_LIMIT.ttlMs,
      MOBILE_LOGIN_LIMIT.limit,
      0,
      'mobile-login',
    );
    if (hit.totalHits > MOBILE_LOGIN_LIMIT.limit) {
      res.setHeader(
        'Retry-After',
        String(Math.max(1, Math.ceil(hit.timeToExpire))),
      );
      // Spec 0001 section 12: 429 with `{ "error": "rate_limited" }`
      throw oauthError(
        HttpStatus.TOO_MANY_REQUESTS,
        'rate_limited',
        'Too many sign in attempts from this address. Wait a minute and try again.',
      );
    }

    const client = await this.endpoint.publicClient(dto.clientId);
    if (!client?.system || !client.grants.includes('mobile_login')) {
      throw coded(
        HttpStatus.BAD_REQUEST,
        'INVALID_CLIENT',
        'This app may not sign in here',
      );
    }
    const { user } = await this.auth.checkCredentials({
      email: dto.email,
      password: dto.password,
      system: client.system,
    });
    const answer = await this.grants.startMobile(client, {
      user,
      deviceName: deviceNameOf(dto.deviceName),
      ip: req.ip ?? null,
    });
    return {
      accessToken: answer.access_token,
      refreshToken: answer.refresh_token,
      expiresIn: answer.expires_in,
      sid: answer.sid,
      sessionExpiresAt: answer.session_expires_at,
      user: answer.user,
    };
  }
}
