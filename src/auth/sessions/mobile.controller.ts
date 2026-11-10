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
import type { OAuthClient } from '@prisma/client';
import { AuthService } from '../auth.service';
import { TokenEndpointService } from '../clients/token-endpoint.service';
import { countCodeCall } from '../codes/address-limit';
import {
  SignInStepService,
  type EmailVerificationStep,
} from '../codes/sign-in-step.service';
import {
  MobileVerifySignInDto,
  ResendSignInDto,
} from '../dto/email-verification.dto';
import { MobileLoginDto } from '../dto/mobile-login.dto';
import { oauthError } from '../clients/oauth-error';
import { coded } from '../errors';
import {
  UserGrantsService,
  type MobileGrant,
  type UserTokenAnswer,
} from './user-grants.service';

/** `/auth/mobile/login` allows 5 a minute per address (spec 0003, AC-28, AC-38). */
export const MOBILE_LOGIN_LIMIT = { limit: 5, ttlMs: 60_000 };

/** The `/auth/mobile/login` token body (contract 0001 section 8). */
export type MobileTokenBody = {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  sid: string;
  sessionExpiresAt: string;
  user: UserTokenAnswer['user'];
};

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
    private readonly signInStep: SignInStepService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(
    @Body() dto: MobileLoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<MobileTokenBody | EmailVerificationStep> {
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

    const client = await this.mobileClient(dto.clientId);
    const { user } = await this.auth.checkCredentials({
      email: dto.email,
      password: dto.password,
    });
    // NO_SYSTEM_ACCESS and APP_NOT_ALLOWED before the email step (suite spec 0009, AC-11)
    const grant = await this.grants.checkMobileGrant(client, user.id);
    if (!user.emailVerified) return this.signInStep.start(user);
    return this.issue(grant, user, dto.deviceName, req);
  }

  /**
   * Suite spec 0009, AC-11: the email step's code, in AC-9's order. The ticket's row, then the
   * client, the account and the grant again (no try counted), then the code; a right one confirms
   * the email and answers the token body. 10 calls a minute per address (AC-6).
   */
  @Post('login/verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(
    @Body() dto: MobileVerifySignInDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    await countCodeCall(this.storage, 'code-signin', req, res, 'mobile');
    let found: {
      grant: MobileGrant;
      user: { id: string; name: string; email: string };
    } | null = null;
    await this.signInStep.verify(dto.challengeId, dto.code, async (userId) => {
      const client = await this.mobileClient(dto.clientId);
      const user = await this.auth.assertCanSignIn(userId);
      found = {
        grant: await this.grants.checkMobileGrant(client, userId),
        user,
      };
    });
    const { grant, user } = found!;
    return this.issue(grant, user, dto.deviceName, req);
  }

  /** Suite spec 0009, AC-11: a new code on the same ticket (AC-10). */
  @Post('login/verify-email/resend')
  @HttpCode(HttpStatus.OK)
  async resendEmailCode(
    @Body() dto: ResendSignInDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ resendAfter: number }> {
    res.setHeader('Cache-Control', 'no-store');
    await countCodeCall(this.storage, 'code-signin', req, res, 'mobile');
    return this.signInStep.resend(dto.challengeId);
  }

  /** A public native client allowed the mobile login, else 400 `INVALID_CLIENT`. */
  private async mobileClient(clientId: string): Promise<OAuthClient> {
    const client = await this.endpoint.publicClient(clientId);
    if (!client?.system || !client.grants.includes('mobile_login')) {
      throw coded(
        HttpStatus.BAD_REQUEST,
        'INVALID_CLIENT',
        'This app may not sign in here',
      );
    }
    return client;
  }

  /** The one way a mobile login ends: a session and the token body, in camel case. */
  private async issue(
    grant: MobileGrant,
    user: { id: string; name: string; email: string },
    deviceName: string,
    req: Request,
  ): Promise<MobileTokenBody> {
    const answer: UserTokenAnswer = await this.grants.startMobile(grant, {
      user: { id: user.id, name: user.name, email: user.email },
      deviceName: deviceNameOf(deviceName),
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
