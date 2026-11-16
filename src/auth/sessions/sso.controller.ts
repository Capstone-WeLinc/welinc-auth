import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import type { Request, Response } from 'express';
import { PrismaService } from '../../shared/prisma.service';
import { AdminStandingService } from '../admin/admin-standing.service';
import { AuthService, type SignInUser } from '../auth.service';
import { countCodeCall } from '../codes/address-limit';
import {
  SignInStepService,
  type EmailVerificationStep,
} from '../codes/sign-in-step.service';
import {
  ResendSignInDto,
  VerifySignInDto,
} from '../dto/email-verification.dto';
import { LoginDto } from '../dto/login.dto';
import { coded } from '../errors';
import { requestMeta, type RequestMeta } from '../events/request-meta';
import { bearerToken } from '../guards/request-authenticator';
import {
  TokenRejectedError,
  TokenService,
  type VerifiedToken,
} from '../tokens/token.service';
import {
  AuthorizeService,
  errorPage,
  type AuthorizeResult,
} from './authorize.service';
import { PortalCsrfGuard } from './csrf';
import { LauncherService, type LauncherAnswer } from './launcher';
import { SESSION_SETTINGS, type SessionSettings } from './session-config';
import { SessionService, sessionExpiresAt } from './session.service';
import { readSsoCookie, setSsoCookie } from './sso-cookie';

import { ApiTags } from '@nestjs/swagger';
import {
  ApiCookieRoute,
  ApiGenericErrors,
  ApiSsoCookie,
} from '../../openapi/decorators';
/** `/auth/authorize` allows 30 a minute per address (spec 0003, AC-13, AC-38). */
export const AUTHORIZE_LIMIT = { limit: 30, ttlMs: 60_000 };

/** `/auth/login` allows 10 a minute per address (contract 0001 section 12). */
export const LOGIN_LIMIT = { limit: 10, ttlMs: 60_000 };

/** `/auth/sso` allows 60 a minute per address (spec 0007, AC-4). */
export const SSO_LIMIT = { limit: 60, ttlMs: 60_000 };

const sessionEnded = () =>
  coded(HttpStatus.UNAUTHORIZED, 'SESSION_ENDED', 'The session has ended');

/**
 * The browser and session check routes of spec 0003: the portal login with the SSO cookie,
 * `/auth/sso`, the authorize routes, and `/auth/session` for system backends.
 */
@ApiTags('Web Login')
@ApiGenericErrors()
@Controller('auth')
export class SsoController {
  constructor(
    private readonly auth: AuthService,
    private readonly sessions: SessionService,
    private readonly authorize: AuthorizeService,
    private readonly tokens: TokenService,
    private readonly prisma: PrismaService,
    private readonly launcher: LauncherService,
    private readonly signInStep: SignInStepService,
    private readonly admins: AdminStandingService,
    @Inject(SESSION_SETTINGS) private readonly settings: SessionSettings,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  /**
   * The portal login (spec 0003, AC-11; spec 0007, AC-3): checks the password, builds the
   * launcher answer, then creates a web session and sets `welinc_sso`. Never answers a token.
   * No usable system means 403 and no session. A browser that already holds an SSO session
   * loses it first. An unverified email gets the code step instead, last of all, so nobody
   * without a system is sent a code (spec 0009, AC-7).
   */
  @ApiCookieRoute()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LauncherAnswer | EmailVerificationStep> {
    res.setHeader('Cache-Control', 'no-store');
    // Counted before the password check, so guessing passwords costs the same as a bad request
    const hit = await this.storage.increment(
      `login:${req.ip ?? 'unknown'}`,
      LOGIN_LIMIT.ttlMs,
      LOGIN_LIMIT.limit,
      0,
      'login',
    );
    if (hit.totalHits > LOGIN_LIMIT.limit) {
      res.setHeader(
        'Retry-After',
        String(Math.max(1, Math.ceil(hit.timeToExpire))),
      );
      throw coded(
        HttpStatus.TOO_MANY_REQUESTS,
        'RATE_LIMITED',
        'Too many sign in attempts from this address. Wait a minute and try again.',
      );
    }
    const meta = requestMeta(req);
    const { user } = await this.auth.checkCredentials(dto, meta);
    const answer = await this.answerFor(user, meta);
    // One code only, even for an unverified admin (spec 0013, AC-5)
    if (!user.emailVerified) return this.signInStep.start(user, meta);
    if (await this.admins.asksCodeAtLogin(user.id)) {
      return this.signInStep.start(user, meta, 'SIGN_IN_CODE_REQUIRED');
    }
    return this.finishLogin(user, answer, meta, req, res, false);
  }

  /**
   * Spec 0009, AC-9: the sign in step's code. The ticket's row, then the account and its systems
   * again (no try counted), then the code; a right one confirms the email and finishes the login
   * exactly as `/auth/login` does. 10 calls a minute per address (AC-6).
   */
  @ApiCookieRoute()
  @Post('login/verify-email')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  async verifyEmail(
    @Body() dto: VerifySignInDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LauncherAnswer> {
    res.setHeader('Cache-Control', 'no-store');
    await countCodeCall(this.storage, 'code-signin', req, res);
    const meta = requestMeta(req);
    let found: { user: SignInUser; answer: LauncherAnswer } | null = null;
    await this.signInStep.verify(
      dto.challengeId,
      dto.code,
      async (userId) => {
        const user = await this.auth.assertCanSignIn(userId, meta);
        found = { user, answer: await this.answerFor(user, meta) };
      },
      meta,
    );
    const { user, answer } = found!;
    return this.finishLogin(user, answer, meta, req, res, true);
  }

  /** Spec 0009, AC-10: a new code on the same ticket. */
  @ApiCookieRoute()
  @Post('login/verify-email/resend')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  async resendEmailCode(
    @Body() dto: ResendSignInDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<{ resendAfter: number }> {
    res.setHeader('Cache-Control', 'no-store');
    await countCodeCall(this.storage, 'code-signin', req, res);
    return this.signInStep.resend(dto.challengeId, requestMeta(req));
  }

  /** The launcher answer at a sign in, a `NO_SYSTEM_ACCESS` recorded (spec 0011, AC-1). */
  private answerFor(user: SignInUser, meta: RequestMeta) {
    return this.auth.withSignInCheck(user.id, meta, () =>
      this.launcher.answerFor(user),
    );
  }

  /**
   * The one way a portal login ends (AC-9 step 5): a web session and the `welinc_sso` cookie.
   * A login through the code step starts its session with `sign_in_code_at`, admin or not, and
   * an admin's also writes `ADMIN_CODE_PASSED` (spec 0013, AC-5, AC-7).
   */
  private async finishLogin(
    user: SignInUser,
    answer: LauncherAnswer,
    meta: RequestMeta,
    req: Request,
    res: Response,
    throughCode: boolean,
  ): Promise<LauncherAnswer> {
    const { session, handle } = await this.sessions.createWeb({
      userId: user.id,
      meta,
      previousHandle: readSsoCookie(req, this.settings),
      codePassed: throughCode
        ? { admin: await this.admins.asksCodeAtLogin(user.id) }
        : undefined,
    });
    setSsoCookie(res, this.settings, handle, session.absoluteExpiresAt!);
    return answer;
  }

  /**
   * Whether this browser holds a live SSO session, and the systems the launcher lists
   * (spec 0007, AC-1, AC-2, AC-4). Never counts as activity.
   */
  @ApiSsoCookie()
  @Get('sso')
  async sso(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LauncherAnswer> {
    res.setHeader('Cache-Control', 'no-store');
    const hit = await this.storage.increment(
      `sso:${req.ip ?? 'unknown'}`,
      SSO_LIMIT.ttlMs,
      SSO_LIMIT.limit,
      0,
      'sso',
    );
    if (hit.totalHits > SSO_LIMIT.limit) {
      res.setHeader(
        'Retry-After',
        String(Math.max(1, Math.ceil(hit.timeToExpire))),
      );
      throw coded(
        HttpStatus.TOO_MANY_REQUESTS,
        'RATE_LIMITED',
        'Too many requests from this address. Wait a minute and try again.',
      );
    }
    const session = await this.sessions.liveBySsoHandle(
      readSsoCookie(req, this.settings),
    );
    if (!session) throw sessionEnded();
    return this.launcher.answerFor(session.user);
  }

  /** The start of the code flow (AC-13). */
  @ApiSsoCookie()
  @Get('authorize')
  async authorizeStart(
    @Query() query: Record<string, unknown>,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const hit = await this.storage.increment(
      `authorize:${req.ip ?? 'unknown'}`,
      AUTHORIZE_LIMIT.ttlMs,
      AUTHORIZE_LIMIT.limit,
      0,
      'authorize',
    );
    if (hit.totalHits > AUTHORIZE_LIMIT.limit) {
      res.setHeader(
        'Retry-After',
        String(Math.max(1, Math.ceil(hit.timeToExpire))),
      );
      this.page(
        res,
        HttpStatus.TOO_MANY_REQUESTS,
        'Too many sign in attempts from this address. Wait a minute and try again.',
      );
      return;
    }
    const checked = await this.authorize.check(query);
    if ('error' in checked) {
      this.page(res, HttpStatus.BAD_REQUEST, checked.error);
      return;
    }
    const session = await this.sessions.liveBySsoHandle(
      readSsoCookie(req, this.settings),
    );
    this.send(
      res,
      await this.authorize.continue(checked, session, this.settings.portalUrl),
    );
  }

  /** The portal continues a login request after a password login (AC-14). */
  @ApiSsoCookie()
  @Get('authorize/resume')
  async authorizeResume(
    @Query('request') request: unknown,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const session = await this.sessions.liveBySsoHandle(
      readSsoCookie(req, this.settings),
    );
    this.send(
      res,
      await this.authorize.resume(request, session, this.settings.portalUrl),
    );
  }

  /**
   * The session check for system backends (AC-1, AC-26, AC-27; spec 0001 section 6). A locked
   * account's live session still answers 200 (AC-4).
   */
  @ApiSsoCookie()
  @Get('session')
  async session(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const raw = bearerToken(req);
    if (!raw) throw sessionEnded();
    let token: VerifiedToken;
    try {
      token = await this.tokens.verify(raw);
    } catch (error) {
      if (error instanceof TokenRejectedError && error.expired) {
        throw coded(
          HttpStatus.UNAUTHORIZED,
          'TOKEN_EXPIRED',
          'The access token has expired',
        );
      }
      if (error instanceof TokenRejectedError) throw sessionEnded();
      throw error;
    }
    if (token.tokenUse !== 'user' || !token.sid) throw sessionEnded();

    const row = await this.prisma.session.findUnique({
      where: { id: token.sid },
      select: {
        userId: true,
        user: { select: { isActive: true, deletedAt: true } },
      },
    });
    if (!row || row.userId !== token.sub) throw sessionEnded();
    if (!row.user.isActive || row.user.deletedAt) {
      throw coded(
        HttpStatus.UNAUTHORIZED,
        'ACCOUNT_INACTIVE',
        'This account is not active',
      );
    }
    const session = await this.sessions.live(token.sid);
    if (!session) throw sessionEnded();
    return {
      active: true,
      sid: session.id,
      expiresAt: sessionExpiresAt(session).toISOString(),
      user: {
        id: session.user.id,
        name: session.user.name,
        email: session.user.email,
      },
    };
  }

  private send(res: Response, result: AuthorizeResult) {
    if (result.kind === 'redirect')
      res.redirect(HttpStatus.FOUND, result.location);
    else this.page(res, HttpStatus.BAD_REQUEST, result.message);
  }

  private page(res: Response, status: HttpStatus, message: string) {
    res
      .status(status)
      .setHeader(
        'Content-Security-Policy',
        "default-src 'none'; style-src 'unsafe-inline'",
      )
      .type('html')
      .send(errorPage(message));
  }
}
