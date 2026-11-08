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
import { ClientKind, type SystemType } from '@prisma/client';
import type { Request, Response } from 'express';
import { PrismaService } from '../../shared/prisma.service';
import { AuthService } from '../auth.service';
import { LoginDto } from '../dto/login.dto';
import { coded } from '../errors';
import { bearerToken } from '../guards/request-authenticator';
import { pickLoginSystem } from '../tokens/login-system';
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
import { SESSION_SETTINGS, type SessionSettings } from './session-config';
import { SessionService, sessionExpiresAt } from './session.service';
import { readSsoCookie, setSsoCookie } from './sso-cookie';

/** `/auth/authorize` allows 30 a minute per address (spec 0003, AC-13, AC-38). */
export const AUTHORIZE_LIMIT = { limit: 30, ttlMs: 60_000 };

const sessionEnded = () =>
  coded(HttpStatus.UNAUTHORIZED, 'SESSION_ENDED', 'The session has ended');

/**
 * The browser and session check routes of spec 0003: the portal login with the SSO cookie,
 * `/auth/sso`, the authorize routes, and `/auth/session` for system backends.
 */
@Controller('auth')
export class SsoController {
  constructor(
    private readonly auth: AuthService,
    private readonly sessions: SessionService,
    private readonly authorize: AuthorizeService,
    private readonly tokens: TokenService,
    private readonly prisma: PrismaService,
    @Inject(SESSION_SETTINGS) private readonly settings: SessionSettings,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  /**
   * The portal login (AC-11): checks the password, creates a web session and sets `welinc_sso`.
   * Never answers a token. A browser that already holds an SSO session loses it first.
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const { user, system } = await this.auth.checkCredentials(dto);
    const url = await this.webAddress(system);
    const { session, handle } = await this.sessions.createWeb({
      userId: user.id,
      userAgent: req.headers['user-agent'] ?? null,
      ip: req.ip ?? null,
      previousHandle: readSsoCookie(req, this.settings),
    });
    setSsoCookie(res, this.settings, handle, session.absoluteExpiresAt!);
    return { user, system, url };
  }

  /** Whether this browser holds a live SSO session, and where it would go (AC-12). */
  @Get('sso')
  async sso(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    const session = await this.sessions.liveBySsoHandle(
      readSsoCookie(req, this.settings),
    );
    if (!session) throw sessionEnded();
    const roles = await this.prisma.userRoleAssignment.findMany({
      where: { userId: session.userId },
      select: { system: true },
    });
    const system = pickLoginSystem(roles);
    if (!system) {
      throw coded(
        HttpStatus.FORBIDDEN,
        'NO_SYSTEM_ACCESS',
        'This account has no access to any system',
      );
    }
    const { id, name, email } = session.user;
    return {
      user: { id, name, email },
      system,
      url: await this.webAddress(system),
    };
  }

  /** The start of the code flow (AC-13). */
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

  /** The web address of a system's client, where the portal sends a user after login. */
  private async webAddress(system: SystemType): Promise<string> {
    const client = await this.prisma.oAuthClient.findFirst({
      where: { system, kind: ClientKind.CONFIDENTIAL, isActive: true },
      select: { webAddress: true },
    });
    if (!client?.webAddress) {
      throw coded(
        HttpStatus.SERVICE_UNAVAILABLE,
        'AUTH_UNAVAILABLE',
        `${system} has no web address in the client registry. Run npm run seed:clients.`,
      );
    }
    return client.webAddress;
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
