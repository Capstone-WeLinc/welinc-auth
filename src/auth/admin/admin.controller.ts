import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { SystemType } from '@prisma/client';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import type { Response } from 'express';
import { countCodeCall } from '../codes/address-limit';
import { codeExpired } from '../codes/code-errors';
import { SignInStepService } from '../codes/sign-in-step.service';
import { VerifySignInDto } from '../dto/email-verification.dto';
import { requestMeta } from '../events/request-meta';
import { PortalCsrfGuard } from '../sessions/csrf';
import { SessionService } from '../sessions/session.service';
import { codeNotRequired } from './admin-errors';
import {
  TemporaryGrantsService,
  type GrantView,
} from './temporary-grants.service';
import {
  AdminRoute,
  AdminSessionGuard,
  portalAdmin,
  type AdminRequest,
} from './admin-session.guard';

import { ApiTags } from '@nestjs/swagger';
import {
  ApiCookieRoute,
  ApiErrorMap,
  ApiGenericErrors,
  ApiSsoCookie,
} from '../../openapi/decorators';
import {
  ADMIN_SIGNED_IN,
  ADMIN_STEP,
  CODE_MAIL,
  CODE_ROUTE_LIMIT,
  CSRF,
  VALIDATION,
} from '../../openapi/guard-errors';
/** The `GET /auth/admin/me` body (spec 0013, AC-15). */
export type AdminMe = {
  user: { id: string; name: string; email: string; picture: string | null };
  suiteAdmin: boolean;
  adminOf: SystemType[];
  codeRequired: boolean;
  codePassed: boolean;
  /** AC-24: a suite admin's own live temporary access (empty for everyone else). */
  temporaryGrants: GrantView[];
};

/**
 * Spec 0013: the portal admin section's routes, authenticated by the `welinc_sso` cookie
 * (AC-14). Slice 1 holds who the caller is and the step up code (AC-7, AC-15).
 */
@ApiTags('Portal Admin Session')
@ApiSsoCookie()
@ApiGenericErrors()
@Controller('auth/admin')
@UseGuards(AdminSessionGuard)
export class AdminController {
  constructor(
    private readonly signInStep: SignInStepService,
    private readonly sessions: SessionService,
    private readonly grants: TemporaryGrantsService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  /** AC-15: answers for any signed in person, so the launcher knows whether to show Admin. */
  @ApiErrorMap(ADMIN_SIGNED_IN)
  @Get('me')
  @AdminRoute('signed-in')
  async me(
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AdminMe> {
    res.setHeader('Cache-Control', 'no-store');
    const caller = portalAdmin(req);
    return {
      user: {
        id: caller.user.id,
        name: caller.user.name,
        email: caller.user.email,
        picture: caller.user.profilePicture,
      },
      suiteAdmin: caller.standing.suiteAdmin,
      adminOf: caller.standing.adminOf,
      codeRequired: caller.codeRequired,
      codePassed: caller.codePassed,
      // AC-24: the caller's own live temporary access, for the top bar banner
      temporaryGrants: caller.standing.suiteAdmin
        ? await this.grants.liveFor(caller.userId)
        : [],
    };
  }

  /**
   * AC-7: emails a `SIGN_IN` code to the caller for this session's step up. Already passed:
   * `{ passed: true }` and nothing is sent. Spec 0009's send limits and address count apply.
   */
  @ApiCookieRoute()
  @ApiErrorMap(ADMIN_STEP, CSRF, CODE_ROUTE_LIMIT, CODE_MAIL, {
    409: ['CODE_NOT_REQUIRED'],
  })
  @Post('code')
  @HttpCode(HttpStatus.OK)
  @AdminRoute('admin')
  @UseGuards(PortalCsrfGuard)
  async sendCode(
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<
    | { challengeId: string; email: string; resendAfter: number }
    | { passed: true }
  > {
    res.setHeader('Cache-Control', 'no-store');
    const caller = portalAdmin(req);
    if (!caller.codeRequired) throw codeNotRequired();
    if (caller.codePassed) return { passed: true };
    await countCodeCall(this.storage, 'code-signin', req, res);
    // The admin wording in the email; this route answers no status
    const step = await this.signInStep.start(
      caller.user,
      requestMeta(req),
      'SIGN_IN_CODE_REQUIRED',
    );
    return {
      challengeId: step.challengeId,
      email: step.email,
      resendAfter: step.resendAfter,
    };
  }

  /**
   * AC-7: a right code sets `sign_in_code_at` on the cookie session and writes
   * `ADMIN_CODE_PASSED`. A ticket that belongs to someone else counts as expired.
   */
  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_STEP, CSRF, CODE_ROUTE_LIMIT, {
    400: ['CODE_EXPIRED', 'INVALID_CODE'],
    409: ['CODE_NOT_REQUIRED'],
  })
  @Post('code/verify')
  @HttpCode(HttpStatus.NO_CONTENT)
  @AdminRoute('admin')
  @UseGuards(PortalCsrfGuard)
  async verifyCode(
    @Body() dto: VerifySignInDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    res.setHeader('Cache-Control', 'no-store');
    const caller = portalAdmin(req);
    if (!caller.codeRequired) throw codeNotRequired();
    await countCodeCall(this.storage, 'code-signin', req, res);
    const meta = requestMeta(req);
    await this.signInStep.verify(
      dto.challengeId,
      dto.code,
      (userId) => {
        if (userId !== caller.userId) throw codeExpired();
        return Promise.resolve();
      },
      meta,
    );
    await this.sessions.markCodePassed(caller.sid, caller.userId, meta);
  }
}
