import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  NotFoundException,
  Param,
  ParseUUIDPipe,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { SessionEndReason } from '@prisma/client';
import type { Request, Response } from 'express';
import { AccountSessionsService } from '../admin/account-sessions.service';
import { ReauthBodyDto } from '../dto/reauth-body.dto';
import { requestMeta } from '../events/request-meta';
import { PrismaService } from '../../shared/prisma.service';
import { SystemAdmin } from '../decorators/system-admin.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import type { UserCaller } from '../guards/request-authenticator';
import type { AdminCaller } from '../user-scope';
import { SessionService } from './session.service';

type UserRequest = Pick<Request, 'ip' | 'headers'> & { user: UserCaller };

/** The bearer admin's scope: the token's system and session (spec 0013, AC-16). */
const adminOf = (req: UserRequest): AdminCaller => ({
  id: req.user.sub,
  email: req.user.email,
  system: req.user.system,
  sid: req.user.sid,
  meta: requestMeta(req),
});

/**
 * Seeing and ending sessions (spec 0003, AC-31, AC-32): your own under `/auth/me/sessions`, and
 * an admin's view of a user they can see (spec 0011 scoping) under `/auth/users/:id/sessions`.
 */
@Controller('auth')
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(
    private readonly sessions: SessionService,
    private readonly prisma: PrismaService,
    private readonly accountSessions: AccountSessionsService,
  ) {}

  /** Your live sessions, newest activity first, with `current` on this one (AC-31). */
  @Get('me/sessions')
  async mine(
    @Req() req: UserRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    return {
      sessions: await this.sessions.listLive(req.user.sub, req.user.sid),
    };
  }

  /**
   * Ends one of your sessions (`USER_ENDED`). Your current one too: the app then acts as after a
   * logout. A sid that isn't yours answers 404; one of yours that already ended answers 204.
   */
  @Delete('me/sessions/:sid')
  @HttpCode(HttpStatus.NO_CONTENT)
  async endMine(
    @Param('sid', ParseUUIDPipe) sid: string,
    @Req() req: UserRequest,
  ) {
    const row = await this.prisma.session.findUnique({
      where: { id: sid },
      select: { userId: true },
    });
    if (!row || row.userId !== req.user.sub) {
      throw new NotFoundException('Session not found');
    }
    await this.sessions.endNow(sid, SessionEndReason.USER_ENDED, {
      ip: requestMeta(req).ip,
    });
  }

  /** A user's live sessions, for an admin who can see them (AC-32). */
  @Get('users/:id/sessions')
  @SystemAdmin()
  async ofUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: UserRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    return { sessions: await this.accountSessions.list(id, adminOf(req)) };
  }

  /**
   * Ends every live session of a user (AC-32). An admin account needs `reauthToken` in the body
   * (spec 0013, AC-14b).
   */
  @Delete('users/:id/sessions')
  @SystemAdmin()
  async endAllOfUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: UserRequest,
    @Body() dto: ReauthBodyDto,
  ) {
    return {
      ended: await this.accountSessions.endAll(
        id,
        adminOf(req),
        dto.reauthToken,
      ),
    };
  }
}
