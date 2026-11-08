import {
  Controller,
  Delete,
  ForbiddenException,
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
import { SessionEndReason, UserChangeAction, UserRole } from '@prisma/client';
import type { Response } from 'express';
import { PrismaService } from '../../shared/prisma.service';
import { Roles } from '../decorators/roles.decorator';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { RolesGuard } from '../guards/roles.guard';
import type { UserCaller } from '../guards/request-authenticator';
import { change } from '../user-changes';
import { assertInSystem } from '../user-scope';
import { SessionService } from './session.service';

/** Admins end their own sessions through logout or Signed in devices, not the admin route. */
export const SELF_END_ALL =
  "You can't end your own sessions here. Use Signed in devices on your profile.";

type UserRequest = { user: UserCaller };

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
    await this.sessions.endNow(sid, SessionEndReason.USER_ENDED);
  }

  /** A user's live sessions, for an admin who can see them (AC-32). */
  @Get('users/:id/sessions')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  async ofUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: UserRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    await this.visibleUser(id, req.user);
    return { sessions: await this.sessions.listLive(id) };
  }

  /**
   * Ends every live session of a user (`ADMIN_ENDED`, the admin as `endedById`) and records one
   * `SESSIONS_ENDED` change holding the count, in one transaction (AC-32).
   */
  @Delete('users/:id/sessions')
  @UseGuards(RolesGuard)
  @Roles(UserRole.ADMIN)
  async endAllOfUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: UserRequest,
  ) {
    const caller = req.user;
    const ended = await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({
        where: { id },
        select: {
          deletedAt: true,
          roles: { select: { role: true, system: true } },
        },
      });
      assertInSystem(user?.deletedAt ? null : user, caller.system);
      if (id === caller.sub) throw new ForbiddenException(SELF_END_ALL);
      const count = await this.sessions.endAllForUser(
        tx,
        id,
        SessionEndReason.ADMIN_ENDED,
        { endedById: caller.sub },
      );
      await tx.userChange.create({
        data: change(
          id,
          { id: caller.sub, email: caller.email },
          UserChangeAction.SESSIONS_ENDED,
          { newValue: String(count) },
        ),
      });
      return count;
    });
    return { ended };
  }

  /** 404 unless the user exists, isn't deleted and holds a role in the caller's system. */
  private async visibleUser(id: string, caller: UserCaller) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        deletedAt: true,
        roles: { select: { role: true, system: true } },
      },
    });
    assertInSystem(user?.deletedAt ? null : user, caller.system);
  }
}
