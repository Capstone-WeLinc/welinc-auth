import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
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
import type { SystemType } from '@prisma/client';
import type { Request, Response } from 'express';
import { coded } from '../errors';
import { requestMeta } from '../events/request-meta';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { SystemAdmin } from '../decorators/system-admin.decorator';
import { DeletionService, type SelfCaller } from './deletion.service';
import {
  DeletionListQueryDto,
  DeletionRequestDto,
  RejectDeletionDto,
  VerifyPasswordDto,
} from './deletion.dto';

import { ApiTags } from '@nestjs/swagger';
import { ApiGenericErrors, ApiUserToken } from '../../openapi/decorators';
/** AC-2: verify password takes at most 10 calls a minute per user. */
export const VERIFY_PASSWORD_LIMIT = { limit: 10, ttlMs: 60_000 };

/** AC-2: counts one password check for `userId` (both route families, spec 0013), or 429. */
export async function countPasswordCheck(
  storage: ThrottlerStorage,
  userId: string,
  res: Response,
): Promise<void> {
  const hit = await storage.increment(
    `verify-password:${userId}`,
    VERIFY_PASSWORD_LIMIT.ttlMs,
    VERIFY_PASSWORD_LIMIT.limit,
    0,
    'verify-password',
  );
  if (hit.totalHits > VERIFY_PASSWORD_LIMIT.limit) {
    res.setHeader(
      'Retry-After',
      String(Math.max(1, Math.ceil(hit.timeToExpire))),
    );
    throw coded(
      HttpStatus.TOO_MANY_REQUESTS,
      'RATE_LIMITED',
      'Too many password checks. Wait a minute and try again.',
    );
  }
}

type SelfRequest = Pick<Request, 'ip' | 'headers'> & {
  user: { sub: string; sid: string };
};
type AdminRequest = Pick<Request, 'ip' | 'headers'> & {
  user: { sub: string; email: string; system: SystemType; sid: string };
};

const self = (req: SelfRequest): SelfCaller => ({
  sub: req.user.sub,
  sid: req.user.sid,
  meta: requestMeta(req),
});

const admin = (req: AdminRequest) => ({
  id: req.user.sub,
  email: req.user.email,
  system: req.user.system,
  sid: req.user.sid,
  meta: requestMeta(req),
});

/**
 * Spec 0012: password recheck and account deletion requests. User tokens only: a service token
 * gets 403 WRONG_TOKEN_USE from the guards (no route here takes a service scope).
 */
@ApiTags('Account Deletion')
@ApiUserToken()
@ApiGenericErrors()
@Controller('auth')
export class DeletionController {
  constructor(
    private readonly deletion: DeletionService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Post('profile/verify-password')
  @HttpCode(HttpStatus.OK)
  async verifyPassword(
    @Req() req: SelfRequest,
    @Body() dto: VerifyPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    await countPasswordCheck(this.storage, req.user.sub, res);
    return this.deletion.verifyPassword(self(req), dto.password, dto.purpose);
  }

  @UseGuards(JwtAuthGuard)
  @Post('profile/deletion-request')
  @HttpCode(HttpStatus.CREATED)
  request(@Req() req: SelfRequest, @Body() dto: DeletionRequestDto) {
    return this.deletion.request(self(req), dto.reauthToken, dto.reason);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile/deletion-request')
  own(@Req() req: SelfRequest) {
    return this.deletion.own(req.user.sub);
  }

  @UseGuards(JwtAuthGuard)
  @Delete('profile/deletion-request')
  @HttpCode(HttpStatus.NO_CONTENT)
  async cancel(@Req() req: SelfRequest): Promise<void> {
    await this.deletion.cancel(self(req));
  }

  @SystemAdmin()
  @Get('deletion-requests')
  list(@Req() req: AdminRequest, @Query() query: DeletionListQueryDto) {
    return this.deletion.list(req.user.system, query);
  }

  @SystemAdmin()
  @Post('deletion-requests/:id/approve')
  @HttpCode(HttpStatus.OK)
  approve(@Param('id', ParseUUIDPipe) id: string, @Req() req: AdminRequest) {
    return this.deletion.approve(id, admin(req));
  }

  @SystemAdmin()
  @Post('deletion-requests/:id/reject')
  @HttpCode(HttpStatus.OK)
  reject(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: AdminRequest,
    @Body() dto: RejectDeletionDto,
  ) {
    return this.deletion.reject(id, dto.note, admin(req));
  }
}
