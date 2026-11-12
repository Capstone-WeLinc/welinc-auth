import {
  Controller,
  Get,
  Header,
  HttpStatus,
  Param,
  ParseUUIDPipe,
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
import { SystemAdmin } from '../decorators/system-admin.decorator';
import { coded } from '../errors';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import type { UserCaller } from '../guards/request-authenticator';
import { etagOf, matchesEtag } from '../roles/systems.controller';
import { AccountEventsService } from './account-events.service';
import { parseActivityQuery } from './activity-query';
import { EVENT_CATALOG } from './event-types';

/** Browsers and the gateway may reuse the catalog for this long (AC-15). */
export const CATALOG_MAX_AGE_SECONDS = 300;

/** `GET /auth/activity` allows 60 calls a minute per admin, counted per container (AC-13). */
export const FEED_LIMIT = { limit: 60, ttlMs: 60_000 };

// The catalog never changes while the process runs, so its body and tag are made once at boot
const CATALOG_BODY = JSON.stringify(EVENT_CATALOG);
const CATALOG_ETAG = etagOf(CATALOG_BODY);

/** AC-13: counts one feed call for `adminId` (both route families, spec 0013), or 429. */
export async function countFeedCall(
  storage: ThrottlerStorage,
  adminId: string,
  res: Response,
): Promise<void> {
  const hit = await storage.increment(
    `activity-feed:${adminId}`,
    FEED_LIMIT.ttlMs,
    FEED_LIMIT.limit,
    0,
    'activity-feed',
  );
  if (hit.totalHits > FEED_LIMIT.limit) {
    res.setHeader(
      'Retry-After',
      String(Math.max(1, Math.ceil(hit.timeToExpire))),
    );
    throw coded(
      HttpStatus.TOO_MANY_REQUESTS,
      'RATE_LIMITED',
      'Too many activity searches. Wait a minute and try again.',
    );
  }
}

/**
 * Spec 0011: account activity. A user token of any system reads its own events; a service token
 * gets 403 `WRONG_TOKEN_USE` from `JwtAuthGuard` (AC-14).
 */
@Controller('auth')
export class ActivityController {
  constructor(
    private readonly events: AccountEventsService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  @UseGuards(JwtAuthGuard)
  @Get('profile/activity')
  @Header('Cache-Control', 'no-store')
  ownActivity(
    @Query() query: Record<string, unknown>,
    @Req() req: { user: UserCaller },
  ) {
    return this.events.listOwn(req.user.sub, parseActivityQuery(query));
  }

  /** AC-12: one person's events for an admin of the token's system. */
  @SystemAdmin()
  @Get('users/:id/activity')
  @Header('Cache-Control', 'no-store')
  userActivity(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: Record<string, unknown>,
    @Req() req: { user: UserCaller },
  ) {
    const filters = parseActivityQuery(query, { type: true, dates: true });
    return this.events.listForUser(id, req.user.system, filters);
  }

  /** AC-13: the system's feed for its admins, 60 calls a minute each. */
  @SystemAdmin()
  @Get('activity')
  async systemActivity(
    @Query() query: Record<string, unknown>,
    @Req() req: { user: UserCaller },
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    await countFeedCall(this.storage, req.user.sub, res);
    const filters = parseActivityQuery(query, {
      type: true,
      dates: true,
      feed: true,
    });
    return this.events.feed(req.user.system, filters);
  }

  /** AC-15: public, no user data. Labels for every category, type and reason. */
  @Get('activity/catalog')
  catalog(@Req() req: Request, @Res() res: Response): void {
    res.setHeader(
      'Cache-Control',
      `public, max-age=${CATALOG_MAX_AGE_SECONDS}`,
    );
    res.setHeader('ETag', CATALOG_ETAG);
    if (matchesEtag(req.headers['if-none-match'], CATALOG_ETAG)) {
      res.status(304).end();
      return;
    }
    res.status(200).type('application/json').send(CATALOG_BODY);
  }
}
