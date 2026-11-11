import {
  Controller,
  Get,
  Header,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import type { UserCaller } from '../guards/request-authenticator';
import { etagOf, matchesEtag } from '../roles/systems.controller';
import { AccountEventsService } from './account-events.service';
import { parseActivityQuery } from './activity-query';
import { EVENT_CATALOG } from './event-types';

/** Browsers and the gateway may reuse the catalog for this long (AC-15). */
export const CATALOG_MAX_AGE_SECONDS = 300;

// The catalog never changes while the process runs, so its body and tag are made once at boot
const CATALOG_BODY = JSON.stringify(EVENT_CATALOG);
const CATALOG_ETAG = etagOf(CATALOG_BODY);

/**
 * Spec 0011: account activity. A user token of any system reads its own events; a service token
 * gets 403 `WRONG_TOKEN_USE` from `JwtAuthGuard` (AC-14).
 */
@Controller('auth')
export class ActivityController {
  constructor(private readonly events: AccountEventsService) {}

  @UseGuards(JwtAuthGuard)
  @Get('profile/activity')
  @Header('Cache-Control', 'no-store')
  ownActivity(
    @Query() query: Record<string, unknown>,
    @Req() req: { user: UserCaller },
  ) {
    return this.events.listOwn(req.user.sub, parseActivityQuery(query));
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
