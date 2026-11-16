import {
  Controller,
  Injectable,
  NotFoundException,
  Post,
  Req,
  UseGuards,
  type CanActivate,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiExcludeController } from '@nestjs/swagger';
import type { Env } from '../../config/env';
import { PortalCsrfGuard } from '../sessions/csrf';
import { notSuiteAdmin } from './admin-errors';
import {
  AdminSessionGuard,
  portalAdmin,
  type AdminRequest,
} from './admin-session.guard';

/**
 * VRMS spec 0025, AC-16: with `SENTRY_TEST_ROUTES` off the route answers 404 before any other
 * check, so it looks the same as a route that does not exist. The boot check refuses the switch
 * in production (AC-15).
 */
@Injectable()
export class SentryTestSwitch implements CanActivate {
  constructor(private readonly config: ConfigService<Env, true>) {}

  canActivate(): boolean {
    if (!this.config.get('SENTRY_TEST_ROUTES', { infer: true })) {
      throw new NotFoundException();
    }
    return true;
  }
}

/**
 * VRMS spec 0025, AC-16: `POST /auth/admin/debug/sentry-test` throws so a suite admin can see an
 * issue arrive. It needs the admin session with its emailed code (the guard's default level) and
 * a suite admin, and it is kept out of the API docs (spec 0026, AC-7).
 */
@ApiExcludeController()
@Controller('auth/admin/debug')
@UseGuards(SentryTestSwitch, AdminSessionGuard)
export class SentryTestController {
  @Post('sentry-test')
  @UseGuards(PortalCsrfGuard)
  sentryTest(@Req() req: AdminRequest): never {
    if (!portalAdmin(req).standing.suiteAdmin) throw notSuiteAdmin();
    throw new Error('Sentry test error from welinc-auth (spec 0025)');
  }
}
