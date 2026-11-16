import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { SystemType } from '@prisma/client';
import {
  InjectThrottlerStorage,
  type ThrottlerStorage,
} from '@nestjs/throttler';
import type { Response } from 'express';
import { AuthService } from '../auth.service';
import { countPasswordCheck } from '../deletion/deletion.controller';
import { DeletionService } from '../deletion/deletion.service';
import { coded } from '../errors';
import { countFeedCall } from '../events/activity.controller';
import { countLookupCall } from '../lookup-limit';
import { AccountEventsService } from '../events/account-events.service';
import { parseActivityQuery } from '../events/activity-query';
import { requestMeta } from '../events/request-meta';
import { PortalCsrfGuard } from '../sessions/csrf';
import type { AccountScope, AdminCaller } from '../user-scope';
import { AccountSessionsService } from './account-sessions.service';
import { notAdminOfSystem } from './admin-errors';
import {
  AdminRoute,
  AdminSessionGuard,
  portalAdmin,
  type AdminRequest,
} from './admin-session.guard';
import {
  AdminCreateUserDto,
  AdminDeletionListQueryDto,
  AdminListUsersQueryDto,
  AdminLookupQueryDto,
  AdminOptionalSystemDto,
  AdminRejectDto,
  AdminSetStatusDto,
  AdminSystemDto,
  AdminSystemReauthDto,
  AdminUpdateUserDto,
  AdminVerifyPasswordDto,
} from './admin.dto';

import { ApiTags } from '@nestjs/swagger';
import {
  ApiCookieRoute,
  ApiErrorMap,
  ApiGenericErrors,
  ApiSsoCookie,
} from '../../openapi/decorators';
import {
  ADMIN_SESSION,
  ADMIN_STEP,
  CODE_MAIL,
  CSRF,
  NOT_FOUND,
  PASSWORD_CHECK,
  VALIDATION,
} from '../../openapi/guard-errors';
const systemRequired = () =>
  coded(
    HttpStatus.BAD_REQUEST,
    'VALIDATION_FAILED',
    `system must be one of ${Object.values(SystemType).join(', ')}`,
  );

/**
 * Spec 0013, AC-16, AC-17: the scope an admin acts in for one system. A system admin must pass a
 * system they hold the admin role of (403 `NOT_ADMIN_OF_SYSTEM`); a suite admin may pass any.
 */
export function systemScope(
  req: AdminRequest,
  system: SystemType,
): AdminCaller {
  const caller = portalAdmin(req);
  const suite = caller.standing.suiteAdmin;
  if (!suite && !caller.standing.adminOf.includes(system)) {
    throw notAdminOfSystem();
  }
  return {
    id: caller.userId,
    email: caller.user.email,
    system,
    sid: caller.sid,
    suite,
    meta: requestMeta(req),
  };
}

/**
 * AC-17: on the routes where a suite admin may leave `system` out (lists, activity, deletion
 * requests, delete, restore, the deletion decisions). A system admin still must pass one (400).
 */
export function accountScope(
  req: AdminRequest,
  system: SystemType | undefined,
): AccountScope {
  if (system !== undefined) return systemScope(req, system);
  const caller = portalAdmin(req);
  if (!caller.standing.suiteAdmin) throw systemRequired();
  return {
    id: caller.userId,
    email: caller.user.email,
    system: null,
    sid: caller.sid,
    suite: true,
    meta: requestMeta(req),
  };
}

/** `system` from a hand parsed query (the activity routes): unknown is 400, missing undefined. */
function querySystem(query: Record<string, unknown>): SystemType | undefined {
  const system = query.system;
  if (system === undefined) return undefined;
  if (
    typeof system !== 'string' ||
    !(Object.values(SystemType) as string[]).includes(system)
  ) {
    throw systemRequired();
  }
  return system as SystemType;
}

/**
 * Spec 0013, AC-14, AC-16: the portal's account routes, authenticated by the `welinc_sso`
 * cookie, each write behind `PortalCsrfGuard`, every route needing a session that passed the
 * code (the guard's default level). Each one runs the same service as its bearer route, so the
 * scope, self, last admin and shared account rules match exactly.
 */
@ApiTags('Portal Admin Accounts')
@ApiSsoCookie()
@ApiGenericErrors()
@Controller('auth/admin')
@UseGuards(AdminSessionGuard)
export class AdminAccountsController {
  constructor(
    private readonly authService: AuthService,
    private readonly deletion: DeletionService,
    private readonly events: AccountEventsService,
    private readonly accountSessions: AccountSessionsService,
    @InjectThrottlerStorage() private readonly storage: ThrottlerStorage,
  ) {}

  /** AC-14: a reauth token bound to this cookie session; `ADMIN_ACTION` or `TEMPORARY_ACCESS`. */
  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_STEP, CSRF, PASSWORD_CHECK, {
    400: ['VALIDATION_FAILED'],
    403: ['NOT_SUITE_ADMIN'],
    429: ['RATE_LIMITED'],
  })
  @Post('verify-password')
  @HttpCode(HttpStatus.OK)
  @AdminRoute('admin')
  @UseGuards(PortalCsrfGuard)
  async verifyPassword(
    @Req() req: AdminRequest,
    @Body() dto: AdminVerifyPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const caller = portalAdmin(req);
    await countPasswordCheck(this.storage, caller.userId, res);
    return this.deletion.verifyPassword(
      { sub: caller.userId, sid: caller.sid, meta: requestMeta(req) },
      dto.password,
      dto.purpose,
      'admin',
    );
  }

  @ApiErrorMap(VALIDATION, ADMIN_SESSION, {
    400: ['INVALID_CURSOR', 'UNKNOWN_ROLE', 'VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM'],
  })
  @Get('users')
  listUsers(
    @Query() query: AdminListUsersQueryDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    return this.authService.listPeople(query, accountScope(req, query.system));
  }

  // Declared before users/:id so "lookup" is never read as an id
  // Suite spec 0014, AC-9: 30 a minute per admin, one counter with the bearer route
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, {
    403: ['NOT_ADMIN_OF_SYSTEM'],
    429: ['RATE_LIMITED'],
  })
  @Get('users/lookup')
  async lookupUsers(
    @Query() query: AdminLookupQueryDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const scope = systemScope(req, query.system);
    await countLookupCall(this.storage, scope.id, res);
    return this.authService.lookupUsers(query.q, scope);
  }

  @ApiErrorMap(VALIDATION, ADMIN_SESSION, NOT_FOUND, {
    400: ['VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM'],
  })
  @Get('users/:id')
  getUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: AdminOptionalSystemDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    return this.authService.getPerson(id, accountScope(req, query.system));
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, {
    400: ['UNKNOWN_ROLE'],
    403: ['NOT_ADMIN_OF_SYSTEM', 'REAUTH_REQUIRED', null],
    409: ['ACCOUNT_EXISTS', 'ROLE_LIMIT', 'SUITE_ADMIN_NO_ROLES', null],
  })
  @Post('users')
  @UseGuards(PortalCsrfGuard)
  createUser(@Body() dto: AdminCreateUserDto, @Req() req: AdminRequest) {
    const { system, ...body } = dto;
    return this.authService.createUser(body, systemScope(req, system));
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    400: ['UNKNOWN_ROLE'],
    403: [
      'NOT_ADMIN_OF_SYSTEM',
      'REAUTH_REQUIRED',
      'SUITE_ADMIN_SELF_ONLY',
      null,
    ],
    409: [
      'EMAIL_TAKEN',
      'IS_SUITE_ADMIN',
      'LAST_ADMIN',
      'ROLE_LIMIT',
      'SELF_EMAIL',
      'SUITE_ADMIN_NO_ROLES',
      'TEMPORARY_ROLE',
      null,
    ],
  })
  @Patch('users/:id')
  @UseGuards(PortalCsrfGuard)
  updateUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminUpdateUserDto,
    @Req() req: AdminRequest,
  ) {
    const { system, ...body } = dto;
    return this.authService.updateUser(id, body, systemScope(req, system));
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    403: ['NOT_ADMIN_OF_SYSTEM'],
    409: ['IS_SUITE_ADMIN', 'LAST_ADMIN', null],
  })
  @Patch('users/:id/status')
  @UseGuards(PortalCsrfGuard)
  setStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminSetStatusDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.updateUserStatus(
      id,
      { isActive: dto.isActive },
      systemScope(req, dto.system),
    );
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    403: ['NOT_ADMIN_OF_SYSTEM', 'REAUTH_REQUIRED'],
  })
  @Patch('users/:id/unlock')
  @UseGuards(PortalCsrfGuard)
  unlock(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminSystemReauthDto,
    @Req() req: AdminRequest,
  ) {
    return this.authService.unlockUser(
      id,
      systemScope(req, dto.system),
      dto.reauthToken,
    );
  }

  /** A reset code, or a setup code while setup is pending (AC-16, spec 0009). */
  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, CODE_MAIL, {
    403: ['NOT_ADMIN_OF_SYSTEM', 'REAUTH_REQUIRED'],
    409: ['NOT_ACTIVE'],
  })
  @Post('users/:id/reset-code')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(PortalCsrfGuard)
  async sendResetCode(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminSystemReauthDto,
    @Req() req: AdminRequest,
  ): Promise<void> {
    await this.authService.sendPasswordCode(
      id,
      systemScope(req, dto.system),
      dto.reauthToken,
    );
  }

  @ApiErrorMap(VALIDATION, ADMIN_SESSION, NOT_FOUND, {
    403: ['NOT_ADMIN_OF_SYSTEM'],
  })
  @Get('users/:id/sessions')
  async sessions(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: AdminSystemDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    return {
      sessions: await this.accountSessions.list(
        id,
        systemScope(req, query.system),
      ),
    };
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    403: ['NOT_ADMIN_OF_SYSTEM', 'REAUTH_REQUIRED', null],
  })
  @Delete('users/:id/sessions')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(PortalCsrfGuard)
  async endSessions(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminSystemReauthDto,
    @Req() req: AdminRequest,
  ): Promise<void> {
    await this.accountSessions.endAll(
      id,
      systemScope(req, dto.system),
      dto.reauthToken,
    );
  }

  @ApiErrorMap(VALIDATION, ADMIN_SESSION, NOT_FOUND, {
    400: ['INVALID_CURSOR', 'VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM'],
  })
  @Get('users/:id/activity')
  userActivity(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: Record<string, unknown>,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const scope = accountScope(req, querySystem(query));
    const filters = parseActivityQuery(query, { type: true, dates: true });
    return this.events.listForUser(id, scope.system, filters);
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    400: ['VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM', null],
    409: ['IS_SUITE_ADMIN', 'LAST_ADMIN', null],
  })
  @Delete('users/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(PortalCsrfGuard)
  async deleteUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Query() query: AdminOptionalSystemDto,
    @Req() req: AdminRequest,
  ): Promise<void> {
    const actor = accountScope(req, query.system);
    await this.authService.deleteUser(id, actor);
    // Spec 0012, AC-13: the AC-10 emails, after the commit
    await this.deletion.notifyAdminDelete(id, actor);
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    400: ['VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM'],
    409: ['NOT_RESTORABLE'],
  })
  @Post('users/:id/restore')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  async restoreUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminOptionalSystemDto,
    @Req() req: AdminRequest,
  ) {
    const user = await this.authService.restoreUser(
      id,
      accountScope(req, dto.system),
    );
    await this.deletion.notifyRestored(id);
    return user;
  }

  /** Spec 0011, AC-13: the system's feed, 60 calls a minute per admin across both families. */
  @ApiErrorMap(ADMIN_SESSION, {
    400: ['INVALID_CURSOR', 'VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM'],
    429: ['RATE_LIMITED'],
  })
  @Get('activity')
  async activity(
    @Query() query: Record<string, unknown>,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const scope = accountScope(req, querySystem(query));
    await countFeedCall(this.storage, scope.id, res);
    const filters = parseActivityQuery(query, {
      type: true,
      dates: true,
      feed: true,
    });
    return this.events.feed(scope.system, filters);
  }

  @ApiErrorMap(VALIDATION, ADMIN_SESSION, {
    400: ['INVALID_CURSOR', 'VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM'],
  })
  @Get('deletion-requests')
  deletionRequests(
    @Query() query: AdminDeletionListQueryDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const { system, ...rest } = query;
    return this.deletion.list(accountScope(req, system).system, rest);
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    400: ['VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM', 'SELF_DECISION'],
    409: ['LAST_ADMIN', 'NOT_PENDING'],
  })
  @Post('deletion-requests/:id/approve')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  approve(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminOptionalSystemDto,
    @Req() req: AdminRequest,
  ) {
    return this.deletion.approve(id, accountScope(req, dto.system));
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, NOT_FOUND, {
    400: ['VALIDATION_FAILED'],
    403: ['NOT_ADMIN_OF_SYSTEM', 'SELF_DECISION'],
    409: ['NOT_PENDING'],
  })
  @Post('deletion-requests/:id/reject')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  reject(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AdminRejectDto,
    @Req() req: AdminRequest,
  ) {
    return this.deletion.reject(id, dto.note, accountScope(req, dto.system));
  }
}
