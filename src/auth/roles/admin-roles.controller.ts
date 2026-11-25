import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import {
  Allow,
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
} from 'class-validator';
import type { Response } from 'express';
import {
  ApiCookieRoute,
  ApiErrorMap,
  ApiGenericErrors,
  ApiSsoCookie,
} from '../../openapi/decorators';
import { ADMIN_SESSION, CSRF, VALIDATION } from '../../openapi/guard-errors';
import { systemScope } from '../admin/admin-accounts.controller';
import {
  AdminSessionGuard,
  type AdminRequest,
} from '../admin/admin-session.guard';
import { AuthService } from '../auth.service';
import { coded } from '../errors';
import { systemParam } from '../permissions/permissions.controller';
import { PortalCsrfGuard } from '../sessions/csrf';
import { ROLE_CODE_RE } from './catalog.types';
import { RolesAdminService } from './roles-admin.service';

// Suite spec 0018, child 0001 (AC-17): the Roles page routes. Suite admins and the admins of the
// system read; Add people is a role change, open to the same admins as Change role (spec 0017).
// Changing permissions stays on PATCH /auth/admin/permissions/:system.

export class RoleHistoryQueryDto {
  @Allow()
  cursor?: unknown;

  @Allow()
  limit?: unknown;
}

export class AddRoleMembersDto {
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(50)
  @IsUUID('all', { each: true })
  userIds!: string[];

  @IsOptional()
  @IsString()
  @MaxLength(200)
  reauthToken?: string;
}

/** 404 for a value that can't be a role code (the role routes' `:code`). */
function roleParam(value: string): string {
  if (!ROLE_CODE_RE.test(value)) {
    throw coded(HttpStatus.NOT_FOUND, 'NOT_FOUND', 'No such role');
  }
  return value;
}

/** Cookie authenticated like every `/auth/admin/*` route, each needing the code. */
@ApiTags('Portal Admin Roles')
@ApiSsoCookie()
@ApiGenericErrors()
@Controller('auth/admin/roles')
@UseGuards(AdminSessionGuard)
export class AdminRolesController {
  constructor(
    private readonly roles: RolesAdminService,
    private readonly authService: AuthService,
  ) {}

  @ApiErrorMap(ADMIN_SESSION, {
    403: ['NOT_ADMIN_OF_SYSTEM'],
    404: ['NOT_FOUND'],
  })
  @Get(':system')
  read(
    @Param('system') raw: string,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const scope = systemScope(req, systemParam(raw));
    return this.roles.page(scope.system, scope.suite === true);
  }

  @ApiErrorMap(VALIDATION, ADMIN_SESSION, {
    400: ['INVALID_CURSOR'],
    403: ['NOT_ADMIN_OF_SYSTEM'],
    404: ['NOT_FOUND'],
  })
  @Get(':system/:code/history')
  history(
    @Param('system') raw: string,
    @Param('code') code: string,
    @Query() query: RoleHistoryQueryDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const scope = systemScope(req, systemParam(raw));
    const limit = Number(query.limit);
    return this.roles.history(scope.system, roleParam(code), {
      cursor:
        typeof query.cursor === 'string' && query.cursor
          ? query.cursor
          : undefined,
      limit: Number.isInteger(limit) ? limit : undefined,
    });
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, {
    400: ['NOT_IN_SYSTEM', 'UNKNOWN_ROLE'],
    403: ['NOT_ADMIN_OF_SYSTEM', 'REAUTH_REQUIRED'],
    404: ['NOT_FOUND'],
    409: [
      'LAST_ADMIN',
      'ROLE_LIMIT',
      'SELF_ROLE',
      'SUITE_ADMIN_NO_ROLES',
      'TEMPORARY_ROLE',
    ],
  })
  @Post(':system/:code/members')
  @HttpCode(HttpStatus.OK)
  @UseGuards(PortalCsrfGuard)
  async addMembers(
    @Param('system') raw: string,
    @Param('code') code: string,
    @Body() dto: AddRoleMembersDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const scope = systemScope(req, systemParam(raw));
    return this.authService.moveToRole(
      roleParam(code),
      dto.userIds,
      dto.reauthToken,
      scope,
    );
  }
}
