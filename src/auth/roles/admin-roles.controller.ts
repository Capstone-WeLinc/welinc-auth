import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Patch,
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
import { notSuiteAdmin } from '../admin/admin-errors';
import {
  AdminSessionGuard,
  portalAdmin,
  type AdminRequest,
} from '../admin/admin-session.guard';
import { AuthService } from '../auth.service';
import { coded } from '../errors';
import { systemParam } from '../permissions/permissions.controller';
import { PortalCsrfGuard } from '../sessions/csrf';
import { ROLE_CODE_RE } from './catalog.types';
import { CustomRolesService, type RoleActor } from './custom-roles.service';
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

/** Child 0002, AC-20 to AC-22: the exact name and description rules run in the service. */
export class CreateRoleDto {
  @IsString()
  @MaxLength(200)
  name!: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;

  @IsString()
  @MaxLength(40)
  from!: string;
}

/** Child 0002, AC-24: one field or both. */
export class UpdateRoleDto {
  @IsOptional()
  @IsString()
  @MaxLength(200)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  description?: string;
}

/** Creating, renaming and deleting roles is for suite admins only (umbrella security model). */
function suiteActor(req: AdminRequest): RoleActor {
  const caller = portalAdmin(req);
  if (!caller.standing.suiteAdmin) throw notSuiteAdmin();
  return {
    id: caller.userId,
    name: caller.user.name,
    email: caller.user.email,
  };
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
    private readonly customRoles: CustomRolesService,
    private readonly authService: AuthService,
  ) {}

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, {
    400: ['UNKNOWN_ROLE', 'VALIDATION_FAILED'],
    403: ['NOT_SUITE_ADMIN'],
    404: ['NOT_FOUND'],
    409: ['CUSTOM_ROLES_NOT_SUPPORTED', 'CUSTOM_ROLE_LIMIT', 'ROLE_NAME_TAKEN'],
  })
  @Post(':system')
  @UseGuards(PortalCsrfGuard)
  async create(
    @Param('system') raw: string,
    @Body() dto: CreateRoleDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const system = systemParam(raw);
    return this.customRoles.create(suiteActor(req), system, {
      name: dto.name,
      description: dto.description,
      from: dto.from,
    });
  }

  @ApiCookieRoute()
  @ApiErrorMap(VALIDATION, ADMIN_SESSION, CSRF, {
    400: ['BUILT_IN_ROLE', 'VALIDATION_FAILED'],
    403: ['NOT_SUITE_ADMIN'],
    404: ['NOT_FOUND'],
    409: ['ROLE_NAME_TAKEN'],
  })
  @Patch(':system/:code')
  @UseGuards(PortalCsrfGuard)
  async update(
    @Param('system') raw: string,
    @Param('code') code: string,
    @Body() dto: UpdateRoleDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const system = systemParam(raw);
    return this.customRoles.update(suiteActor(req), system, roleParam(code), {
      name: dto.name,
      description: dto.description,
    });
  }

  @ApiCookieRoute()
  @ApiErrorMap(ADMIN_SESSION, CSRF, {
    400: ['BUILT_IN_ROLE'],
    403: ['NOT_SUITE_ADMIN'],
    404: ['NOT_FOUND'],
    409: ['ROLE_IN_USE'],
  })
  @Delete(':system/:code')
  @UseGuards(PortalCsrfGuard)
  async remove(
    @Param('system') raw: string,
    @Param('code') code: string,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const system = systemParam(raw);
    return this.customRoles.remove(suiteActor(req), system, roleParam(code));
  }

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
