import {
  Body,
  Controller,
  Get,
  Param,
  Patch,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Type } from 'class-transformer';
import {
  Allow,
  ArrayMaxSize,
  IsArray,
  IsBoolean,
  IsInt,
  IsOptional,
  IsString,
  Matches,
  MaxLength,
  Min,
  ValidateNested,
} from 'class-validator';
import type { Response } from 'express';
import { systemScope } from '../admin/admin-accounts.controller';
import { notSuiteAdmin } from '../admin/admin-errors';
import {
  AdminSessionGuard,
  portalAdmin,
  type AdminRequest,
} from '../admin/admin-session.guard';
import { ROLE_CODE_RE } from '../roles/catalog.types';
import { PortalCsrfGuard } from '../sessions/csrf';
import { MatrixService, NOTE_MAX } from './matrix.service';
import { systemParam } from './permissions.controller';

import { ApiTags } from '@nestjs/swagger';
import {
  ApiCookieRoute,
  ApiGenericErrors,
  ApiSsoCookie,
} from '../../openapi/decorators';
// Spec 0013, AC-27: the matrix in the portal. Suite admins and the admins of that system read it;
// only suite admins save.

export class MatrixCellDto {
  @IsString()
  @Matches(ROLE_CODE_RE)
  role!: string;

  @IsString()
  @MaxLength(60)
  key!: string;

  @IsBoolean()
  allowed!: boolean;
}

export class UpdateMatrixDto {
  @IsInt()
  @Min(1)
  version!: number;

  @IsArray()
  @ArrayMaxSize(500)
  @ValidateNested({ each: true })
  @Type(() => MatrixCellDto)
  changes!: MatrixCellDto[];

  @IsOptional()
  @IsString()
  @MaxLength(NOTE_MAX)
  note?: string;
}

export class MatrixChangesQueryDto {
  @Allow()
  cursor?: unknown;

  @Allow()
  limit?: unknown;
}

/** Cookie authenticated like every `/auth/admin/*` route, each needing the code (AC-6). */
@ApiTags('Portal Admin Permissions')
@ApiSsoCookie()
@ApiGenericErrors()
@Controller('auth/admin/permissions')
@UseGuards(AdminSessionGuard)
export class AdminPermissionsController {
  constructor(private readonly matrix: MatrixService) {}

  @Get(':system')
  async read(
    @Param('system') raw: string,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const scope = systemScope(req, systemParam(raw));
    return this.matrix.adminMatrix(scope.system, scope.suite === true);
  }

  @ApiCookieRoute()
  @Patch(':system')
  @UseGuards(PortalCsrfGuard)
  update(
    @Param('system') raw: string,
    @Body() dto: UpdateMatrixDto,
    @Req() req: AdminRequest,
  ) {
    const system = systemParam(raw);
    const caller = portalAdmin(req);
    if (!caller.standing.suiteAdmin) throw notSuiteAdmin();
    return this.matrix.update(
      { id: caller.userId, name: caller.user.name, email: caller.user.email },
      system,
      { version: dto.version, changes: dto.changes, note: dto.note },
    );
  }

  @Get(':system/changes')
  async changes(
    @Param('system') raw: string,
    @Query() query: MatrixChangesQueryDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const scope = systemScope(req, systemParam(raw));
    const limit = Number(query.limit);
    return this.matrix.changes(scope.system, {
      cursor:
        typeof query.cursor === 'string' && query.cursor
          ? query.cursor
          : undefined,
      limit: Number.isInteger(limit) ? limit : undefined,
    });
  }
}
