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
import { SystemType } from '@prisma/client';
import {
  Allow,
  IsEnum,
  IsString,
  IsUUID,
  Matches,
  MaxLength,
} from 'class-validator';
import type { Response } from 'express';
import { requestMeta } from '../events/request-meta';
import { ROLE_CODE_RE } from '../roles/catalog.types';
import { PortalCsrfGuard } from '../sessions/csrf';
import { notSuiteAdmin } from './admin-errors';
import { AdminReportService } from './admin-report.service';
import {
  AdminSessionGuard,
  portalAdmin,
  type AdminRequest,
  type PortalAdmin,
} from './admin-session.guard';
import { SuiteAdminsService } from './suite-admins.service';
import { TemporaryGrantsService } from './temporary-grants.service';

// Spec 0013, AC-1, AC-2, AC-9 to AC-11, AC-19: the suite admin routes. Reasons, hours and the
// reauth token are checked by the services, so their errors match the spec's codes.

export class AddSuiteAdminDto {
  @IsUUID()
  userId!: string;

  @IsString()
  @MaxLength(2000)
  reason!: string;

  @Allow()
  reauthToken?: string;
}

export class RemoveSuiteAdminDto {
  @IsString()
  @MaxLength(2000)
  reason!: string;

  @Allow()
  reauthToken?: string;
}

export class StartGrantDto {
  @IsEnum(SystemType)
  system!: SystemType;

  @IsString()
  @Matches(ROLE_CODE_RE)
  role!: string;

  @Allow()
  hours?: unknown;

  @IsString()
  @MaxLength(2000)
  reason!: string;

  @Allow()
  reauthToken?: string;
}

export class GrantListQueryDto {
  @Allow()
  state?: unknown;

  @Allow()
  system?: unknown;

  @Allow()
  cursor?: unknown;

  @Allow()
  limit?: unknown;
}

function suiteOnly(req: AdminRequest): PortalAdmin {
  const caller = portalAdmin(req);
  if (!caller.standing.suiteAdmin) throw notSuiteAdmin();
  return caller;
}

const token = (value: unknown) =>
  typeof value === 'string' ? value : undefined;

/** Cookie authenticated like every `/auth/admin/*` route, each needing the code (AC-6). */
@Controller('auth/admin')
@UseGuards(AdminSessionGuard)
export class SuiteAdminController {
  constructor(
    private readonly suiteAdmins: SuiteAdminsService,
    private readonly grants: TemporaryGrantsService,
    private readonly reports: AdminReportService,
  ) {}

  @Get('suite-admins')
  async list(
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    suiteOnly(req);
    return { items: await this.suiteAdmins.list() };
  }

  @Post('suite-admins')
  @UseGuards(PortalCsrfGuard)
  add(@Body() dto: AddSuiteAdminDto, @Req() req: AdminRequest) {
    const caller = suiteOnly(req);
    return this.suiteAdmins.add(
      { id: caller.userId, sid: caller.sid, meta: requestMeta(req) },
      {
        userId: dto.userId,
        reason: dto.reason,
        reauthToken: token(dto.reauthToken),
      },
    );
  }

  /** A `POST`, since some clients drop `DELETE` bodies (AC-2). */
  @Post('suite-admins/:userId/remove')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(PortalCsrfGuard)
  async remove(
    @Param('userId', ParseUUIDPipe) userId: string,
    @Body() dto: RemoveSuiteAdminDto,
    @Req() req: AdminRequest,
  ): Promise<void> {
    const caller = suiteOnly(req);
    await this.suiteAdmins.remove(
      { id: caller.userId, sid: caller.sid, meta: requestMeta(req) },
      userId,
      { reason: dto.reason, reauthToken: token(dto.reauthToken) },
    );
  }

  @Get('temporary-grants')
  listGrants(
    @Query() query: GrantListQueryDto,
    @Req() req: AdminRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    res.setHeader('Cache-Control', 'no-store');
    const caller = portalAdmin(req);
    return this.grants.list(
      { id: caller.userId, sid: caller.sid, standing: caller.standing },
      query,
    );
  }

  @Post('temporary-grants')
  @UseGuards(PortalCsrfGuard)
  startGrant(@Body() dto: StartGrantDto, @Req() req: AdminRequest) {
    const caller = portalAdmin(req);
    return this.grants.grant(
      {
        id: caller.userId,
        sid: caller.sid,
        standing: caller.standing,
        meta: requestMeta(req),
      },
      {
        system: dto.system,
        role: dto.role,
        hours: dto.hours,
        reason: dto.reason,
        reauthToken: token(dto.reauthToken),
      },
    );
  }

  @Delete('temporary-grants/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @UseGuards(PortalCsrfGuard)
  async endGrant(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: AdminRequest,
  ): Promise<void> {
    const caller = portalAdmin(req);
    await this.grants.endEarly(
      {
        id: caller.userId,
        sid: caller.sid,
        standing: caller.standing,
        meta: requestMeta(req),
      },
      id,
    );
  }

  @Get('report')
  report(@Req() req: AdminRequest, @Res({ passthrough: true }) res: Response) {
    res.setHeader('Cache-Control', 'no-store');
    suiteOnly(req);
    return this.reports.report();
  }
}
