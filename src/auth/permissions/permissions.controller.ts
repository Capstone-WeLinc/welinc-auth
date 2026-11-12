import {
  Controller,
  Get,
  HttpStatus,
  Param,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { SystemType } from '@prisma/client';
import type { Response } from 'express';
import { coded } from '../errors';
import { matchesEtag } from '../roles/systems.controller';
import { MatrixService, matrixEtag } from './matrix.service';
import {
  PermissionsReadGuard,
  type PermissionsReadRequest,
} from './permissions-read.guard';

/** A system code from the path, or 404 for anything else. */
export function systemParam(value: string): SystemType {
  const system = value.toUpperCase();
  if (!(Object.values(SystemType) as string[]).includes(system)) {
    throw coded(HttpStatus.NOT_FOUND, 'NOT_FOUND', 'No such system');
  }
  return system as SystemType;
}

/**
 * `GET /auth/permissions/:system` (spec 0013, AC-26): a system backend polls its own matrix.
 * `If-None-Match` with the current tag answers 304 after one version read, so the poll costs
 * almost nothing while the matrix stays the same.
 */
@Controller('auth/permissions')
@UseGuards(PermissionsReadGuard)
export class PermissionsController {
  constructor(private readonly matrix: MatrixService) {}

  @Get(':system')
  async read(
    @Param('system') raw: string,
    @Req() req: PermissionsReadRequest,
    @Res() res: Response,
  ): Promise<void> {
    const system = systemParam(raw);
    if (req.permissionsClient?.system !== system) {
      throw coded(
        HttpStatus.FORBIDDEN,
        'WRONG_SYSTEM',
        'A system may only read its own matrix',
      );
    }
    res.setHeader('Cache-Control', 'no-cache');

    const current = matrixEtag(await this.matrix.version(system));
    if (matchesEtag(req.headers['if-none-match'], current)) {
      res.setHeader('ETag', current);
      res.status(HttpStatus.NOT_MODIFIED).end();
      return;
    }
    const body = await this.matrix.systemMatrix(system);
    res.setHeader('ETag', matrixEtag(body.version));
    res.status(HttpStatus.OK).json(body);
  }
}
