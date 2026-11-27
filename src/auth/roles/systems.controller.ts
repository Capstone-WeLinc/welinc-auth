import { Controller, Get, Req, Res } from '@nestjs/common';
import { ClientKind, SystemType } from '@prisma/client';
import { createHash } from 'crypto';
import type { Request, Response } from 'express';
import { PrismaService } from '../../shared/prisma.service';
import { CatalogService, type CatalogSystem } from './catalog.service';

import { ApiTags } from '@nestjs/swagger';
import { ApiGenericErrors, ApiNoErrors } from '../../openapi/decorators';
import { ApiHeader, ApiOkResponse, ApiResponse } from '@nestjs/swagger';
import { SystemsResponse } from './systems.response';
export type SystemView = Omit<CatalogSystem, 'code'> & {
  code: SystemType;
  webAddress: string | null;
};

/**
 * Suite spec 0018 child 0002, AC-29: every read revalidates with the ETag (was `max-age=60`), so a
 * custom role made, renamed or deleted shows on the next read; a match still costs only a 304.
 */
export const SYSTEMS_CACHE_CONTROL = 'no-cache';

/** A strong ETag from the body: the same catalog always gives the same tag. */
export function etagOf(body: string): string {
  return `"${createHash('sha256').update(body).digest('base64url').slice(0, 32)}"`;
}

/** True when an `If-None-Match` value names this tag (or `*`); weak tags count (RFC 9110). */
export function matchesEtag(header: string | undefined, etag: string): boolean {
  if (!header) return false;
  return header
    .split(',')
    .map((t) => t.trim().replace(/^W\//, ''))
    .some((t) => t === '*' || t === etag);
}

/**
 * `GET /auth/systems` (spec 0004, AC-16): public on purpose. Role names and descriptions aren't
 * secret, and the launcher and every app's pickers need them before or without a session. No
 * user data, no permissions.
 */
@ApiTags('Systems')
@ApiGenericErrors()
@Controller('auth')
export class SystemsController {
  constructor(
    private readonly catalog: CatalogService,
    private readonly prisma: PrismaService,
  ) {}

  @ApiNoErrors()
  @ApiHeader({
    name: 'If-None-Match',
    required: false,
    description: 'The ETag you hold; a match answers 304',
  })
  @ApiOkResponse({
    type: SystemsResponse,
    headers: {
      ETag: { description: 'A hash of the body', schema: { type: 'string' } },
    },
  })
  @ApiResponse({
    status: 304,
    description: 'Not modified: your copy is current (no body)',
    headers: { ETag: { schema: { type: 'string' } } },
  })
  @Get('systems')
  async systems(@Req() req: Request, @Res() res: Response): Promise<void> {
    const [systems, clients] = await Promise.all([
      this.catalog.systems(),
      this.prisma.oAuthClient.findMany({
        where: { kind: ClientKind.CONFIDENTIAL, isActive: true },
        select: { system: true, webAddress: true },
        orderBy: { id: 'asc' },
      }),
    ]);

    const views: SystemView[] = systems.map((s) => ({
      code: s.code,
      name: s.name,
      description: s.description,
      // The system's active confidential client; the lowest id when there are several
      webAddress: clients.find((c) => c.system === s.code)?.webAddress ?? null,
      maxRolesPerUser: s.maxRolesPerUser,
      roles: s.roles,
    }));
    const body = JSON.stringify({ systems: views });
    const etag = etagOf(body);

    res.setHeader('Cache-Control', SYSTEMS_CACHE_CONTROL);
    res.setHeader('ETag', etag);
    if (matchesEtag(req.headers['if-none-match'], etag)) {
      res.status(304).end();
      return;
    }
    res.status(200).type('application/json').send(body);
  }
}
