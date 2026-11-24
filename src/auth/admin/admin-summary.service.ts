import { Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { DeletionService } from '../deletion/deletion.service';
import type { ReadScope } from '../user-scope';
import { groupWhere } from './people-page';
import { liveGrantWhere } from './temporary-grants.service';

/** The `GET /auth/admin/summary` body (suite spec 0019, AC-7): numbers only, never people. */
export type AdminSummary = {
  needsAttention: number;
  deletionRequests: number;
  /** Suite admins only: temporary grants live now. */
  temporaryGrants?: number;
};

/**
 * Suite spec 0019, AC-3, AC-7: the launcher strip's three counts, in the caller's People read
 * scope (every system they admin; the whole suite for a suite admin).
 */
@Injectable()
export class AdminSummaryService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly deletion: DeletionService,
  ) {}

  async summaryFor(scope: ReadScope): Promise<AdminSummary> {
    const systems = scope.systems;
    // The People list's scope and its `attention` group rule (`groupWhere`), never a copy
    const inScope: Prisma.UserWhereInput =
      systems === null ? {} : { roles: { some: { system: { in: systems } } } };
    const [needsAttention, deletionRequests, temporaryGrants] =
      await Promise.all([
        this.prisma.user.count({
          where: {
            AND: [{ deletedAt: null }, inScope, groupWhere('attention')],
          },
        }),
        this.deletion.pendingCount(systems),
        scope.suite
          ? this.prisma.temporaryGrant.count({ where: liveGrantWhere() })
          : undefined,
      ]);
    return {
      needsAttention,
      deletionRequests,
      ...(temporaryGrants !== undefined ? { temporaryGrants } : {}),
    };
  }
}
