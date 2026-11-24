import { HttpException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SystemType } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import type { DeletionService } from '../deletion/deletion.service';
import type { SessionService } from '../sessions/session.service';
import type { SessionSettings } from '../sessions/session-config';
import { AdminController } from './admin.controller';
import { AdminSessionGuard } from './admin-session.guard';
import type {
  AdminStanding,
  AdminStandingService,
} from './admin-standing.service';
import { AdminSummaryService } from './admin-summary.service';
import { groupWhere } from './people-page';

// covers: suite spec 0019 AC-7 (counts in the read scope, no step up, 403 for a non admin)

const fn = jest.fn;

describe('GET /auth/admin/summary guard level', () => {
  function guardFor(standing: AdminStanding) {
    const sessions = {
      liveBySsoHandle: fn().mockResolvedValue({
        id: 'sid-1',
        userId: 'u1',
        // The session never passed the admin sign in code
        signInCodeAt: null,
        user: {
          id: 'u1',
          name: 'Ana',
          email: 'a@welinc.com',
          profilePicture: null,
        },
      }),
    };
    const prisma = {
      user: { findUnique: fn().mockResolvedValue({ lockedAt: null }) },
    };
    const admins = {
      standing: fn().mockResolvedValue(standing),
      codeRequired: fn().mockReturnValue(true),
    };
    return new AdminSessionGuard(
      new Reflector(),
      sessions as unknown as SessionService,
      prisma as unknown as PrismaService,
      admins as unknown as AdminStandingService,
      { ssoCookieSecure: false } as SessionSettings,
    );
  }

  const context = {
    switchToHttp: () => ({ getRequest: () => ({ cookies: {} }) }),
    getHandler: () => AdminController.prototype.summary,
    getClass: () => AdminController,
  } as unknown as ExecutionContext;

  it('lets an admin through whose session has not passed the code', async () => {
    const guard = guardFor({ suiteAdmin: false, adminOf: [SystemType.VRMS] });
    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('answers 403 NOT_AN_ADMIN to someone who administers nothing', async () => {
    const guard = guardFor({ suiteAdmin: false, adminOf: [] });
    const error = await guard.canActivate(context).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(HttpException);
    const http = error as HttpException;
    expect(http.getStatus()).toBe(403);
    expect((http.getResponse() as { code: string }).code).toBe('NOT_AN_ADMIN');
  });
});

describe('AdminSummaryService', () => {
  beforeEach(() =>
    jest.useFakeTimers({ now: new Date('2026-11-24T08:00:00Z') }),
  );
  afterEach(() => jest.useRealTimers());

  function build() {
    const prisma = {
      user: { count: fn().mockResolvedValue(4) },
      temporaryGrant: { count: fn().mockResolvedValue(2) },
    };
    const deletion = { pendingCount: fn().mockResolvedValue(1) };
    return {
      service: new AdminSummaryService(
        prisma as unknown as PrismaService,
        deletion as unknown as DeletionService,
      ),
      prisma,
      deletion,
    };
  }

  it("counts a system admin's systems only, with the People attention rule, and no grants", async () => {
    const { service, prisma, deletion } = build();
    const summary = await service.summaryFor({
      systems: [SystemType.VRMS],
      only: null,
      suite: false,
    });
    expect(summary).toEqual({ needsAttention: 4, deletionRequests: 1 });
    expect(prisma.user.count).toHaveBeenCalledWith({
      where: {
        AND: [
          { deletedAt: null },
          { roles: { some: { system: { in: [SystemType.VRMS] } } } },
          groupWhere('attention'),
        ],
      },
    });
    expect(deletion.pendingCount).toHaveBeenCalledWith([SystemType.VRMS]);
    expect(prisma.temporaryGrant.count).not.toHaveBeenCalled();
  });

  it('counts the whole suite for a suite admin, plus the live temporary grants', async () => {
    const { service, prisma, deletion } = build();
    const summary = await service.summaryFor({
      systems: null,
      only: null,
      suite: true,
    });
    expect(summary).toEqual({
      needsAttention: 4,
      deletionRequests: 1,
      temporaryGrants: 2,
    });
    expect(deletion.pendingCount).toHaveBeenCalledWith(null);
    const where = (
      prisma.temporaryGrant.count.mock.calls[0] as [
        { where: { endedAt: null; expiresAt: { gt: Date } } },
      ]
    )[0].where;
    expect(where.endedAt).toBeNull();
    expect(where.expiresAt.gt).toBeInstanceOf(Date);
  });
});
