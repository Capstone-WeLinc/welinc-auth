import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Prisma, SystemType } from '@prisma/client';
import type { Env } from '../../config/env';
import { PrismaService } from '../../shared/prisma.service';
import { CatalogService, holdsAdmin } from '../roles/catalog.service';

type Db = Prisma.TransactionClient | PrismaService;

/** What a person may do as an admin (spec 0013, AC-15). */
export type AdminStanding = {
  suiteAdmin: boolean;
  /** Systems where the person holds the `isSystemAdmin` role, in `SystemType` order. */
  adminOf: SystemType[];
};

export function isAdmin(standing: AdminStanding): boolean {
  return standing.suiteAdmin || standing.adminOf.length > 0;
}

/**
 * AC-13, AC-14b: whose admins hear about an action on this person's account: every system for
 * a suite admin, else each system they admin.
 */
export function alertSystemsOf(standing: AdminStanding): SystemType[] | 'ALL' {
  return standing.suiteAdmin ? 'ALL' : standing.adminOf;
}

/**
 * Spec 0013: who counts as an admin, read per call (no cache, like `@SystemAdmin()`), and
 * whether admins must confirm their sign in with a code (`ADMIN_SIGN_IN_CODE`, AC-8).
 */
@Injectable()
export class AdminStandingService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly catalog: CatalogService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  /** AC-8: read at request time, so a restart with a new value applies at once. */
  codeRequired(): boolean {
    return this.config.get('ADMIN_SIGN_IN_CODE', { infer: true });
  }

  async standing(userId: string, db: Db = this.prisma): Promise<AdminStanding> {
    const suite = await db.suiteAdmin.findUnique({
      where: { userId },
      select: { userId: true },
    });
    const roles = await db.userRoleAssignment.findMany({
      where: { userId },
      select: { role: true, system: true },
    });
    const admins = await this.catalog.adminRoles(db);
    return {
      suiteAdmin: suite !== null,
      adminOf: Object.values(SystemType).filter((system) =>
        holdsAdmin(roles, system, admins),
      ),
    };
  }

  /** AC-5: a right password at the portal asks the code when the person is any kind of admin. */
  async asksCodeAtLogin(userId: string): Promise<boolean> {
    if (!this.codeRequired()) return false;
    return isAdmin(await this.standing(userId));
  }
}
