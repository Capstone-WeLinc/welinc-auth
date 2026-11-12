import {
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import {
  AccountEventType,
  Prisma,
  ReauthPurpose,
  TemporaryGrantEnd,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { AccountEventsService } from '../events/account-events.service';
import type { RequestMeta } from '../events/request-meta';
import { PasswordCheckService } from '../reauth/password-check.service';
import { MAX_SUITE_ADMINS } from '../../../prisma/seeds/manifest';
import { AdminAlertsService } from './admin-alerts.service';
import {
  alreadySuiteAdmin,
  holdsSystemRoles,
  isSuiteAdminNoRolesError,
  lastSuiteAdmin,
  notEligible,
  notSuiteAdmin,
  selfSuiteAdmin,
  suiteAdminLimit,
  suiteAdminNoRoles,
} from './admin-errors';
import { lockSuiteAdmins, reasonProblem } from './admin-recovery.service';
import { TemporaryGrantsService } from './temporary-grants.service';

type Tx = Prisma.TransactionClient;

export type SuiteAdminView = {
  id: string;
  name: string;
  email: string;
  grantedAt: string;
  /** Null for the seed or the recovery script. */
  grantedBy: { id: string; name: string } | null;
  reason: string | null;
};

export type SuiteActor = { id: string; sid: string; meta?: RequestMeta };

const SUITE_ADMIN_SELECT = {
  grantedAt: true,
  reason: true,
  user: { select: { id: true, name: true, email: true } },
  grantedBy: { select: { id: true, name: true } },
} satisfies Prisma.SuiteAdminSelect;

type SuiteAdminRow = Prisma.SuiteAdminGetPayload<{
  select: typeof SUITE_ADMIN_SELECT;
}>;

function viewOf(row: SuiteAdminRow): SuiteAdminView {
  return {
    id: row.user.id,
    name: row.user.name,
    email: row.user.email,
    grantedAt: row.grantedAt.toISOString(),
    grantedBy: row.grantedBy
      ? { id: row.grantedBy.id, name: row.grantedBy.name || 'Deleted user' }
      : null,
    reason: row.reason,
  };
}

const validationFailed = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);

/**
 * Spec 0013, AC-1 to AC-4: 1 to 3 suite admins, added and removed only by another suite admin
 * (or the recovery script), with a reason and the actor's `ADMIN_ACTION` password recheck. Every
 * change takes the `suite_admins` advisory lock first, then the target row, then decides.
 */
@Injectable()
export class SuiteAdminsService {
  private readonly logger = new Logger('SuiteAdmins');

  constructor(
    private readonly prisma: PrismaService,
    private readonly events: AccountEventsService,
    private readonly passwords: PasswordCheckService,
    private readonly grants: TemporaryGrantsService,
    private readonly alerts: AdminAlertsService,
  ) {}

  async list(db: Tx | PrismaService = this.prisma): Promise<SuiteAdminView[]> {
    const rows = await db.suiteAdmin.findMany({
      select: SUITE_ADMIN_SELECT,
      orderBy: [{ grantedAt: 'asc' }, { userId: 'asc' }],
    });
    return rows.map(viewOf);
  }

  /** AC-1 */
  async add(
    actor: SuiteActor,
    input: { userId: string; reason: string; reauthToken?: string },
  ): Promise<SuiteAdminView> {
    const reason = this.checkReason(input.reason);
    let row: SuiteAdminRow;
    try {
      row = await this.prisma.$transaction(async (tx) => {
        await this.useReauth(tx, actor, input.reauthToken);
        await lockSuiteAdmins(tx);
        await this.assertStillSuiteAdmin(tx, actor.id);

        const [target] = await tx.$queryRaw<
          {
            id: string;
            is_active: boolean;
            deleted_at: Date | null;
            locked_at: Date | null;
            email_verified: boolean;
          }[]
        >`
          SELECT id, is_active, deleted_at, locked_at, email_verified
          FROM users WHERE id = ${input.userId}::uuid FOR UPDATE`;
        if (!target) throw new NotFoundException('User not found');

        const already = await tx.suiteAdmin.findUnique({
          where: { userId: target.id },
          select: { userId: true },
        });
        if (already) throw alreadySuiteAdmin();
        if ((await tx.suiteAdmin.count()) >= MAX_SUITE_ADMINS) {
          throw suiteAdminLimit();
        }
        if (
          !target.is_active ||
          target.deleted_at !== null ||
          target.locked_at !== null ||
          !target.email_verified
        ) {
          throw notEligible();
        }
        const roles = await tx.userRoleAssignment.count({
          where: { userId: target.id },
        });
        if (roles > 0) throw holdsSystemRoles();

        await tx.suiteAdmin.create({
          data: { userId: target.id, grantedById: actor.id, reason },
        });
        await this.events.record(tx, {
          userId: target.id,
          actorId: actor.id,
          type: AccountEventType.SUITE_ADMIN_ACTIONED,
          reason,
          meta: actor.meta,
        });
        return tx.suiteAdmin.findUniqueOrThrow({
          where: { userId: target.id },
          select: SUITE_ADMIN_SELECT,
        });
      });
    } catch (error) {
      // The deferred trigger: a role written at the same moment (AC-3)
      if (isSuiteAdminNoRolesError(error)) throw suiteAdminNoRoles();
      throw error;
    }

    this.logger.log(`suite admin added user=${row.user.id} by=${actor.id}`);
    await this.alerts.send(actor.id, [
      {
        kind: 'SUITE_ADMIN_ADDED',
        targetId: row.user.id,
        systems: 'ALL',
        reason,
      },
    ]);
    return viewOf(row);
  }

  /** AC-2: also ends the person's live temporary grants (`SUITE_ADMIN_REMOVED`). */
  async remove(
    actor: SuiteActor,
    userId: string,
    input: { reason: string; reauthToken?: string },
  ): Promise<void> {
    if (userId === actor.id) throw selfSuiteAdmin();
    const reason = this.checkReason(input.reason);

    await this.prisma.$transaction(async (tx) => {
      await this.useReauth(tx, actor, input.reauthToken);
      await lockSuiteAdmins(tx);
      await this.assertStillSuiteAdmin(tx, actor.id);
      const [target] = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM users WHERE id = ${userId}::uuid FOR UPDATE`;
      const row = target
        ? await tx.suiteAdmin.findUnique({
            where: { userId },
            select: { userId: true },
          })
        : null;
      if (!row) throw new NotFoundException('Suite admin not found');
      if ((await tx.suiteAdmin.count()) <= 1) throw lastSuiteAdmin();

      await this.grants.endAllInTx(
        tx,
        userId,
        TemporaryGrantEnd.SUITE_ADMIN_REMOVED,
        actor.id,
        actor.meta,
      );
      await tx.suiteAdmin.delete({ where: { userId } });
      await this.events.record(tx, {
        userId,
        actorId: actor.id,
        type: AccountEventType.SUITE_ADMIN_REMOVED,
        reason,
        meta: actor.meta,
      });
    });

    this.logger.log(`suite admin removed user=${userId} by=${actor.id}`);
    await this.alerts.send(actor.id, [
      {
        kind: 'SUITE_ADMIN_REMOVED',
        targetId: userId,
        systems: 'ALL',
        reason,
        notifyTarget: true,
      },
    ]);
  }

  private checkReason(reason: unknown): string {
    if (typeof reason !== 'string') {
      throw validationFailed('reason must be a string');
    }
    const problem = reasonProblem(reason);
    if (problem) throw validationFailed(problem);
    return reason.trim();
  }

  private useReauth(
    tx: Tx,
    actor: SuiteActor,
    token: string | undefined,
  ): Promise<void> {
    return this.passwords.consumeReauthToken(
      tx,
      token,
      actor.id,
      actor.sid,
      ReauthPurpose.ADMIN_ACTION,
    );
  }

  /** Under the lock: a suite admin removed a moment earlier can't act. */
  private async assertStillSuiteAdmin(tx: Tx, userId: string): Promise<void> {
    const row = await tx.suiteAdmin.findUnique({
      where: { userId },
      select: { userId: true },
    });
    if (!row) throw notSuiteAdmin();
  }
}
