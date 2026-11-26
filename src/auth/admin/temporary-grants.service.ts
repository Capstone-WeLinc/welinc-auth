import {
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import {
  AccountEventType,
  Prisma,
  ReauthPurpose,
  SessionEndReason,
  SystemType,
  TemporaryGrantEnd,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { AccountEventsService } from '../events/account-events.service';
import type { RequestMeta } from '../events/request-meta';
import { PasswordCheckService } from '../reauth/password-check.service';
import { CatalogService } from '../roles/catalog.service';
import { SessionService } from '../sessions/session.service';
import { AdminAlertsService, type AdminAlert } from './admin-alerts.service';
import { grantActive, notAdminOfSystem, notSuiteAdmin } from './admin-errors';
import type { AdminStanding } from './admin-standing.service';
import { reasonProblem } from './admin-recovery.service';
import { reportJobFailure } from '../../monitoring/job-failure';

type Tx = Prisma.TransactionClient;

/** A grant that is live now: not ended and not run out (the report, the banner, the summary). */
export function liveGrantWhere(now: Date = new Date()) {
  return {
    endedAt: null,
    expiresAt: { gt: now },
  } satisfies Prisma.TemporaryGrantWhereInput;
}

/** AC-9: whole hours, 1 to 8, 4 when left out. */
export const GRANT_HOURS_MIN = 1;
export const GRANT_HOURS_MAX = 8;
export const GRANT_HOURS_DEFAULT = 4;

/** The minute sweep's lock key (the hourly sweep holds 3_003_001, catalog sync 4_004_001). */
const GRANT_SWEEP_LOCK_KEY = 3_003_013;
const SWEEP_BATCH = 100;

const PAGE_DEFAULT = 50;
const PAGE_MAX = 100;

/** Who acts on a grant, from the portal admin caller. */
export type GrantActor = {
  id: string;
  sid: string;
  standing: AdminStanding;
  meta?: RequestMeta;
};

export type GrantView = {
  id: string;
  holder: { id: string; name: string; email: string };
  system: SystemType;
  role: string;
  roleName: string;
  reason: string;
  startedAt: string;
  expiresAt: string;
  endedAt: string | null;
  endReason: TemporaryGrantEnd | null;
  endedBy: { id: string; name: string } | null;
};

const GRANT_SELECT = {
  id: true,
  system: true,
  role: true,
  reason: true,
  startedAt: true,
  expiresAt: true,
  endedAt: true,
  endReason: true,
  user: { select: { id: true, name: true, email: true } },
  endedBy: { select: { id: true, name: true } },
  systemRole: { select: { name: true } },
} satisfies Prisma.TemporaryGrantSelect;

type GrantRow = Prisma.TemporaryGrantGetPayload<{
  select: typeof GRANT_SELECT;
}>;

function viewOf(row: GrantRow): GrantView {
  return {
    id: row.id,
    holder: {
      id: row.user.id,
      name: row.user.name || 'Deleted user',
      email: row.user.email,
    },
    system: row.system,
    role: row.role,
    roleName: row.systemRole.name,
    reason: row.reason,
    startedAt: row.startedAt.toISOString(),
    expiresAt: row.expiresAt.toISOString(),
    endedAt: row.endedAt ? row.endedAt.toISOString() : null,
    endReason: row.endReason,
    endedBy: row.endedBy
      ? { id: row.endedBy.id, name: row.endedBy.name || 'Deleted user' }
      : null,
  };
}

const validationFailed = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);

const invalidCursor = () =>
  coded(HttpStatus.BAD_REQUEST, 'INVALID_CURSOR', 'The cursor is not valid');

function encodeCursor(row: { startedAt: Date; id: string }): string {
  return Buffer.from(
    JSON.stringify({ t: row.startedAt.toISOString(), id: row.id }),
  ).toString('base64url');
}

function decodeCursor(cursor: string): { startedAt: Date; id: string } {
  try {
    const value = JSON.parse(
      Buffer.from(cursor, 'base64url').toString('utf8'),
    ) as { t?: unknown; id?: unknown };
    if (typeof value.t !== 'string' || typeof value.id !== 'string') {
      throw new Error('shape');
    }
    const startedAt = new Date(value.t);
    if (Number.isNaN(startedAt.getTime())) throw new Error('date');
    return { startedAt, id: value.id };
  } catch {
    throw invalidCursor();
  }
}

/** Hours from the body: a whole number 1 to 8, or the default. */
export function parseHours(hours: unknown): number {
  if (hours === undefined || hours === null) return GRANT_HOURS_DEFAULT;
  if (
    typeof hours !== 'number' ||
    !Number.isInteger(hours) ||
    hours < GRANT_HOURS_MIN ||
    hours > GRANT_HOURS_MAX
  ) {
    throw validationFailed(
      `hours must be a whole number from ${GRANT_HOURS_MIN} to ${GRANT_HOURS_MAX}`,
    );
  }
  return hours;
}

/**
 * Spec 0013, AC-9 to AC-11: a suite admin's own temporary role in one system. A grant and its
 * `user_roles` row are written together and removed together; the end also signs the holder out
 * of every session that opened that system. Expiry runs every minute and, lazily, in every role
 * read that builds a token (`liveRoleWhere`).
 */
@Injectable()
export class TemporaryGrantsService {
  private readonly logger = new Logger('TemporaryGrants');

  constructor(
    private readonly prisma: PrismaService,
    private readonly catalog: CatalogService,
    private readonly events: AccountEventsService,
    private readonly sessions: SessionService,
    private readonly passwords: PasswordCheckService,
    private readonly alerts: AdminAlertsService,
  ) {}

  /** AC-9: for the caller only, a suite admin, with a `TEMPORARY_ACCESS` reauth token. */
  async grant(
    actor: GrantActor,
    input: {
      system: SystemType;
      role: string;
      hours?: unknown;
      reason: string;
      reauthToken?: string;
    },
  ): Promise<GrantView> {
    if (!actor.standing.suiteAdmin) throw notSuiteAdmin();
    const hours = parseHours(input.hours);
    const problem = reasonProblem(input.reason);
    if (problem) throw validationFailed(problem);
    const reason = input.reason.trim();
    await this.catalog.assertKnownRole(input.system, input.role);

    let row: GrantRow;
    try {
      row = await this.prisma.$transaction(async (tx) => {
        await this.passwords.consumeReauthToken(
          tx,
          input.reauthToken,
          actor.id,
          actor.sid,
          ReauthPurpose.TEMPORARY_ACCESS,
        );
        // A suite admin removed a moment earlier can't start a grant
        const [still] = await tx.$queryRaw<{ user_id: string }[]>`
          SELECT user_id FROM suite_admins WHERE user_id = ${actor.id}::uuid FOR SHARE`;
        if (!still) throw notSuiteAdmin();

        const startedAt = new Date();
        const expiresAt = new Date(startedAt.getTime() + hours * 3_600_000);
        const created = await tx.temporaryGrant.create({
          data: {
            userId: actor.id,
            system: input.system,
            role: input.role,
            reason,
            startedAt,
            expiresAt,
          },
          select: { id: true },
        });
        await tx.userRoleAssignment.create({
          data: {
            userId: actor.id,
            system: input.system,
            role: input.role,
            temporaryGrantId: created.id,
          },
        });
        await this.events.record(tx, {
          userId: actor.id,
          actorId: actor.id,
          type: AccountEventType.TEMP_ACCESS_STARTED,
          system: input.system,
          reason,
          newValue: JSON.stringify({
            role: input.role,
            expiresAt: expiresAt.toISOString(),
          }),
          meta: actor.meta,
        });
        return tx.temporaryGrant.findUniqueOrThrow({
          where: { id: created.id },
          select: GRANT_SELECT,
        });
      });
    } catch (error) {
      if (
        typeof error === 'object' &&
        error !== null &&
        (error as { code?: string }).code === 'P2002'
      ) {
        throw grantActive();
      }
      throw error;
    }

    this.logger.log(
      `temporary access started user=${actor.id} system=${row.system} role=${row.role} grant=${row.id}`,
    );
    await this.alerts.send(actor.id, [
      {
        kind: 'TEMP_ACCESS_STARTED',
        targetId: actor.id,
        systems: [row.system],
        roleSystem: row.system,
        role: row.role,
        until: row.expiresAt,
        reason,
      },
    ]);
    return viewOf(row);
  }

  /**
   * AC-10: `DELETE /auth/admin/temporary-grants/:id`, by the holder, any suite admin, or a
   * permanent admin of that system. An ended grant answers the same and writes nothing.
   */
  async endEarly(actor: GrantActor, grantId: string): Promise<void> {
    const grant = await this.prisma.temporaryGrant.findUnique({
      where: { id: grantId },
      select: { id: true, userId: true, system: true },
    });
    if (!grant) throw new NotFoundException('Temporary access not found');
    const allowed =
      grant.userId === actor.id ||
      actor.standing.suiteAdmin ||
      actor.standing.adminOf.includes(grant.system);
    if (!allowed) throw notAdminOfSystem();

    const alert = await this.prisma.$transaction(async (tx) => {
      const ended = await this.endInTx(
        tx,
        grantId,
        TemporaryGrantEnd.ENDED_EARLY,
        actor.id,
        actor.meta,
      );
      if (!ended) return null;
      return {
        kind: 'TEMP_ACCESS_ENDED_EARLY',
        targetId: ended.userId,
        systems: [ended.system],
        roleSystem: ended.system,
        role: ended.role,
      } satisfies AdminAlert;
    });
    if (alert) await this.alerts.send(actor.id, [alert]);
  }

  /**
   * Ends one grant inside the caller's transaction: locks it, and when it is still live deletes
   * its role row, stamps the end, writes `TEMP_ACCESS_ENDED` and ends the holder's sessions that
   * opened the system. Answers the grant when it ended it, null when it was already ended.
   */
  async endInTx(
    tx: Tx,
    grantId: string,
    reason: TemporaryGrantEnd,
    endedById: string | null,
    meta?: RequestMeta,
  ): Promise<{ userId: string; system: SystemType; role: string } | null> {
    const [locked] = await tx.$queryRaw<
      {
        user_id: string;
        system: SystemType;
        role: string;
        ended_at: Date | null;
      }[]
    >`
      SELECT user_id, system, role, ended_at FROM temporary_grants
      WHERE id = ${grantId}::uuid FOR UPDATE`;
    if (!locked || locked.ended_at !== null) return null;

    await tx.userRoleAssignment.deleteMany({
      where: { temporaryGrantId: grantId },
    });
    await tx.temporaryGrant.update({
      where: { id: grantId },
      data: { endedAt: new Date(), endReason: reason, endedById },
    });
    await this.events.record(tx, {
      userId: locked.user_id,
      actorId: endedById,
      type: AccountEventType.TEMP_ACCESS_ENDED,
      system: locked.system,
      newValue: reason,
      meta,
    });
    const sessionsEnded = await this.sessions.endAllForUser(
      tx,
      locked.user_id,
      SessionEndReason.TEMP_ACCESS_ENDED,
      {
        audience: locked.system,
        system: locked.system,
        endedById: endedById ?? undefined,
        ip: meta?.ip,
      },
    );
    this.logger.log(
      `temporary access ended grant=${grantId} user=${locked.user_id} system=${locked.system} reason=${reason} sessions=${sessionsEnded}`,
    );
    return {
      userId: locked.user_id,
      system: locked.system,
      role: locked.role,
    };
  }

  /** Ends every live grant of one person (AC-2: a suite admin removed). */
  async endAllInTx(
    tx: Tx,
    userId: string,
    reason: TemporaryGrantEnd,
    endedById: string | null,
    meta?: RequestMeta,
  ): Promise<number> {
    const live = await tx.temporaryGrant.findMany({
      where: { userId, endedAt: null },
      select: { id: true },
      orderBy: { id: 'asc' },
    });
    let ended = 0;
    for (const grant of live) {
      if (await this.endInTx(tx, grant.id, reason, endedById, meta)) ended++;
    }
    return ended;
  }

  /**
   * AC-11: newest first, keyset paged. A suite admin sees every system (or one, with `system`);
   * a system admin sees the systems they admin, one at a time when they pass `system`.
   */
  async list(
    actor: GrantActor,
    query: {
      state?: unknown;
      system?: unknown;
      cursor?: unknown;
      limit?: unknown;
    },
  ): Promise<{ items: GrantView[]; next: string | null }> {
    const state = query.state ?? 'live';
    if (state !== 'live' && state !== 'all') {
      throw validationFailed('state must be live or all');
    }
    let systems: SystemType[];
    if (query.system !== undefined) {
      if (
        typeof query.system !== 'string' ||
        !(Object.values(SystemType) as string[]).includes(query.system)
      ) {
        throw validationFailed(
          `system must be one of ${Object.values(SystemType).join(', ')}`,
        );
      }
      const system = query.system as SystemType;
      if (
        !actor.standing.suiteAdmin &&
        !actor.standing.adminOf.includes(system)
      ) {
        throw notAdminOfSystem();
      }
      systems = [system];
    } else {
      systems = actor.standing.suiteAdmin
        ? Object.values(SystemType)
        : actor.standing.adminOf;
    }
    let limit = PAGE_DEFAULT;
    if (query.limit !== undefined) {
      const parsed = Number(query.limit);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > PAGE_MAX) {
        throw validationFailed(`limit must be 1 to ${PAGE_MAX}`);
      }
      limit = parsed;
    }
    if (query.cursor !== undefined && typeof query.cursor !== 'string') {
      throw invalidCursor();
    }
    const cursor =
      typeof query.cursor === 'string' && query.cursor
        ? decodeCursor(query.cursor)
        : null;

    const rows = await this.prisma.temporaryGrant.findMany({
      where: {
        system: { in: systems },
        ...(state === 'live' ? { endedAt: null } : {}),
        ...(cursor
          ? {
              OR: [
                { startedAt: { lt: cursor.startedAt } },
                { startedAt: cursor.startedAt, id: { lt: cursor.id } },
              ],
            }
          : {}),
      },
      select: GRANT_SELECT,
      orderBy: [{ startedAt: 'desc' }, { id: 'desc' }],
      take: limit + 1,
    });
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    return {
      items: page.map(viewOf),
      next: rows.length > limit && last ? encodeCursor(last) : null,
    };
  }

  /** AC-24: the caller's own live grants, for the portal banner. */
  async liveFor(userId: string): Promise<GrantView[]> {
    const rows = await this.prisma.temporaryGrant.findMany({
      where: { userId, ...liveGrantWhere() },
      select: GRANT_SELECT,
      orderBy: [{ startedAt: 'desc' }, { id: 'desc' }],
    });
    return rows.map(viewOf);
  }

  /** AC-10: every minute, end live grants whose time is up. One replica at a time. */
  @Cron(CronExpression.EVERY_MINUTE, { name: 'temporary-grant-sweep' })
  async runSweep(): Promise<void> {
    try {
      const ended = await this.sweep();
      if (ended && ended > 0) {
        this.logger.log(`temporary access sweep ended=${ended}`);
      }
    } catch (error) {
      this.logger.error(
        `temporary access sweep failed: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
      reportJobFailure('temporary-grant-sweep', error);
    }
  }

  /** Answers how many grants it ended, or null when another replica holds the lock. */
  async sweep(now: Date = new Date()): Promise<number | null> {
    return this.prisma.$transaction(
      async (tx) => {
        const [lock] = await tx.$queryRaw<{ locked: boolean }[]>`
          SELECT pg_try_advisory_xact_lock(${GRANT_SWEEP_LOCK_KEY}) AS locked`;
        if (!lock?.locked) return null;
        const due = await tx.temporaryGrant.findMany({
          where: { endedAt: null, expiresAt: { lte: now } },
          select: { id: true },
          orderBy: { expiresAt: 'asc' },
          take: SWEEP_BATCH,
        });
        let ended = 0;
        for (const grant of due) {
          if (
            await this.endInTx(tx, grant.id, TemporaryGrantEnd.EXPIRED, null)
          ) {
            ended++;
          }
        }
        return ended;
      },
      { timeout: 30_000 },
    );
  }
}
