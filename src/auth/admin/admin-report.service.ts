import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  AccountEventCategory,
  AccountEventType,
  DeletionRequestStatus,
  Prisma,
  SystemType,
} from '@prisma/client';
import type { Env } from '../../config/env';
import { PrismaService } from '../../shared/prisma.service';
import { lockRunning } from '../lockout';
import { DeletionService } from '../deletion/deletion.service';
import { CatalogService } from '../roles/catalog.service';
import {
  SuiteAdminsService,
  type SuiteAdminView,
} from './suite-admins.service';

const ATTENTION_FIRST = 10;
const RECENT_CHANGES = 20;
const DAY_MS = 86_400_000;

type Person = { id: string; name: string; email: string };
type Named = { id: string; name: string } | null;

export type ReportSystem = {
  system: SystemType;
  name: string;
  adminRole: { code: string; name: string } | null;
  admins: (Person & { since: string; grantedBy: Named })[];
  temporaryGrants: {
    id: string;
    holder: Person;
    role: string;
    roleName: string;
    reason: string;
    startedAt: string;
    expiresAt: string;
  }[];
};

type AttentionList<T> = { count: number; first: T[] };

export type AdminReport = {
  suiteAdmins: SuiteAdminView[];
  systems: ReportSystem[];
  attention: {
    locked: AttentionList<Person & { lockedAt: string }>;
    setupPending: AttentionList<Person & { createdAt: string }>;
    emailNotVerified: AttentionList<Person & { createdAt: string }>;
    deletionRequests: AttentionList<{
      id: string;
      user: Person;
      requestedAt: string;
      orphan: boolean;
    }>;
    inGrace: AttentionList<
      Person & { deletedAt: string; eraseAfter: string; orphan: boolean }
    >;
  };
  systemsWithoutAdmin: SystemType[];
  recentAdminChanges: {
    id: string;
    type: AccountEventType;
    at: string;
    user: Person;
    actor: Named;
    system: SystemType | null;
    oldValue: string | null;
    newValue: string | null;
    reason: string | null;
  }[];
};

/** The events that are always admin level changes (AC-19). */
const ADMIN_EVENT_TYPES: AccountEventType[] = [
  AccountEventType.SUITE_ADMIN_ACTIONED,
  AccountEventType.SUITE_ADMIN_REMOVED,
  AccountEventType.TEMP_ACCESS_STARTED,
  AccountEventType.TEMP_ACCESS_ENDED,
  AccountEventType.ADMIN_RECOVERY,
];

const ACTIVE = { isActive: true, deletedAt: null } as const;
const PERSON = { id: true, name: true, email: true } as const;

/** Whether a stored `rolesKey()` value holds one of the `ROLE@SYSTEM` tokens. */
function holdsToken(value: string | null, tokens: Set<string>): boolean {
  return !!value && value.split(',').some((token) => tokens.has(token));
}

/**
 * Spec 0013, AC-19: the suite admin's landing page. Who holds admin where and since when (with
 * who granted it), live temporary access, what needs attention, and the latest admin changes.
 * Read only, for suite admins.
 */
@Injectable()
export class AdminReportService {
  private readonly graceDays: number;

  constructor(
    private readonly prisma: PrismaService,
    private readonly catalog: CatalogService,
    private readonly suiteAdmins: SuiteAdminsService,
    private readonly deletion: DeletionService,
    config: ConfigService<Env, true>,
  ) {
    this.graceDays = config.get('ACCOUNT_ERASURE_GRACE_DAYS', { infer: true });
  }

  async report(): Promise<AdminReport> {
    const catalog = await this.catalog.systems();
    const adminRoleOf = new Map(
      catalog.flatMap((s) =>
        s.roles.filter((r) => r.isSystemAdmin).map((r) => [s.code, r] as const),
      ),
    );
    const tokens = new Set(
      [...adminRoleOf].map(([system, role]) => `${role.code}@${system}`),
    );

    const [suiteAdmins, systems, attention, recent] = await Promise.all([
      this.suiteAdmins.list(),
      this.systems(catalog, adminRoleOf),
      this.attention(),
      this.recentChanges(adminRoleOf, tokens),
    ]);
    return {
      suiteAdmins,
      systems,
      attention,
      systemsWithoutAdmin: systems
        .filter((s) => s.admins.length === 0)
        .map((s) => s.system),
      recentAdminChanges: recent,
    };
  }

  private async systems(
    catalog: Awaited<ReturnType<CatalogService['systems']>>,
    adminRoleOf: Map<SystemType, { code: string; name: string }>,
  ): Promise<ReportSystem[]> {
    const holders = await this.prisma.userRoleAssignment.findMany({
      where: {
        temporaryGrantId: null,
        systemRole: { isSystemAdmin: true },
        user: ACTIVE,
      },
      select: {
        system: true,
        role: true,
        createdAt: true,
        user: { select: PERSON },
      },
      orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    });
    const grantedBy = await this.grantersOf(holders);
    const grants = await this.prisma.temporaryGrant.findMany({
      where: { endedAt: null, expiresAt: { gt: new Date() } },
      select: {
        id: true,
        system: true,
        role: true,
        reason: true,
        startedAt: true,
        expiresAt: true,
        user: { select: PERSON },
        systemRole: { select: { name: true } },
      },
      orderBy: [{ startedAt: 'desc' }, { id: 'desc' }],
    });

    return catalog.map((system) => {
      const role = adminRoleOf.get(system.code);
      return {
        system: system.code,
        name: system.name,
        adminRole: role ? { code: role.code, name: role.name } : null,
        admins: holders
          .filter((h) => h.system === system.code)
          .map((h) => ({
            ...h.user,
            since: h.createdAt.toISOString(),
            grantedBy: grantedBy.get(`${h.user.id}:${h.system}`) ?? null,
          })),
        temporaryGrants: grants
          .filter((g) => g.system === system.code)
          .map((g) => ({
            id: g.id,
            holder: g.user,
            role: g.role,
            roleName: g.systemRole.name,
            reason: g.reason,
            startedAt: g.startedAt.toISOString(),
            expiresAt: g.expiresAt.toISOString(),
          })),
      };
    });
  }

  /**
   * Value sourcing "report, admins, grantedBy": the actor of the newest `ACCOUNT` event for that
   * person and system whose new value holds the role. None found (the seed) is null; an erased
   * actor shows "Deleted user".
   */
  private async grantersOf(
    holders: { system: SystemType; role: string; user: { id: string } }[],
  ): Promise<Map<string, Named>> {
    const result = new Map<string, Named>();
    if (holders.length === 0) return result;
    const rows = await this.prisma.accountEvent.findMany({
      where: {
        category: AccountEventCategory.ACCOUNT,
        type: AccountEventType.ROLE_CHANGED,
        OR: holders.map((h) => ({
          userId: h.user.id,
          system: h.system,
          newValue: { contains: `${h.role}@${h.system}` },
        })),
      },
      select: {
        userId: true,
        system: true,
        newValue: true,
        actor: { select: { id: true, name: true } },
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    });
    for (const h of holders) {
      const key = `${h.user.id}:${h.system}`;
      const token = new Set([`${h.role}@${h.system}`]);
      const row = rows.find(
        (r) =>
          r.userId === h.user.id &&
          r.system === h.system &&
          holdsToken(r.newValue, token),
      );
      result.set(
        key,
        row?.actor
          ? { id: row.actor.id, name: row.actor.name || 'Deleted user' }
          : null,
      );
    }
    return result;
  }

  private async attention(): Promise<AdminReport['attention']> {
    const list = async <T>(
      where: Prisma.UserWhereInput,
      orderBy: Prisma.UserOrderByWithRelationInput[],
      map: (row: Person & Record<string, unknown>) => T,
      extra: Prisma.UserSelect,
    ): Promise<AttentionList<T>> => {
      const [count, rows] = await Promise.all([
        this.prisma.user.count({ where }),
        this.prisma.user.findMany({
          where,
          orderBy,
          take: ATTENTION_FIRST,
          select: { ...PERSON, ...extra },
        }),
      ]);
      return {
        count,
        first: rows.map((row) => map(row as Person & Record<string, unknown>)),
      };
    };
    const iso = (value: unknown) => (value as Date).toISOString();

    const [locked, setupPending, emailNotVerified] = await Promise.all([
      list(
        { ...ACTIVE, lockedAt: lockRunning() },
        [{ lockedAt: 'asc' }, { id: 'asc' }],
        (row) => ({
          id: row.id,
          name: row.name,
          email: row.email,
          lockedAt: iso(row.lockedAt),
        }),
        { lockedAt: true },
      ),
      list(
        { ...ACTIVE, passwordSet: false },
        [{ createdAt: 'asc' }, { id: 'asc' }],
        (row) => ({
          id: row.id,
          name: row.name,
          email: row.email,
          createdAt: iso(row.createdAt),
        }),
        { createdAt: true },
      ),
      list(
        { ...ACTIVE, emailVerified: false },
        [{ createdAt: 'asc' }, { id: 'asc' }],
        (row) => ({
          id: row.id,
          name: row.name,
          email: row.email,
          createdAt: iso(row.createdAt),
        }),
        { createdAt: true },
      ),
    ]);

    const pendingWhere: Prisma.AccountDeletionRequestWhereInput = {
      status: DeletionRequestStatus.PENDING,
      user: { deletedAt: null },
    };
    const [pendingCount, pending] = await Promise.all([
      this.prisma.accountDeletionRequest.count({ where: pendingWhere }),
      this.prisma.accountDeletionRequest.findMany({
        where: pendingWhere,
        orderBy: [{ requestedAt: 'asc' }, { id: 'asc' }],
        take: ATTENTION_FIRST,
        select: {
          id: true,
          requestedAt: true,
          user: {
            select: {
              ...PERSON,
              roles: {
                where: { temporaryGrantId: null },
                select: { system: true },
              },
            },
          },
        },
      }),
    ]);
    const graceWhere: Prisma.UserWhereInput = {
      deletedAt: { not: null },
      erasedAt: null,
    };
    const [graceCount, grace] = await Promise.all([
      this.prisma.user.count({ where: graceWhere }),
      this.prisma.user.findMany({
        where: graceWhere,
        orderBy: [{ deletedAt: 'asc' }, { id: 'asc' }],
        take: ATTENTION_FIRST,
        select: {
          ...PERSON,
          deletedAt: true,
          roles: {
            where: { temporaryGrantId: null },
            select: { system: true },
          },
        },
      }),
    ]);
    const orphans = await this.deletion.orphans([
      ...pending.map((p) => p.user),
      ...grace,
    ]);

    return {
      locked,
      setupPending,
      emailNotVerified,
      deletionRequests: {
        count: pendingCount,
        first: pending.map((p) => ({
          id: p.id,
          user: { id: p.user.id, name: p.user.name, email: p.user.email },
          requestedAt: p.requestedAt.toISOString(),
          orphan: orphans.has(p.user.id),
        })),
      },
      inGrace: {
        count: graceCount,
        first: grace.map((g) => ({
          id: g.id,
          name: g.name,
          email: g.email,
          deletedAt: g.deletedAt!.toISOString(),
          eraseAfter: new Date(
            g.deletedAt!.getTime() + this.graceDays * DAY_MS,
          ).toISOString(),
          orphan: orphans.has(g.id),
        })),
      },
    };
  }

  /**
   * AC-19: the newest 20 admin level changes: the suite admin and temporary access events, role
   * changes whose old or new value holds an admin role, and deletes and restores of a person
   * who holds an admin role (their roles stay through a soft delete).
   */
  private async recentChanges(
    adminRoleOf: Map<SystemType, { code: string }>,
    tokens: Set<string>,
  ): Promise<AdminReport['recentAdminChanges']> {
    const select = {
      id: true,
      type: true,
      createdAt: true,
      system: true,
      oldValue: true,
      newValue: true,
      reason: true,
      user: { select: PERSON },
      actor: { select: { id: true, name: true } },
    } satisfies Prisma.AccountEventSelect;
    const order = [{ createdAt: 'desc' as const }, { id: 'desc' as const }];
    const tokenList = [...tokens];
    const adminHolder: Prisma.UserWhereInput = {
      roles: {
        some: {
          temporaryGrantId: null,
          systemRole: { isSystemAdmin: true },
        },
      },
    };

    type Row = Prisma.AccountEventGetPayload<{ select: typeof select }>;
    const none = Promise.resolve<Row[]>([]);
    const [always, roleRows, lifecycle] = await Promise.all([
      this.prisma.accountEvent.findMany({
        where: { type: { in: ADMIN_EVENT_TYPES } },
        select,
        orderBy: order,
        take: RECENT_CHANGES,
      }),
      tokenList.length === 0
        ? none
        : this.prisma.accountEvent.findMany({
            where: {
              type: AccountEventType.ROLE_CHANGED,
              OR: tokenList.flatMap((token) => [
                { oldValue: { contains: token } },
                { newValue: { contains: token } },
              ]),
            },
            select,
            orderBy: order,
            take: RECENT_CHANGES * 2,
          }),
      adminRoleOf.size === 0
        ? none
        : this.prisma.accountEvent.findMany({
            where: {
              type: {
                in: [
                  AccountEventType.CREATED,
                  AccountEventType.DELETED,
                  AccountEventType.RESTORED,
                ],
              },
              user: adminHolder,
            },
            select,
            orderBy: order,
            take: RECENT_CHANGES,
          }),
    ]);
    const roles = roleRows.filter(
      (row) =>
        holdsToken(row.oldValue, tokens) || holdsToken(row.newValue, tokens),
    );
    return [...always, ...roles, ...lifecycle]
      .sort(
        (a, b) =>
          b.createdAt.getTime() - a.createdAt.getTime() ||
          (a.id < b.id ? 1 : a.id > b.id ? -1 : 0),
      )
      .slice(0, RECENT_CHANGES)
      .map((row) => ({
        id: row.id,
        type: row.type,
        at: row.createdAt.toISOString(),
        user: {
          id: row.user.id,
          name: row.user.name || 'Deleted user',
          email: row.user.email,
        },
        actor: row.actor
          ? { id: row.actor.id, name: row.actor.name || 'Deleted user' }
          : null,
        system: row.system,
        oldValue: row.oldValue,
        newValue: row.newValue,
        reason: row.reason,
      }));
  }
}
