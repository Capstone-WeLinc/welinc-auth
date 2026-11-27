import { HttpStatus, Injectable } from '@nestjs/common';
import { Prisma, type RoleEventKind, type SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import {
  decodeEventCursor,
  encodeEventCursor,
  type EventCursor,
} from '../events/event-cursor';
import { MatrixService } from '../permissions/matrix.service';
import { liveRoleWhere } from './live-roles';
import { CATALOG_SYNC_ACTOR } from './permission-plan';

// Suite spec 0018 (child 0001, AC-17): the Roles page reads. One system's live roles with their
// people, last change and cells, the permission groups in catalog order, and one role's history
// (permission changes and role events merged, newest first).

export type RoleSummary = {
  code: string;
  name: string;
  description: string;
  builtIn: boolean;
  isSystemAdmin: boolean;
  copiedFrom: { code: string; name: string } | null;
  /** user_roles rows of people who aren't deleted: the people the People tab lists. */
  peopleCount: number;
  /**
   * The same rows with the deleted filter flipped: people in their deletion grace period who
   * keep the role until erasure. They don't block Delete (child 0002, AC-25).
   */
  graceCount: number;
  lastChanged: { at: string; byName: string } | null;
};

export type RolePermissionView = {
  key: string;
  label: string;
  description: string;
  lockedRoles: string[];
  defaultRoles: string[];
};

export type RolesPage = {
  system: SystemType;
  /** The system has permission keys, so custom roles can be offered (child 0002). */
  supportsCustomRoles: boolean;
  /** Only suite admins change permissions and roles. */
  canEdit: boolean;
  /** `permission_matrices.version`, the value the matrix PATCH needs. */
  version: number;
  roles: RoleSummary[];
  groups: { name: string; permissions: RolePermissionView[] }[];
  /** Each live role's allowed keys, in catalog order. */
  cells: Record<string, string[]>;
};

export type RoleHistoryKind = 'PERMISSION' | RoleEventKind;

export type RoleHistoryItem = {
  id: string;
  at: string;
  actorName: string;
  kind: RoleHistoryKind;
  key?: string;
  label?: string;
  before?: boolean | null;
  after?: boolean | null;
  fromValue?: string | null;
  toValue?: string | null;
  note?: string | null;
};

export const ROLE_HISTORY_LIMIT_DEFAULT = 25;
export const ROLE_HISTORY_LIMIT_MAX = 100;

/** The name the page shows for rows the catalog sync wrote (AC-15). */
export const SYNC_ACTOR_LABEL = 'System';
const ERASED_ACTOR = 'Deleted user';

function actorLabel(name: string | null): string {
  if (name === null) return ERASED_ACTOR;
  return name === CATALOG_SYNC_ACTOR ? SYNC_ACTOR_LABEL : name;
}

function keysetWhere(after: EventCursor | null) {
  return after
    ? {
        OR: [
          { createdAt: { lt: after.createdAt } },
          { createdAt: after.createdAt, id: { lt: after.id } },
        ],
      }
    : {};
}

/** Newest first by (createdAt, id), the order both tables' indexes serve. */
function newestFirst(
  a: { createdAt: Date; id: string },
  b: { createdAt: Date; id: string },
): number {
  const byTime = b.createdAt.getTime() - a.createdAt.getTime();
  if (byTime !== 0) return byTime;
  return a.id < b.id ? 1 : a.id > b.id ? -1 : 0;
}

@Injectable()
export class RolesAdminService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly matrix: MatrixService,
  ) {}

  /** `GET /auth/admin/roles/:system` (umbrella API surface). */
  async page(system: SystemType, canEdit: boolean): Promise<RolesPage> {
    const now = new Date();
    const [roles, permissions, cells, counts, graceCounts, version] =
      await Promise.all([
        this.prisma.systemRole.findMany({
          where: { system, deletedAt: null },
          select: {
            code: true,
            name: true,
            description: true,
            isBuiltIn: true,
            isSystemAdmin: true,
            copiedFrom: true,
            sortOrder: true,
          },
        }),
        this.prisma.systemPermission.findMany({
          where: { system },
          select: {
            key: true,
            label: true,
            group: true,
            description: true,
            lockedRoles: true,
            defaultRoles: true,
          },
          orderBy: { sortOrder: 'asc' },
        }),
        this.prisma.rolePermission.findMany({
          where: { system, allowed: true },
          select: { role: true, key: true },
        }),
        this.prisma.userRoleAssignment.groupBy({
          by: ['role'],
          where: { system, user: { deletedAt: null }, ...liveRoleWhere(now) },
          _count: { _all: true },
        }),
        this.prisma.userRoleAssignment.groupBy({
          by: ['role'],
          where: {
            system,
            user: { deletedAt: { not: null } },
            ...liveRoleWhere(now),
          },
          _count: { _all: true },
        }),
        this.matrix.version(system),
      ]);

    const live = roles.sort((a, b) => {
      if (a.isBuiltIn !== b.isBuiltIn) return a.isBuiltIn ? -1 : 1;
      if (a.isBuiltIn) return a.sortOrder - b.sortOrder;
      return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    });
    const codes = live.map((r) => r.code);
    const sources = live
      .map((r) => r.copiedFrom)
      .filter((c): c is string => c !== null);
    const [sourceRows, lastChanged] = await Promise.all([
      sources.length > 0
        ? this.prisma.systemRole.findMany({
            // The source may be archived: copiedFrom.name still reads it
            where: { system, code: { in: sources } },
            select: { code: true, name: true },
          })
        : Promise.resolve<{ code: string; name: string }[]>([]),
      this.lastChanged(system, codes),
    ]);
    const sourceName = new Map(sourceRows.map((r) => [r.code, r.name]));
    const peopleCount = new Map(counts.map((c) => [c.role, c._count._all]));
    const graceCount = new Map(graceCounts.map((c) => [c.role, c._count._all]));

    const order = new Map(permissions.map((p, i) => [p.key, i]));
    const cellMap: Record<string, string[]> = {};
    for (const code of codes) cellMap[code] = [];
    for (const c of cells) cellMap[c.role]?.push(c.key);
    for (const keys of Object.values(cellMap)) {
      keys.sort((a, b) => (order.get(a) ?? 0) - (order.get(b) ?? 0));
    }

    const groups: RolesPage['groups'] = [];
    const groupAt = new Map<string, RolesPage['groups'][number]>();
    for (const p of permissions) {
      let group = groupAt.get(p.group);
      if (!group) {
        group = { name: p.group, permissions: [] };
        groupAt.set(p.group, group);
        groups.push(group);
      }
      group.permissions.push({
        key: p.key,
        label: p.label,
        description: p.description,
        lockedRoles: p.lockedRoles ?? [],
        defaultRoles: p.defaultRoles ?? [],
      });
    }

    return {
      system,
      supportsCustomRoles: permissions.length > 0,
      canEdit,
      version,
      roles: live.map((r) => ({
        code: r.code,
        name: r.name,
        description: r.description,
        builtIn: r.isBuiltIn,
        isSystemAdmin: r.isSystemAdmin,
        copiedFrom: r.copiedFrom
          ? {
              code: r.copiedFrom,
              name: sourceName.get(r.copiedFrom) ?? r.copiedFrom,
            }
          : null,
        peopleCount: peopleCount.get(r.code) ?? 0,
        graceCount: graceCount.get(r.code) ?? 0,
        lastChanged: lastChanged.get(r.code) ?? null,
      })),
      groups,
      cells: cellMap,
    };
  }

  /**
   * The newest permission change or role event of each role, both indexed on
   * (system, role, created_at desc, id desc). Cell rows a create or delete wrote count here.
   */
  private async lastChanged(
    system: SystemType,
    codes: string[],
  ): Promise<Map<string, { at: string; byName: string }>> {
    const result = new Map<string, { at: string; byName: string }>();
    if (codes.length === 0) return result;
    const rows = await this.prisma.$queryRaw<
      { role: string; created_at: Date; actor_name: string | null }[]
    >(Prisma.sql`
      SELECT DISTINCT ON ("role") "role", "created_at", "actor_name"
        FROM (
          SELECT "role", "created_at", "id", "actor_name" FROM "permission_changes"
           WHERE "system" = ${system}::"SystemType" AND "role" IN (${Prisma.join(codes)})
          UNION ALL
          SELECT "role", "created_at", "id", "actor_name" FROM "role_events"
           WHERE "system" = ${system}::"SystemType" AND "role" IN (${Prisma.join(codes)})
        ) AS changes
       ORDER BY "role", "created_at" DESC, "id" DESC`);
    for (const r of rows) {
      result.set(r.role, {
        at: r.created_at.toISOString(),
        byName: actorLabel(r.actor_name),
      });
    }
    return result;
  }

  /**
   * `GET /auth/admin/roles/:system/:code/history` (AC-15, AC-17): permission changes and role
   * events merged in (created_at desc, id desc) order, keyset paged across both. The cell rows a
   * custom role's create (before null) or delete (after null) wrote are left out: the one CREATED
   * or DELETED line stands for them. Built in roles keep every row, the sync's included.
   */
  async history(
    system: SystemType,
    code: string,
    query: { cursor?: string; limit?: number },
  ): Promise<{ items: RoleHistoryItem[]; next: string | null }> {
    const limit = Math.min(
      Math.max(query.limit ?? ROLE_HISTORY_LIMIT_DEFAULT, 1),
      ROLE_HISTORY_LIMIT_MAX,
    );
    const after = query.cursor ? decodeEventCursor(query.cursor) : null;

    const role = await this.prisma.systemRole.findUnique({
      where: { system_code: { system, code } },
      select: { isBuiltIn: true },
    });
    if (!role) {
      // A built in role that left the catalog still has its history
      const trace = await this.prisma.permissionChange.findFirst({
        where: { system, role: code },
        select: { id: true },
      });
      if (!trace)
        throw coded(HttpStatus.NOT_FOUND, 'NOT_FOUND', 'No such role');
    }
    const custom = role ? !role.isBuiltIn : false;

    const [changes, events, permissions] = await Promise.all([
      this.prisma.permissionChange.findMany({
        where: {
          system,
          role: code,
          ...(custom ? { before: { not: null }, after: { not: null } } : {}),
          ...keysetWhere(after),
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: limit + 1,
      }),
      this.prisma.roleEvent.findMany({
        where: { system, role: code, ...keysetWhere(after) },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: limit + 1,
      }),
      this.prisma.systemPermission.findMany({
        where: { system },
        select: { key: true, label: true },
      }),
    ]);
    const label = new Map(permissions.map((p) => [p.key, p.label]));

    // Each row keeps its sort key beside the answer item
    const merged: { id: string; createdAt: Date; item: RoleHistoryItem }[] = [
      ...changes.map((r) => ({
        id: r.id,
        createdAt: r.createdAt,
        item: {
          id: r.id,
          at: r.createdAt.toISOString(),
          actorName: actorLabel(r.actorName),
          kind: 'PERMISSION' as const,
          key: r.key,
          // A key that left the catalog keeps its key as the label
          label: label.get(r.key) ?? r.key,
          before: r.before,
          after: r.after,
          note: r.note,
        },
      })),
      ...events.map((e) => ({
        id: e.id,
        createdAt: e.createdAt,
        item: {
          id: e.id,
          at: e.createdAt.toISOString(),
          actorName: actorLabel(e.actorName),
          kind: e.kind,
          fromValue: e.fromValue,
          toValue: e.toValue,
        },
      })),
    ].sort(newestFirst);

    const page = merged.slice(0, limit);
    const last = page[page.length - 1];
    return {
      items: page.map(({ item }) => item),
      next: merged.length > limit && last ? encodeEventCursor(last) : null,
    };
  }
}
