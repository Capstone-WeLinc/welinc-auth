import { HttpStatus, Injectable } from '@nestjs/common';
import { Prisma, type SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { AdminAlertsService } from '../admin/admin-alerts.service';
import { coded } from '../errors';
import { decodeEventCursor, encodeEventCursor } from '../events/event-cursor';

// Spec 0013, AC-25 to AC-27: the central permission matrix. Cells live in role_permissions, keys
// in system_permissions (written by catalog:sync), and permission_matrices.version is the one
// number systems poll on.

/** AC-26: what a system backend reads, with `ETag: "v<version>"`. */
export type SystemMatrix = {
  system: SystemType;
  version: number;
  permissions: { key: string; lockedRoles: string[] }[];
  /** Every role of the system, with the keys it holds (an empty list when it holds none). */
  grants: Record<string, string[]>;
};

export function matrixEtag(version: number): string {
  return `"v${version}"`;
}

/** AC-27: the matrix as the portal shows it. */
export type AdminMatrix = {
  system: SystemType;
  version: number;
  roles: { code: string; name: string }[];
  permissions: {
    key: string;
    label: string;
    group: string;
    description: string;
    lockedRoles: string[];
  }[];
  grants: Record<string, string[]>;
  /** Only suite admins edit; a system admin reads (AC-27). */
  canEdit: boolean;
};

export type MatrixChangeInput = { role: string; key: string; allowed: boolean };

export type MatrixActor = { id: string; name: string; email: string };

/** One history row as the portal shows it (AC-27), imported rows included. */
export type MatrixChangeItem = {
  id: string;
  role: string;
  roleName: string;
  key: string;
  label: string;
  before: boolean | null;
  after: boolean | null;
  /** "Deleted user" after an erasure; "Catalog sync" for the sync's rows. */
  actorName: string;
  actorEmail: string | null;
  note: string | null;
  imported: boolean;
  createdAt: string;
};

/** AC-27: a note of 5 to 500 characters whenever a save takes a right away. */
export const NOTE_MIN = 5;
export const NOTE_MAX = 500;

const CHANGES_LIMIT_DEFAULT = 50;
const CHANGES_LIMIT_MAX = 100;

const bad = (code: string, message: string) =>
  coded(HttpStatus.BAD_REQUEST, code, message);

@Injectable()
export class MatrixService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly alerts: AdminAlertsService,
  ) {}

  /** AC-27: labels, groups, locks and version, for a suite admin or that system's admin. */
  async adminMatrix(
    system: SystemType,
    canEdit: boolean,
  ): Promise<AdminMatrix> {
    const [base, roles, permissions] = await Promise.all([
      this.systemMatrix(system),
      // Suite spec 0018: live roles only (an archived custom role has no cells)
      this.prisma.systemRole.findMany({
        where: { system, deletedAt: null },
        select: { code: true, name: true },
        orderBy: { sortOrder: 'asc' },
      }),
      this.prisma.systemPermission.findMany({
        where: { system },
        select: {
          key: true,
          label: true,
          group: true,
          description: true,
          lockedRoles: true,
        },
        orderBy: { sortOrder: 'asc' },
      }),
    ]);
    return {
      system,
      version: base.version,
      roles,
      permissions: permissions.map((p) => ({
        ...p,
        lockedRoles: p.lockedRoles ?? [],
      })),
      grants: base.grants,
      canEdit,
    };
  }

  /**
   * AC-27: a suite admin's save, all or nothing. The version row is locked first, so two saves
   * from the same version can't both win: the second answers 409 MATRIX_STALE. Unchanged cells
   * write nothing; a save that changes nothing answers the matrix with no bump and no alert.
   */
  async update(
    actor: MatrixActor,
    system: SystemType,
    input: {
      version: number;
      changes: MatrixChangeInput[];
      note?: string | null;
    },
  ): Promise<AdminMatrix> {
    if (input.changes.length === 0) {
      throw bad('VALIDATION_FAILED', 'changes must list at least one cell');
    }
    const seen = new Set<string>();
    for (const c of input.changes) {
      const id = `${c.role}|${c.key}`;
      if (seen.has(id)) {
        throw bad('VALIDATION_FAILED', `${c.role} ${c.key} is listed twice`);
      }
      seen.add(id);
    }
    const note = input.note?.trim() || null;

    const changed = await this.prisma.$transaction(async (tx) => {
      const locked = await tx.$queryRaw<{ version: number }[]>(
        Prisma.sql`SELECT "version" FROM "permission_matrices" WHERE "system" = ${system}::"SystemType" FOR UPDATE`,
      );
      const current = locked[0]?.version;
      if (current === undefined || current !== input.version) {
        throw coded(
          HttpStatus.CONFLICT,
          'MATRIX_STALE',
          'Someone changed this matrix since you opened it. Reload it and make your changes again.',
        );
      }

      const [roles, permissions, cells] = await Promise.all([
        // Suite spec 0018: an archived role answers UNKNOWN_ROLE
        tx.systemRole.findMany({
          where: { system, deletedAt: null },
          select: { code: true },
        }),
        tx.systemPermission.findMany({
          where: { system },
          select: { key: true, lockedRoles: true },
        }),
        tx.rolePermission.findMany({
          where: { system },
          select: { role: true, key: true, allowed: true },
        }),
      ]);
      const roleSet = new Set(roles.map((r) => r.code));
      const locks = new Map(
        permissions.map((p) => [p.key, new Set(p.lockedRoles ?? [])]),
      );
      const cellAt = new Map(
        cells.map((c) => [`${c.role}|${c.key}`, c.allowed]),
      );

      for (const c of input.changes) {
        if (!roleSet.has(c.role))
          throw bad('UNKNOWN_ROLE', `${system} has no role ${c.role}`);
        if (!locks.has(c.key))
          throw bad(
            'UNKNOWN_PERMISSION',
            `${system} has no permission ${c.key}`,
          );
        if (locks.get(c.key)?.has(c.role)) {
          throw coded(
            HttpStatus.CONFLICT,
            'LOCKED_CELL',
            `${c.role} ${c.key} is locked and can't be changed`,
          );
        }
      }

      const real = input.changes.filter(
        (c) => cellAt.get(`${c.role}|${c.key}`) !== c.allowed,
      );
      if (real.length === 0) return [];
      const takesAway = real.some(
        (c) => !c.allowed && cellAt.get(`${c.role}|${c.key}`) === true,
      );
      if (
        takesAway &&
        (!note || note.length < NOTE_MIN || note.length > NOTE_MAX)
      ) {
        throw bad(
          'NOTE_REQUIRED',
          `Say why in a note of ${NOTE_MIN} to ${NOTE_MAX} characters when you take a right away`,
        );
      }

      for (const c of real) {
        await tx.rolePermission.upsert({
          where: { system_role_key: { system, role: c.role, key: c.key } },
          create: {
            system,
            role: c.role,
            key: c.key,
            allowed: c.allowed,
            updatedById: actor.id,
          },
          update: { allowed: c.allowed, updatedById: actor.id },
        });
      }
      await tx.permissionChange.createMany({
        data: real.map((c) => ({
          system,
          role: c.role,
          key: c.key,
          before: cellAt.get(`${c.role}|${c.key}`) ?? null,
          after: c.allowed,
          actorId: actor.id,
          actorName: actor.name.slice(0, 100),
          actorEmail: actor.email,
          note,
        })),
      });
      await tx.$executeRaw(
        Prisma.sql`UPDATE "permission_matrices" SET "version" = "version" + 1, "updated_at" = now() WHERE "system" = ${system}::"SystemType"`,
      );
      return real;
    });

    if (changed.length > 0) {
      await this.alerts.send(actor.id, [
        {
          kind: 'PERMISSIONS_CHANGED',
          targetId: null,
          systems: [system],
          roleSystem: system,
          cells: changed.length,
          reason: note,
        },
      ]);
    }
    return this.adminMatrix(system, true);
  }

  /** AC-27: the history, newest first, keyset paged, imported rows included. */
  async changes(
    system: SystemType,
    query: { cursor?: string; limit?: number },
  ): Promise<{ items: MatrixChangeItem[]; nextCursor: string | null }> {
    const limit = Math.min(
      Math.max(query.limit ?? CHANGES_LIMIT_DEFAULT, 1),
      CHANGES_LIMIT_MAX,
    );
    const after = query.cursor ? decodeEventCursor(query.cursor) : null;
    const [rows, roles, permissions] = await Promise.all([
      this.prisma.permissionChange.findMany({
        where: {
          system,
          ...(after
            ? {
                OR: [
                  { createdAt: { lt: after.createdAt } },
                  { createdAt: after.createdAt, id: { lt: after.id } },
                ],
              }
            : {}),
        },
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: limit + 1,
      }),
      this.prisma.systemRole.findMany({
        where: { system },
        select: { code: true, name: true },
      }),
      this.prisma.systemPermission.findMany({
        where: { system },
        select: { key: true, label: true },
      }),
    ]);
    const roleName = new Map(roles.map((r) => [r.code, r.name]));
    const label = new Map(permissions.map((p) => [p.key, p.label]));
    const page = rows.slice(0, limit);
    const last = page[page.length - 1];
    return {
      items: page.map((r) => ({
        id: r.id,
        role: r.role,
        roleName: roleName.get(r.role) ?? r.role,
        key: r.key,
        // A key that left the catalog keeps its key as the label
        label: label.get(r.key) ?? r.key,
        before: r.before,
        after: r.after,
        actorName: r.actorName ?? 'Deleted user',
        actorEmail: r.actorEmail,
        note: r.note,
        imported: r.imported,
        createdAt: r.createdAt.toISOString(),
      })),
      nextCursor: rows.length > limit && last ? encodeEventCursor(last) : null,
    };
  }

  /** The current version, or 1 when catalog:sync has not run for this system yet. */
  async version(system: SystemType): Promise<number> {
    const row = await this.prisma.permissionMatrix.findUnique({
      where: { system },
      select: { version: true },
    });
    return row?.version ?? 1;
  }

  /** AC-26, read in one snapshot so the version always matches the grants it is sent with. */
  async systemMatrix(system: SystemType): Promise<SystemMatrix> {
    return this.prisma.$transaction(
      async (tx) => {
        const [matrix, roles, permissions, cells] = await Promise.all([
          tx.permissionMatrix.findUnique({
            where: { system },
            select: { version: true },
          }),
          tx.systemRole.findMany({
            where: { system, deletedAt: null },
            select: { code: true },
            orderBy: { sortOrder: 'asc' },
          }),
          tx.systemPermission.findMany({
            where: { system },
            select: { key: true, lockedRoles: true },
            orderBy: { sortOrder: 'asc' },
          }),
          tx.rolePermission.findMany({
            where: { system, allowed: true },
            select: { role: true, key: true },
          }),
        ]);
        const order = new Map(permissions.map((p, i) => [p.key, i]));
        const grants: Record<string, string[]> = {};
        for (const role of roles) grants[role.code] = [];
        for (const cell of cells) grants[cell.role]?.push(cell.key);
        for (const keys of Object.values(grants)) {
          keys.sort((a, b) => (order.get(a) ?? 0) - (order.get(b) ?? 0));
        }
        return {
          system,
          version: matrix?.version ?? 1,
          permissions: permissions.map((p) => ({
            key: p.key,
            lockedRoles: p.lockedRoles ?? [],
          })),
          grants,
        };
      },
      { isolationLevel: 'RepeatableRead' },
    );
  }
}
