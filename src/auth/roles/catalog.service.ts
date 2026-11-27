import { HttpStatus, Injectable } from '@nestjs/common';
import { Prisma, SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import type { RoleAssignment, RoleCode } from './catalog.types';

// Spec 0004: reads the role catalog (`systems`, `system_roles`) for the rules welinc-auth
// enforces. No cache on purpose: someone who loses admin through a sync loses it on their next
// request. Only `GET /auth/systems` is cached, through HTTP headers (AC-16).

/** A transaction or the service itself: checks that guard a write run inside its transaction. */
export type CatalogDb = Pick<Prisma.TransactionClient, 'system' | 'systemRole'>;

export type CatalogRole = {
  code: RoleCode;
  name: string;
  description: string;
  isSystemAdmin: boolean;
  /** Suite spec 0018: false for a custom role. */
  builtIn: boolean;
};

export type CatalogSystem = {
  code: SystemType;
  name: string;
  description: string;
  maxRolesPerUser: number | null;
  roles: CatalogRole[];
};

/** Each system's admin role code. */
export type AdminRoles = ReadonlyMap<SystemType, RoleCode>;

/** `VRMS allows one role per person.` (AC-10) */
export function roleLimitMessage(system: SystemType, limit: number): string {
  return `${system} allows ${limit === 1 ? 'one role' : `${limit} roles`} per person.`;
}

/** `BMS has no role 'MECHANIC'. Its roles are Admin, Operations, ...` (AC-9) */
export function unknownRoleMessage(
  system: SystemType,
  code: string,
  roles: Pick<CatalogRole, 'name'>[],
): string {
  return `${system} has no role '${code}'. Its roles are ${roles.map((r) => r.name).join(', ')}.`;
}

/** True when `roles` holds the admin role of `system`. */
export function holdsAdmin(
  roles: RoleAssignment[],
  system: SystemType,
  admins: AdminRoles,
): boolean {
  const admin = admins.get(system);
  return (
    admin !== undefined &&
    roles.some((r) => r.system === system && r.role === admin)
  );
}

/**
 * Suite spec 0018 child 0002, AC-29: live roles only (an archived custom role is unknown
 * everywhere), with `builtIn`; `liveOrder` sorts them.
 */
const ROLES_SELECT = {
  where: { deletedAt: null },
  select: {
    code: true,
    name: true,
    description: true,
    isSystemAdmin: true,
    isBuiltIn: true,
    sortOrder: true,
  },
  orderBy: { sortOrder: 'asc' },
} satisfies Prisma.System$rolesArgs;

type RoleRow = Omit<CatalogRole, 'builtIn'> & {
  isBuiltIn: boolean;
  sortOrder: number;
};

/** Built in roles first in catalog order, then custom roles by name ignoring case (AC-29). */
export function liveOrder<
  T extends Pick<RoleRow, 'isBuiltIn' | 'sortOrder' | 'name'>,
>(roles: T[]): T[] {
  return [...roles].sort((a, b) => {
    if (a.isBuiltIn !== b.isBuiltIn) return a.isBuiltIn ? -1 : 1;
    if (a.isBuiltIn) return a.sortOrder - b.sortOrder;
    return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
  });
}

function toSystem<S extends { roles: RoleRow[] }>(
  row: S,
): Omit<S, 'roles'> & { roles: CatalogRole[] } {
  return {
    ...row,
    roles: liveOrder(row.roles).map((r) => ({
      code: r.code,
      name: r.name,
      description: r.description,
      isSystemAdmin: r.isSystemAdmin,
      builtIn: r.isBuiltIn,
    })),
  };
}

@Injectable()
export class CatalogService {
  constructor(private readonly prisma: PrismaService) {}

  /** Every system with its live roles (built in first, then custom), in SystemType order (AC-16). */
  async systems(db: CatalogDb = this.prisma): Promise<CatalogSystem[]> {
    const rows = await db.system.findMany({
      select: {
        code: true,
        name: true,
        description: true,
        maxRolesPerUser: true,
        roles: ROLES_SELECT,
      },
    });
    const order = Object.values(SystemType);
    return rows
      .sort((a, b) => order.indexOf(a.code) - order.indexOf(b.code))
      .map(toSystem);
  }

  /** One system, or null before the catalog is synced. */
  async system(
    system: SystemType,
    db: CatalogDb = this.prisma,
  ): Promise<CatalogSystem | null> {
    const row = await db.system.findUnique({
      where: { code: system },
      select: {
        code: true,
        name: true,
        description: true,
        maxRolesPerUser: true,
        roles: ROLES_SELECT,
      },
    });
    return row ? toSystem(row) : null;
  }

  /** Each system's admin role, read per call (AC-14). */
  async adminRoles(db: CatalogDb = this.prisma): Promise<AdminRoles> {
    const rows = await db.systemRole.findMany({
      where: { isSystemAdmin: true },
      select: { system: true, code: true },
    });
    return new Map(rows.map((r) => [r.system, r.code]));
  }

  /** 400 `UNKNOWN_ROLE` unless `system` has `code` (AC-9). */
  async assertKnownRole(
    system: SystemType,
    code: string,
    db: CatalogDb = this.prisma,
  ): Promise<void> {
    const entry = await this.system(system, db);
    this.checkKnown(entry, system, [code]);
  }

  /**
   * The request's roles for the caller's system: 400 `UNKNOWN_ROLE` for a pair the catalog
   * doesn't have, then 409 `ROLE_LIMIT` when they exceed the limit (AC-9, AC-10). Never trims.
   */
  async assertRoleRules(
    roles: RoleAssignment[],
    system: SystemType,
    db: CatalogDb = this.prisma,
  ): Promise<void> {
    const entry = await this.system(system, db);
    this.checkKnown(
      entry,
      system,
      roles.filter((r) => r.system === system).map((r) => r.role),
    );
    this.checkLimit(entry, system, roles);
  }

  /** 409 `ROLE_LIMIT` when an account's roles after a write exceed `system`'s limit (AC-10, AC-13). */
  async assertWithinLimit(
    roles: RoleAssignment[],
    system: SystemType,
    db: CatalogDb = this.prisma,
  ): Promise<void> {
    this.checkLimit(await this.system(system, db), system, roles);
  }

  private checkKnown(
    entry: CatalogSystem | null,
    system: SystemType,
    codes: string[],
  ): void {
    const known = new Set(entry?.roles.map((r) => r.code) ?? []);
    const unknown = codes.find((code) => !known.has(code));
    if (unknown !== undefined) {
      throw coded(
        HttpStatus.BAD_REQUEST,
        'UNKNOWN_ROLE',
        unknownRoleMessage(system, unknown, entry?.roles ?? []),
      );
    }
  }

  private checkLimit(
    entry: CatalogSystem | null,
    system: SystemType,
    roles: RoleAssignment[],
  ): void {
    const limit = entry?.maxRolesPerUser ?? null;
    if (limit === null) return;
    if (roles.filter((r) => r.system === system).length > limit) {
      throw coded(
        HttpStatus.CONFLICT,
        'ROLE_LIMIT',
        roleLimitMessage(system, limit),
      );
    }
  }
}
