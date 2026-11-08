import type { SystemType } from '@prisma/client';
import {
  ROLE_CODE_RE,
  type RoleDefinition,
  type SystemDefinition,
} from './catalog.types';

// Spec 0004, AC-2 to AC-4: what `catalog:sync` would change, and every reason it refuses.
// Pure: the runner (prisma/catalog-sync.ts) reads the database, calls planCatalogSync, and
// writes the plan only when it has no errors.

/** The key of the sync's transaction scoped advisory lock: one sync at a time (AC-3). */
export const CATALOG_SYNC_LOCK_KEY = 4_004_001;

/** How many holder emails a refusal lists (AC-3). */
export const HOLDER_LIST_LIMIT = 20;

const NAME_MAX = 60;
const DESCRIPTION_MAX = 200;
const SYSTEM_NAME_MAX = 100;

export type CurrentSystem = {
  code: SystemType;
  name: string;
  maxRolesPerUser: number | null;
};

export type CurrentRole = {
  system: SystemType;
  code: string;
  name: string;
  description: string;
  sortOrder: number;
  isSystemAdmin: boolean;
};

/** One `user_roles` row with what the checks need from its account. */
export type Holding = {
  userId: string;
  email: string;
  system: SystemType;
  role: string;
  /** Active and not deleted. */
  active: boolean;
};

export type RoleRow = Omit<CurrentRole, 'system'>;

export type SystemPlan = {
  system: SystemType;
  roleCount: number;
  /** The `systems` row to write, or null when it already matches. */
  systemRow: CurrentSystem | null;
  inserts: RoleRow[];
  updates: RoleRow[];
  deletes: string[];
};

export type CatalogPlan = {
  errors: string[];
  systems: SystemPlan[];
};

export function hasChanges(plan: SystemPlan): boolean {
  return (
    plan.systemRow !== null ||
    plan.inserts.length > 0 ||
    plan.updates.length > 0 ||
    plan.deletes.length > 0
  );
}

/** `VRMS: 3 roles, no change` or `BMS: 5 roles, added DRIVER, HELPER`. */
export function describePlan(plan: SystemPlan): string {
  const head = `${plan.system}: ${plan.roleCount} role${plan.roleCount === 1 ? '' : 's'}`;
  if (!hasChanges(plan)) return `${head}, no change`;
  const parts: string[] = [];
  if (plan.systemRow) parts.push('system details updated');
  if (plan.inserts.length > 0)
    parts.push(`added ${plan.inserts.map((r) => r.code).join(', ')}`);
  if (plan.updates.length > 0)
    parts.push(`updated ${plan.updates.map((r) => r.code).join(', ')}`);
  if (plan.deletes.length > 0) parts.push(`removed ${plan.deletes.join(', ')}`);
  return `${head}, ${parts.join('; ')}`;
}

function rowsOf(definition: SystemDefinition): RoleRow[] {
  return definition.roles.map((role: RoleDefinition, index) => ({
    code: role.code,
    name: role.name,
    description: role.description,
    sortOrder: index,
    isSystemAdmin: role.isSystemAdmin === true,
  }));
}

function sameRow(a: RoleRow, b: RoleRow): boolean {
  return (
    a.name === b.name &&
    a.description === b.description &&
    a.sortOrder === b.sortOrder &&
    a.isSystemAdmin === b.isSystemAdmin
  );
}

/** Errors in the files alone, before the database is compared (AC-3). */
function fileErrors(
  definitions: SystemDefinition[],
  allSystems: readonly SystemType[],
): string[] {
  const errors: string[] = [];
  const seenSystems = new Set<string>();

  for (const def of definitions) {
    const at = def.system;
    if (!allSystems.includes(def.system)) {
      errors.push(`${at}: not a SystemType value.`);
    }
    if (seenSystems.has(def.system)) {
      errors.push(`${at}: has more than one catalog file.`);
    }
    seenSystems.add(def.system);

    if (!def.name.trim() || def.name.length > SYSTEM_NAME_MAX) {
      errors.push(
        `${at}: the system name must be 1 to ${SYSTEM_NAME_MAX} characters.`,
      );
    }
    if (
      def.maxRolesPerUser !== null &&
      (!Number.isInteger(def.maxRolesPerUser) || def.maxRolesPerUser < 1)
    ) {
      errors.push(
        `${at}: maxRolesPerUser must be a whole number of at least 1, or null.`,
      );
    }
    if (def.roles.length === 0) {
      errors.push(`${at}: has no role.`);
    }

    const codes = new Set<string>();
    for (const role of def.roles) {
      if (!ROLE_CODE_RE.test(role.code)) {
        errors.push(
          `${at}: role code '${role.code}' must match ${ROLE_CODE_RE.source}.`,
        );
      }
      if (codes.has(role.code)) {
        errors.push(`${at}: role code '${role.code}' appears twice.`);
      }
      codes.add(role.code);
      if (!role.name.trim() || role.name.length > NAME_MAX) {
        errors.push(
          `${at} ${role.code}: the name must be 1 to ${NAME_MAX} characters.`,
        );
      }
      if (
        !role.description.trim() ||
        role.description.length > DESCRIPTION_MAX
      ) {
        errors.push(
          `${at} ${role.code}: the description must be 1 to ${DESCRIPTION_MAX} characters.`,
        );
      }
    }

    const admins = def.roles.filter((r) => r.isSystemAdmin === true);
    if (def.roles.length > 0 && admins.length !== 1) {
      errors.push(
        `${at}: needs exactly one isSystemAdmin role, found ${admins.length}.`,
      );
    }
  }

  for (const system of allSystems) {
    if (!seenSystems.has(system)) {
      errors.push(`${system}: has no catalog file in prisma/catalog/.`);
    }
  }
  return errors;
}

function emailList(holdings: Holding[]): string {
  const emails = [...new Set(holdings.map((h) => h.email))].sort();
  const shown = emails.slice(0, HOLDER_LIST_LIMIT).join(', ');
  return emails.length > HOLDER_LIST_LIMIT
    ? `${shown} and ${emails.length - HOLDER_LIST_LIMIT} more`
    : shown;
}

/**
 * Compares the files with the tables and the role holders. `errors` empty means the plan is safe
 * to write; otherwise nothing may be written (AC-3).
 */
export function planCatalogSync(
  definitions: SystemDefinition[],
  allSystems: readonly SystemType[],
  current: { systems: CurrentSystem[]; roles: CurrentRole[] },
  holdings: Holding[],
): CatalogPlan {
  const errors = fileErrors(definitions, allSystems);
  const systems: SystemPlan[] = [];

  for (const def of definitions) {
    if (!allSystems.includes(def.system)) continue;
    const wanted = rowsOf(def);
    const wantedCodes = new Set(wanted.map((r) => r.code));
    const existing = current.roles.filter((r) => r.system === def.system);
    const existingByCode = new Map(existing.map((r) => [r.code, r]));
    const held = holdings.filter((h) => h.system === def.system);

    const inserts = wanted.filter((r) => !existingByCode.has(r.code));
    const updates = wanted.filter((r) => {
      const now = existingByCode.get(r.code);
      return now !== undefined && !sameRow(now, r);
    });
    const deletes = existing
      .filter((r) => !wantedCodes.has(r.code))
      .map((r) => r.code);

    // A dropped (or renamed, AC-4) role that someone still holds
    for (const code of deletes) {
      const holders = held.filter((h) => h.role === code);
      if (holders.length > 0) {
        errors.push(
          `${def.system}: can't remove ${code}, ${holders.length} account${holders.length === 1 ? ' holds' : 's hold'} it: ${emailList(holders)}. Move them to another role first.`,
        );
      }
    }

    // A limit lower than what some account already holds
    if (def.maxRolesPerUser !== null) {
      const perUser = new Map<string, Holding[]>();
      for (const h of held) {
        perUser.set(h.userId, [...(perUser.get(h.userId) ?? []), h]);
      }
      const over = [...perUser.values()].filter(
        (rows) => rows.length > (def.maxRolesPerUser as number),
      );
      if (over.length > 0) {
        errors.push(
          `${def.system}: maxRolesPerUser ${def.maxRolesPerUser} is below what ${over.length === 1 ? '1 account already holds' : `${over.length} accounts already hold`}: ${emailList(over.map((rows) => rows[0]))}.`,
        );
      }
    }

    // The admin flag moving to a role no active account holds would leave nobody as admin
    const oldAdmin = existing.find((r) => r.isSystemAdmin)?.code;
    const newAdmin = wanted.find((r) => r.isSystemAdmin)?.code;
    if (
      oldAdmin !== undefined &&
      newAdmin !== undefined &&
      oldAdmin !== newAdmin
    ) {
      if (!held.some((h) => h.role === newAdmin && h.active)) {
        errors.push(
          `${def.system}: the admin flag can't move to ${newAdmin}, no active account holds it.`,
        );
      }
    }

    const now = current.systems.find((s) => s.code === def.system);
    const systemRow =
      !now ||
      now.name !== def.name ||
      now.maxRolesPerUser !== def.maxRolesPerUser
        ? {
            code: def.system,
            name: def.name,
            maxRolesPerUser: def.maxRolesPerUser,
          }
        : null;

    systems.push({
      system: def.system,
      roleCount: wanted.length,
      systemRow,
      inserts,
      updates,
      deletes,
    });
  }

  return { errors, systems };
}
