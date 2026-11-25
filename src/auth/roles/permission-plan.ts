import type { SystemType } from '@prisma/client';
import {
  PERMISSION_KEY_RE,
  type PermissionDefinition,
  type SystemDefinition,
} from './catalog.types';

// Spec 0013, AC-25: what `catalog:sync` changes in a system's permission matrix, and every reason
// it refuses. Pure, like catalog-plan.ts: the runner reads the database, calls
// planPermissionSync, and writes the plan in the same transaction as the role plan, only when
// neither has errors.

/** The actor name on every `permission_changes` row the sync writes (AC-25). */
export const CATALOG_SYNC_ACTOR = 'Catalog sync';

const LABEL_MAX = 100;
const GROUP_MAX = 40;
const DESCRIPTION_MAX = 300;

export type CurrentPermission = {
  system: SystemType;
  key: string;
  label: string;
  group: string;
  description: string;
  sortOrder: number;
  lockedRoles: string[];
  /** Suite spec 0018: the roles whose default is on, sorted (Reset to defaults reads it). */
  defaultRoles: string[];
};

export type CurrentCell = {
  system: SystemType;
  role: string;
  key: string;
  allowed: boolean;
};

export type PermissionRow = Omit<CurrentPermission, 'system'>;

export type CellRow = { role: string; key: string; allowed: boolean };

/** One `permission_changes` row the sync writes: `before` or `after` null for a new or gone cell. */
export type CellChange = {
  role: string;
  key: string;
  before: boolean | null;
  after: boolean | null;
};

export type PermissionPlan = {
  system: SystemType;
  /** `system_permissions` rows to write: new keys, and keys whose label, order, locks or defaults changed. */
  upserts: PermissionRow[];
  /** Keys that left the file. Their cells are in `cellDeletes`. */
  deletes: string[];
  /** Missing cells, written with their default and no history row. */
  cellInserts: CellRow[];
  /** Locked cells that differed from their default, set back to it. */
  cellResets: CellRow[];
  /** Cells whose key or role left the file; deleted before the key or role goes. */
  cellDeletes: { role: string; key: string }[];
  /** One history row per reset or deleted cell. */
  changes: CellChange[];
  /** True when anything above is not empty: the matrix version goes up by one. */
  bump: boolean;
};

function rowsOf(definitions: PermissionDefinition[]): PermissionRow[] {
  return definitions.map((p, index) => ({
    key: p.key,
    label: p.label,
    group: p.group,
    description: p.description,
    sortOrder: index,
    lockedRoles: [...(p.lockedRoles ?? [])].sort(),
    defaultRoles: Object.keys(p.defaults)
      .filter((role) => p.defaults[role])
      .sort(),
  }));
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function sameRow(a: PermissionRow, b: PermissionRow): boolean {
  return (
    a.label === b.label &&
    a.group === b.group &&
    a.description === b.description &&
    a.sortOrder === b.sortOrder &&
    sameList(a.lockedRoles, b.lockedRoles) &&
    sameList(a.defaultRoles, b.defaultRoles)
  );
}

function textError(
  system: SystemType,
  key: string,
  field: string,
  value: unknown,
  max: number,
): string | null {
  if (
    typeof value !== 'string' ||
    value.trim().length === 0 ||
    value.length > max
  ) {
    return `${system} permission ${key}: ${field} must be 1 to ${max} characters`;
  }
  return null;
}

/** Every reason the permissions in one system's file can't be synced (AC-25). */
export function permissionFileErrors(definition: SystemDefinition): string[] {
  const { system } = definition;
  const roles = new Set(definition.roles.map((r) => r.code));
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const p of definition.permissions ?? []) {
    const key = String(p.key);
    if (!PERMISSION_KEY_RE.test(key) || key.length > 60) {
      errors.push(
        `${system} permission ${key}: the key must be dotted lower case words, at most 60 characters`,
      );
    }
    if (seen.has(key))
      errors.push(`${system} permission ${key} is listed twice`);
    seen.add(key);
    for (const e of [
      textError(system, key, 'label', p.label, LABEL_MAX),
      textError(system, key, 'group', p.group, GROUP_MAX),
      textError(system, key, 'description', p.description, DESCRIPTION_MAX),
    ]) {
      if (e) errors.push(e);
    }
    const defaults = p.defaults ?? {};
    for (const role of Object.keys(defaults)) {
      if (!roles.has(role))
        errors.push(
          `${system} permission ${key}: the default names ${role}, which ${system} doesn't have`,
        );
      else if (typeof defaults[role] !== 'boolean')
        errors.push(
          `${system} permission ${key}: the default for ${role} must be true or false`,
        );
    }
    for (const role of roles) {
      if (!(role in defaults))
        errors.push(`${system} permission ${key}: no default for ${role}`);
    }
    const locked = p.lockedRoles ?? [];
    if (new Set(locked).size !== locked.length)
      errors.push(`${system} permission ${key}: a locked role is listed twice`);
    for (const role of locked) {
      if (!roles.has(role))
        errors.push(
          `${system} permission ${key}: the lock names ${role}, which ${system} doesn't have`,
        );
    }
  }
  return errors;
}

/**
 * The plan for one system (AC-25): write `system_permissions` from the file, insert missing cells
 * with their default, never overwrite an unlocked cell, set every locked cell to its default, and
 * delete the cells of keys or roles that left the file. Call it only when permissionFileErrors
 * found nothing.
 */
export function planPermissionSync(
  definition: SystemDefinition,
  current: { permissions: CurrentPermission[]; cells: CurrentCell[] },
): PermissionPlan {
  const { system } = definition;
  const definitions = definition.permissions ?? [];
  const roles = definition.roles.map((r) => r.code);
  const wanted = rowsOf(definitions);
  const wantedKeys = new Set(wanted.map((p) => p.key));
  const roleSet = new Set(roles);

  const existing = new Map(
    current.permissions
      .filter((p) => p.system === system)
      .map((p) => [p.key, p]),
  );
  const upserts = wanted.filter((row) => {
    const now = existing.get(row.key);
    return (
      !now ||
      !sameRow(row, {
        ...now,
        lockedRoles: [...now.lockedRoles].sort(),
        defaultRoles: [...now.defaultRoles].sort(),
      })
    );
  });
  const deletes = [...existing.keys()]
    .filter((key) => !wantedKeys.has(key))
    .sort();

  const cells = current.cells.filter((c) => c.system === system);
  const cellAt = new Map(cells.map((c) => [`${c.role}|${c.key}`, c]));
  const changes: CellChange[] = [];

  const cellDeletes = cells
    .filter((c) => !wantedKeys.has(c.key) || !roleSet.has(c.role))
    .sort((a, b) => a.key.localeCompare(b.key) || a.role.localeCompare(b.role))
    .map((c) => {
      changes.push({
        role: c.role,
        key: c.key,
        before: c.allowed,
        after: null,
      });
      return { role: c.role, key: c.key };
    });

  const cellInserts: CellRow[] = [];
  const cellResets: CellRow[] = [];
  for (const p of definitions) {
    const locked = new Set(p.lockedRoles ?? []);
    for (const role of roles) {
      const allowed = p.defaults[role];
      const cell = cellAt.get(`${role}|${p.key}`);
      if (!cell) {
        cellInserts.push({ role, key: p.key, allowed });
      } else if (locked.has(role) && cell.allowed !== allowed) {
        cellResets.push({ role, key: p.key, allowed });
        changes.push({
          role,
          key: p.key,
          before: cell.allowed,
          after: allowed,
        });
      }
    }
  }

  return {
    system,
    upserts,
    deletes,
    cellInserts,
    cellResets,
    cellDeletes,
    changes,
    bump:
      upserts.length +
        deletes.length +
        cellInserts.length +
        cellResets.length +
        cellDeletes.length >
      0,
  };
}

/** One line per system for the sync's output, or a quiet line when nothing changes. */
export function describePermissionPlan(plan: PermissionPlan): string {
  if (!plan.bump) return `${plan.system} permissions: no changes`;
  const parts = [
    plan.upserts.length && `${plan.upserts.length} keys written`,
    plan.deletes.length && `${plan.deletes.length} keys removed`,
    plan.cellInserts.length && `${plan.cellInserts.length} cells added`,
    plan.cellResets.length && `${plan.cellResets.length} locked cells reset`,
    plan.cellDeletes.length && `${plan.cellDeletes.length} cells removed`,
  ].filter(Boolean);
  return `${plan.system} permissions: ${parts.join(', ')}`;
}
