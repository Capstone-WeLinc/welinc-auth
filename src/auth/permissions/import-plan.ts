import type { SystemType } from '@prisma/client';

// Suite spec 0013, AC-28: the one time import of a system's matrix and history, as exported by
// backend-vrms's `permissions:export`. Pure: prisma/permissions-import.ts reads the database,
// calls planImport, and writes the plan in one transaction.

/** The file shape backend-vrms writes (its prisma/permissions-export.ts). */
export type PermissionsExport = {
  format: 'welinc-permissions-export';
  formatVersion: 1;
  system: string;
  exportedAt: string;
  cells: { role: string; key: string; allowed: boolean }[];
  changes: {
    role: string;
    key: string;
    before: boolean | null;
    after: boolean | null;
    actorId: string | null;
    actorName: string | null;
    actorEmail: string | null;
    note: string | null;
    createdAt: string;
  }[];
};

/** Who an imported row with no actor was: VRMS's own startup backfill. */
export const IMPORTED_SYSTEM_ACTOR = 'VRMS (automatic)';

/** AC-28: the key whose value each role carries onto `team.manage`. */
const RENAMES: Record<string, string> = { 'users.manage': 'team.manage' };

const NOTE_MAX = 500;

export type ImportPlan = {
  /** Cells to set (only the ones whose value differs today). */
  sets: { role: string; key: string; allowed: boolean }[];
  /** Cells left alone, each with why, for the script to list. */
  skipped: string[];
  history: {
    role: string;
    key: string;
    before: boolean | null;
    after: boolean | null;
    actorId: string | null;
    actorName: string;
    actorEmail: string | null;
    note: string | null;
    createdAt: Date;
  }[];
};

/** Every reason the file can't be imported, before anything is read from the database. */
export function fileProblems(data: unknown, system: SystemType): string[] {
  const d = data as Partial<PermissionsExport> | null;
  if (!d || d.format !== 'welinc-permissions-export' || d.formatVersion !== 1) {
    return [
      'This is not a permissions export (format welinc-permissions-export, version 1)',
    ];
  }
  const problems: string[] = [];
  if (d.system !== system)
    problems.push(`The file is for ${String(d.system)}, not ${system}`);
  if (!Array.isArray(d.cells)) problems.push('The file has no cells list');
  if (!Array.isArray(d.changes)) problems.push('The file has no changes list');
  for (const c of d.changes ?? []) {
    if (Number.isNaN(new Date(c.createdAt).getTime())) {
      problems.push(`A change has a bad createdAt: ${String(c.createdAt)}`);
      break;
    }
  }
  return problems;
}

/**
 * AC-28: set each cell whose role and key exist here, except locked cells; copy each role's
 * `users.manage` onto `team.manage`; carry the whole history with its original time and actor
 * (`actorId` kept only when that user exists here).
 */
export function planImport(
  data: PermissionsExport,
  current: {
    roles: string[];
    permissions: { key: string; lockedRoles: string[] }[];
    cells: { role: string; key: string; allowed: boolean }[];
    userIds: Set<string>;
  },
): ImportPlan {
  const roles = new Set(current.roles);
  const locks = new Map(
    current.permissions.map((p) => [p.key, new Set(p.lockedRoles)]),
  );
  const now = new Map(
    current.cells.map((c) => [`${c.role}|${c.key}`, c.allowed]),
  );
  const wanted = new Map<
    string,
    { role: string; key: string; allowed: boolean }
  >();
  const skipped: string[] = [];

  const consider = (
    role: string,
    key: string,
    allowed: boolean,
    from?: string,
  ) => {
    const what = from ? `${role} ${key} (from ${from})` : `${role} ${key}`;
    if (!roles.has(role)) return skipped.push(`${what}: no such role`);
    if (!locks.has(key)) return skipped.push(`${what}: no such permission`);
    if (locks.get(key)?.has(role))
      return skipped.push(`${what}: locked, keeps its default`);
    wanted.set(`${role}|${key}`, { role, key, allowed });
  };
  for (const cell of data.cells) {
    const renamed = RENAMES[cell.key];
    if (renamed) consider(cell.role, renamed, cell.allowed, cell.key);
    else consider(cell.role, cell.key, cell.allowed);
  }

  const sets = [...wanted.values()].filter(
    (c) => now.get(`${c.role}|${c.key}`) !== c.allowed,
  );

  const history = data.changes.map((c) => {
    const actorId =
      c.actorId && current.userIds.has(c.actorId) ? c.actorId : null;
    return {
      role: c.role.slice(0, 40),
      key: c.key.slice(0, 60),
      before: c.before,
      after: c.after,
      actorId,
      actorName: (
        c.actorName?.trim() ||
        (c.actorId ? 'Former user' : IMPORTED_SYSTEM_ACTOR)
      ).slice(0, 100),
      actorEmail: c.actorEmail ? c.actorEmail.slice(0, 255) : null,
      note: c.note ? c.note.slice(0, NOTE_MAX) : null,
      createdAt: new Date(c.createdAt),
    };
  });

  return { sets, skipped, history };
}
