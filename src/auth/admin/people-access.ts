import { HttpStatus } from '@nestjs/common';
import { Prisma, SystemType } from '@prisma/client';
import { coded } from '../errors';
import type { CatalogSystem } from '../roles/catalog.service';
import type { ReadScope } from '../user-scope';
import { notAdminOfSystem } from './admin-errors';

// Suite spec 0019, AC-21a: the People list's `access` filter. Each item is a whole system
// (`VRMS`) or one of its roles (`VMMS:MECHANIC`), read as any of them. Holding a role means what
// it means in the list today (`roles: { some }`), with no new expiry rule.

export const ACCESS_MAX_ITEMS = 40;
export const ACCESS_MAX_LENGTH = 600;

/** One upper case system code, then optionally `:` and a role code (`ROLE_CODE_RE`). */
const ACCESS_ITEM_RE = /^[A-Z]+(?::[A-Z][A-Z0-9_]{1,39})?$/;

/** One normalized pick: a whole system (`role` null) or one role of it. */
export type AccessItem = { system: SystemType; role: string | null };

const invalid = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);

const unknownRole = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'UNKNOWN_ROLE', message);

/** How an item is written in the address and the cursor fingerprint. */
export function accessItemText(item: AccessItem): string {
  return item.role === null ? item.system : `${item.system}:${item.role}`;
}

/**
 * Checks `access` in AC-21a's order (malformed, too many, unknown, out of scope), then
 * normalizes it: duplicates go, a whole system absorbs its own role items, items sort. It never
 * turns "every role ticked" into the whole system; the portal does that.
 */
export function parseAccess(
  raw: string | undefined,
  catalog: readonly CatalogSystem[],
  scope: ReadScope,
): AccessItem[] {
  if (raw === undefined) return [];
  const parts = raw.split(',');
  if (parts.some((part) => !ACCESS_ITEM_RE.test(part))) {
    throw invalid(
      'access must be a comma list of SYSTEM or SYSTEM:ROLE items, in capitals with no spaces',
    );
  }
  if (parts.length > ACCESS_MAX_ITEMS || raw.length > ACCESS_MAX_LENGTH) {
    throw invalid(
      `access takes at most ${ACCESS_MAX_ITEMS} items and ${ACCESS_MAX_LENGTH} characters`,
    );
  }
  const items = parts.map((part): AccessItem => {
    const [system, role] = part.split(':');
    const entry = catalog.find((s) => s.code === system);
    if (!entry) throw unknownRole(`${system} is not a WeLinc system`);
    if (role !== undefined && !entry.roles.some((r) => r.code === role)) {
      throw unknownRole(`${system} has no role ${role}`);
    }
    return { system: entry.code, role: role ?? null };
  });
  for (const item of items) {
    const inScope =
      scope.only !== null
        ? item.system === scope.only
        : scope.systems === null || scope.systems.includes(item.system);
    if (!inScope) throw notAdminOfSystem();
  }
  return normalizeAccess(items);
}

/** Duplicates go, a whole system absorbs its role items, and the items sort by their text. */
export function normalizeAccess(items: readonly AccessItem[]): AccessItem[] {
  const whole = new Set(
    items.filter((i) => i.role === null).map((i) => i.system),
  );
  const kept = new Map<string, AccessItem>();
  for (const item of items) {
    if (item.role !== null && whole.has(item.system)) continue;
    kept.set(accessItemText(item), item);
  }
  return [...kept.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, item]) => item);
}

/** The cursor fingerprint part: the normalized items, sorted, comma joined. */
export function accessKey(items: readonly AccessItem[]): string {
  return items.map(accessItemText).join(',');
}

/** Any of the items; no items is no filter. One `roles: { some }` per system. */
export function accessWhere(
  items: readonly AccessItem[],
): Prisma.UserWhereInput {
  if (items.length === 0) return {};
  const bySystem = new Map<SystemType, string[] | null>();
  for (const item of items) {
    if (item.role === null) {
      bySystem.set(item.system, null);
    } else if (bySystem.get(item.system) !== null) {
      bySystem.set(item.system, [
        ...(bySystem.get(item.system) ?? []),
        item.role,
      ]);
    }
  }
  const clauses: Prisma.UserWhereInput[] = [...bySystem].map(
    ([system, roles]) => ({
      roles: {
        some: roles === null ? { system } : { system, role: { in: roles } },
      },
    }),
  );
  return clauses.length === 1 ? clauses[0] : { OR: clauses };
}
