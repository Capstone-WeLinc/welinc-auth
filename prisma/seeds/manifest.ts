// Spec 0006: the suite seed people. `people.json` next to this file is the only source of seed
// people for every system; this module reads it and holds the pure checks the seed runs before
// writing anything. Other systems copy people.json byte for byte (`npm run seed:check`).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const MANIFEST_PATH = join(__dirname, 'people.json');

export const PERSON_STATES = [
  'active',
  'locked',
  'deactivated',
  'unverified',
  'deleted',
] as const;
export type PersonState = (typeof PERSON_STATES)[number];

export const PERSON_GROUPS = [
  'office',
  'mechanic',
  'bulk',
  'driver',
  'helper',
  'multi',
  'state',
] as const;
export type PersonGroup = (typeof PERSON_GROUPS)[number];

export type ManifestRole = { system: string; role: string };

export type ManifestPerson = {
  id: string;
  email: string;
  name: string;
  group: PersonGroup;
  state: PersonState;
  password: string;
  contact: string | null;
  roles: ManifestRole[];
  /** Spec 0013, AC-33: a suite admin (no roles allowed); left out means false. */
  suiteAdmin?: boolean;
};

/** Spec 0013, AC-1: never more than this many suite admins. */
export const MAX_SUITE_ADMINS = 3;

export type Manifest = {
  version: number;
  passwords: Record<string, string>;
  people: ManifestPerson[];
};

/** The role catalog as `systems` and `system_roles` hold it (spec 0004). */
export type CatalogView = {
  systems: { code: string; maxRolesPerUser: number | null }[];
  roles: { system: string; code: string; isSystemAdmin: boolean }[];
};

const ID_RE = /^00000000-0000-4000-8000-\d{12}$/;
const EMAIL_DOMAIN = '@welinc.com';
/** Login's lockout threshold; a `locked` seed person looks exactly like a real lockout. */
export const LOCKED_ATTEMPTS = 5;

/** Reads and parses the manifest. Throws a plain message when the file is missing or not JSON. */
export function loadManifest(path = MANIFEST_PATH): Manifest {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new Error(`No manifest at ${path}`);
  }
  try {
    return JSON.parse(text) as Manifest;
  } catch (e) {
    throw new Error(
      `${path} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`,
    );
  }
}

/**
 * AC-2: every problem with the manifest, checked against itself and the catalog. An empty list
 * means the seed may write. Never stops at the first problem.
 */
export function checkManifest(
  manifest: Manifest,
  catalog: CatalogView,
): string[] {
  const problems: string[] = [];
  if (manifest.version !== 1) {
    problems.push(`version is ${String(manifest.version)}, expected 1`);
  }
  const passwords = manifest.passwords ?? {};
  if (!Array.isArray(manifest.people)) {
    problems.push('people is not a list');
    return problems;
  }

  const maxBySystem = new Map(
    catalog.systems.map((s) => [s.code, s.maxRolesPerUser]),
  );
  const roleKey = (system: string, code: string) => `${system}:${code}`;
  const roles = new Map(
    catalog.roles.map((r) => [roleKey(r.system, r.code), r]),
  );
  const seenIds = new Map<string, number>();
  const seenEmails = new Map<string, number>();

  manifest.people.forEach((p, index) => {
    const who = `people[${index}] (${p.email ?? p.id ?? 'no email'})`;

    if (typeof p.id !== 'string' || !ID_RE.test(p.id)) {
      problems.push(
        `${who}: id ${String(p.id)} is not 00000000-0000-4000-8000- plus 12 digits`,
      );
    } else if (seenIds.has(p.id)) {
      problems.push(
        `${who}: id ${p.id} is also used by people[${seenIds.get(p.id)}]`,
      );
    } else {
      seenIds.set(p.id, index);
    }

    if (typeof p.email !== 'string') {
      problems.push(`${who}: email is missing`);
    } else {
      const email = p.email.toLowerCase();
      if (p.email !== email) problems.push(`${who}: email is not lowercase`);
      if (!email.endsWith(EMAIL_DOMAIN)) {
        problems.push(`${who}: email does not end in ${EMAIL_DOMAIN}`);
      }
      if (seenEmails.has(email)) {
        problems.push(
          `${who}: email ${email} is also used by people[${seenEmails.get(email)}]`,
        );
      } else {
        seenEmails.set(email, index);
      }
    }

    if (
      typeof p.name !== 'string' ||
      p.name.trim().length === 0 ||
      p.name.length > 100
    ) {
      problems.push(`${who}: name must be 1 to 100 characters`);
    }
    if (!PERSON_GROUPS.includes(p.group)) {
      problems.push(
        `${who}: group ${String(p.group)} is not one of ${PERSON_GROUPS.join(', ')}`,
      );
    }
    if (!PERSON_STATES.includes(p.state)) {
      problems.push(
        `${who}: state ${String(p.state)} is not one of ${PERSON_STATES.join(', ')}`,
      );
    }
    if (typeof p.password !== 'string' || !(p.password in passwords)) {
      problems.push(
        `${who}: password ${String(p.password)} is not a key of passwords`,
      );
    }
    if (p.contact !== null && typeof p.contact !== 'string') {
      problems.push(`${who}: contact must be a string or null`);
    }

    if (p.suiteAdmin !== undefined && typeof p.suiteAdmin !== 'boolean') {
      problems.push(`${who}: suiteAdmin must be true or false`);
    }

    if (!Array.isArray(p.roles)) {
      problems.push(`${who}: roles is not a list`);
      return;
    }
    // Spec 0013, AC-3, AC-33: a suite admin holds no system role
    if (p.suiteAdmin === true && p.roles.length > 0) {
      problems.push(`${who}: is a suite admin, so roles must be empty`);
    }
    const perSystem = new Map<string, number>();
    const seenRoles = new Set<string>();
    const adminIn = new Set<string>();
    for (const r of p.roles) {
      const key = roleKey(r.system, r.role);
      const def = roles.get(key);
      if (!def) {
        problems.push(
          `${who}: role ${r.system} ${r.role} is not in the catalog`,
        );
        continue;
      }
      if (seenRoles.has(key)) {
        problems.push(`${who}: role ${r.system} ${r.role} is listed twice`);
        continue;
      }
      seenRoles.add(key);
      perSystem.set(r.system, (perSystem.get(r.system) ?? 0) + 1);
      if (def.isSystemAdmin) adminIn.add(r.system);
    }
    for (const [system, count] of perSystem) {
      const max = maxBySystem.get(system);
      if (max != null && count > max) {
        problems.push(
          `${who}: holds ${count} ${system} roles, more than its limit of ${max}`,
        );
      }
    }
    if (
      catalog.systems.length > 0 &&
      catalog.systems.every((s) => adminIn.has(s.code))
    ) {
      problems.push(`${who}: is the admin in every system`);
    }
  });
  const suiteAdmins = manifest.people.filter((p) => p.suiteAdmin === true);
  if (suiteAdmins.length > MAX_SUITE_ADMINS) {
    problems.push(
      `${suiteAdmins.length} people are suite admins, more than the limit of ${MAX_SUITE_ADMINS}`,
    );
  }
  return problems;
}

/** The `users` columns a person's state decides (AC-5). */
export type StateFields = {
  isActive: boolean;
  emailVerified: boolean;
  /** Every seed person has a password (spec 0009, AC-16), `state.unverified@` included. */
  passwordSet: boolean;
  failedLoginAttempts: number;
  lockedAt: Date | null;
  deletedAt: Date | null;
  /** Spec 0012: a seed person is never an erased one, so a rerun clears an erasure. */
  erasedAt: Date | null;
};

/**
 * AC-5: the state columns after a run. `lockedAt` and `deletedAt` keep an existing value, so a
 * rerun leaves the row (and the directory feed) unchanged; otherwise they take the run's time.
 */
export function stateFields(
  state: PersonState,
  existing: { lockedAt: Date | null; deletedAt: Date | null } | undefined,
  now: Date,
): StateFields {
  const active: StateFields = {
    isActive: true,
    emailVerified: true,
    passwordSet: true,
    failedLoginAttempts: 0,
    lockedAt: null,
    deletedAt: null,
    erasedAt: null,
  };
  switch (state) {
    case 'active':
      return active;
    case 'locked':
      return {
        ...active,
        failedLoginAttempts: LOCKED_ATTEMPTS,
        lockedAt: existing?.lockedAt ?? now,
      };
    case 'deactivated':
      return { ...active, isActive: false };
    case 'unverified':
      return { ...active, emailVerified: false };
    case 'deleted':
      return {
        ...active,
        isActive: false,
        deletedAt: existing?.deletedAt ?? now,
      };
  }
}

/**
 * AC-7: a manifest email already held by a user with another id (soft deleted users included).
 * Upserting by id would then break the unique email, so the seed refuses before writing. This
 * also catches two manifest people swapping emails.
 */
export function emailConflicts(
  people: Pick<ManifestPerson, 'id' | 'email'>[],
  existing: { id: string; email: string }[],
): string[] {
  const holder = new Map(existing.map((u) => [u.email.toLowerCase(), u.id]));
  const problems: string[] = [];
  for (const p of people) {
    const heldBy = holder.get(p.email.toLowerCase());
    if (heldBy !== undefined && heldBy !== p.id) {
      problems.push(
        `${p.email} belongs to user ${heldBy}, but the manifest gives it to ${p.id}`,
      );
    }
  }
  return problems;
}

export const PRODUCTION_REFUSAL =
  'Seeding is off in production. Set SEED_ALLOW=staging only on the staging environment.';
export const RESET_REFUSAL = '--reset runs only on a local database.';

/** AC-9: localhost, 127.0.0.1, or a name with no dot (a compose service such as auth-db). */
export function isLocalDatabase(databaseUrl: string | undefined): boolean {
  if (!databaseUrl) return false;
  let host: string;
  try {
    host = new URL(databaseUrl).hostname;
  } catch {
    return false;
  }
  if (host === '') return false;
  return host === 'localhost' || host === '127.0.0.1' || !host.includes('.');
}

export type SeedMode =
  | { ok: true; reset: boolean; staging: boolean }
  | { ok: false; message: string };

/** AC-9 and AC-10: decides whether this run may write, before any connection is opened. */
export function seedGuard(input: {
  nodeEnv: string | undefined;
  seedAllow: string | undefined;
  databaseUrl: string | undefined;
  reset: boolean;
}): SeedMode {
  // Any value other than `staging` counts as unset
  const staging = input.seedAllow === 'staging';
  if (input.nodeEnv === 'production' && !staging) {
    return { ok: false, message: PRODUCTION_REFUSAL };
  }
  if (input.reset) {
    const devEnv =
      input.nodeEnv === undefined ||
      input.nodeEnv === 'development' ||
      input.nodeEnv === 'test';
    if (!devEnv || staging || !isLocalDatabase(input.databaseUrl)) {
      return { ok: false, message: RESET_REFUSAL };
    }
  }
  return { ok: true, reset: input.reset, staging };
}
