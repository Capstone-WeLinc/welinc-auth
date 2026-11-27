import { liveRoleWhere } from '../roles/live-roles';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { ClientKind, type Session, SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { allowedCodes } from '../roles/allowed-roles';
import { sessionExpiresAt } from './session.service';

// Spec 0007: which systems a person holds, for the portal launcher (`/auth/sso`, `/auth/login`)
// and for each app's Switch system link (`user.systems` in every user grant answer).

/** The fixed launcher order (spec 0007, AC-1, AC-6). */
export const LAUNCHER_ORDER: readonly SystemType[] = [
  SystemType.BMS,
  SystemType.VMMS,
  SystemType.VRMS,
];

/** The distinct systems in `held`, in launcher order. */
export function launcherOrder(
  held: readonly { system: SystemType }[],
): SystemType[] {
  const systems = new Set(held.map((h) => h.system));
  return LAUNCHER_ORDER.filter((s) => systems.has(s));
}

export type LauncherRole = { code: string; name: string };

export type LauncherSystem = {
  system: SystemType;
  name: string;
  description: string;
  url: string;
  roles: LauncherRole[];
};

/** Suite spec 0014, AC-4: a system the person holds only through its phone app. */
export type LauncherMobileSystem = {
  system: SystemType;
  name: string;
  description: string;
  roles: LauncherRole[];
  app: { clientId: string; released: boolean };
};

/** Who the person is and what they can open: the launcher body before the session is known. */
export type LauncherSystems = {
  user: { id: string; name: string; email: string; picture: string | null };
  systems: LauncherSystem[];
  mobileSystems: LauncherMobileSystem[];
  /** Whether the person is a suite admin (suite spec 0019, AC-6): about themselves only. */
  suiteAdmin: boolean;
};

/** The browser session's cutoffs, as ISO times (suite spec 0016, AC-12a). */
export type LauncherCutoffs = {
  sessionExpiresAt: string;
  sessionAbsoluteExpiresAt: string;
  serverTime: string;
};

/**
 * The `/auth/sso`, `/auth/login` and `/auth/login/verify-email` body (spec 0007, AC-1, AC-3;
 * suite spec 0014, AC-4; suite spec 0016, AC-12a).
 */
export type LauncherAnswer = LauncherSystems & LauncherCutoffs;

/** The session fields the cutoffs come from. */
export type LauncherSession = Pick<
  Session,
  'endedAt' | 'idleExpiresAt' | 'absoluteExpiresAt'
>;

/**
 * Adds the session's cutoffs to the launcher body. `sessionExpiresAt` is computed as
 * `/auth/session` computes it; a web session always has a 12 hour cutoff, but one without
 * falls back to the idle cutoff so the field is never missing.
 */
export function withCutoffs(
  answer: LauncherSystems,
  session: LauncherSession,
  now: Date = new Date(),
): LauncherAnswer {
  const expires = sessionExpiresAt(session);
  return {
    ...answer,
    sessionExpiresAt: expires.toISOString(),
    sessionAbsoluteExpiresAt: (
      session.absoluteExpiresAt ?? expires
    ).toISOString(),
    serverTime: now.toISOString(),
  };
}

/** An active client row the launcher reads: confidential web clients and phone apps. */
export type LauncherClientRow = {
  id: string;
  kind: ClientKind;
  system: SystemType | null;
  webAddress: string | null;
  allowedRoles: unknown;
  appReleased: boolean;
  createdAt: Date;
};

type CatalogRow = {
  code: SystemType;
  name: string;
  description: string;
  roles: { code: string; name: string; sortOrder: number }[];
};

/**
 * Catalog order: `sortOrder`, then code. The launcher's role lists and `user.systemRoles` both
 * sort with it (VRMS spec 0027, step 6a).
 */
export const byCatalogOrder = (
  a: { sortOrder: number; code: string },
  b: { sortOrder: number; code: string },
): number => a.sortOrder - b.sortOrder || a.code.localeCompare(b.code);

const oldestFirst = (a: { createdAt: Date }, b: { createdAt: Date }) =>
  a.createdAt.getTime() - b.createdAt.getTime();

/** Whether one of `roles` (held in `system`) passes the client's `allowedRoles` (spec 0004). */
function passes(
  client: Pick<LauncherClientRow, 'allowedRoles'>,
  system: SystemType,
  roles: readonly string[],
): boolean {
  const allowed = allowedCodes(client.allowedRoles, system);
  return allowed === null || roles.some((r) => allowed.includes(r));
}

/** The system's web clients: confidential with a web address, oldest first (the one used). */
function webClients(
  clients: readonly LauncherClientRow[],
  system: SystemType,
): LauncherClientRow[] {
  return clients
    .filter(
      (c) =>
        c.system === system &&
        c.kind === ClientKind.CONFIDENTIAL &&
        c.webAddress !== null,
    )
    .sort(oldestFirst);
}

/** The held role codes per system. */
function heldBySystem(
  held: readonly { system: SystemType; role: string }[],
): Map<SystemType, string[]> {
  const map = new Map<SystemType, string[]>();
  for (const h of held) {
    map.set(h.system, [...(map.get(h.system) ?? []), h.role]);
  }
  return map;
}

/**
 * Pure (suite spec 0014, AC-4): the systems a person can open on the web, in launcher order. A
 * held system counts when one live role passes its web client's `allowedRoles`.
 */
export function webSystemCodes(
  held: readonly { system: SystemType; role: string }[],
  clients: readonly LauncherClientRow[],
): SystemType[] {
  const roles = heldBySystem(held);
  return launcherOrder(held).filter((code) => {
    const web = webClients(clients, code)[0];
    return web !== undefined && passes(web, code, roles.get(code) ?? []);
  });
}

/**
 * Pure: the launcher cards from the user's role rows, the catalog and the active clients. A held
 * system goes to `systems` when a role passes its web client, else to `mobileSystems` when a role
 * passes an active phone app of that system (suite spec 0014, AC-4), else it is left out. A held
 * system with no usable web client is named in `missing` (spec 0007, AC-2).
 */
export function buildLauncherSystems(
  held: readonly { system: SystemType; role: string }[],
  catalog: readonly CatalogRow[],
  clients: readonly LauncherClientRow[],
): {
  systems: LauncherSystem[];
  mobileSystems: LauncherMobileSystem[];
  missing: SystemType[];
  duplicates: SystemType[];
} {
  const systems: LauncherSystem[] = [];
  const mobileSystems: LauncherMobileSystem[] = [];
  const missing: SystemType[] = [];
  const duplicates: SystemType[] = [];
  const bySystem = heldBySystem(held);
  for (const code of launcherOrder(held)) {
    const entry = catalog.find((c) => c.code === code);
    const web = webClients(clients, code);
    if (!entry || web.length === 0) missing.push(code);
    if (!entry) continue;
    if (web.length > 1) duplicates.push(code);
    const codes = bySystem.get(code) ?? [];
    const roles = entry.roles
      .filter((r) => codes.includes(r.code))
      .sort(byCatalogOrder)
      .map((r) => ({ code: r.code, name: r.name }));
    const card = {
      system: code,
      name: entry.name,
      description: entry.description,
    };

    const first = web[0];
    if (first && passes(first, code, codes)) {
      systems.push({ ...card, url: first.webAddress as string, roles });
      continue;
    }
    const app = clients
      .filter(
        (c) =>
          c.system === code &&
          c.kind === ClientKind.PUBLIC_NATIVE &&
          passes(c, code, codes),
      )
      .sort(oldestFirst)[0];
    if (app) {
      mobileSystems.push({
        ...card,
        roles,
        app: { clientId: app.id, released: app.appReleased },
      });
    }
  }
  return { systems, mobileSystems, missing, duplicates };
}

/**
 * 403 `NO_SYSTEM_ACCESS` with the caller's own email, so the portal's no access state can say
 * who is signed in (spec 0007, AC-19). Only ever the caller's own address.
 */
export function noSystemAccess(email: string): HttpException {
  const error = coded(
    HttpStatus.FORBIDDEN,
    'NO_SYSTEM_ACCESS',
    'This account has no access to any system',
  );
  return new HttpException(
    { ...(error.getResponse() as object), user: { email } },
    HttpStatus.FORBIDDEN,
  );
}

type ClientReader = Pick<PrismaService, 'oAuthClient'>;

/** The active clients the launcher reads for `systems`: web clients and phone apps. */
export function readLauncherClients(
  db: ClientReader,
  systems: SystemType[],
): Promise<LauncherClientRow[]> {
  return db.oAuthClient.findMany({
    where: {
      system: { in: systems },
      isActive: true,
      OR: [
        { kind: ClientKind.CONFIDENTIAL, webAddress: { not: null } },
        { kind: ClientKind.PUBLIC_NATIVE },
      ],
    },
    select: {
      id: true,
      kind: true,
      system: true,
      webAddress: true,
      allowedRoles: true,
      appReleased: true,
      createdAt: true,
    },
  });
}

/**
 * `user.systems` for a grant answer (suite spec 0014, AC-4): the web openable systems only, so
 * Switch system never offers a phone only system. `held` are the person's live role rows.
 */
export async function webSystemsFor(
  db: ClientReader,
  held: readonly { system: SystemType; role: string }[],
): Promise<SystemType[]> {
  const codes = launcherOrder(held);
  if (codes.length === 0) return [];
  return webSystemCodes(held, await readLauncherClients(db, codes));
}

/** One `user.systemRoles` entry (VRMS spec 0027, step 6a): the live role codes held there. */
export type SystemRolesEntry = { system: SystemType; roles: string[] };

/** What every user grant answer says about the person's systems, beside `user.roles`. */
export type GrantSystems = {
  systems: SystemType[];
  systemRoles: SystemRolesEntry[];
  suiteAdmin: boolean;
};

/**
 * Pure (VRMS spec 0027, step 6a): one entry per system in `systems`, same order, holding the
 * codes held there in catalog order. A held code with no catalog row is left out, as the
 * launcher does; a system left with none keeps its entry with `roles: []`. Not filtered by any
 * client's `allowedRoles`.
 */
export function buildSystemRoles(
  held: readonly { system: SystemType; role: string }[],
  systems: readonly SystemType[],
  catalog: readonly { system: SystemType; code: string; sortOrder: number }[],
): SystemRolesEntry[] {
  const bySystem = heldBySystem(held);
  return systems.map((system) => {
    const codes = bySystem.get(system) ?? [];
    const roles = catalog
      .filter((r) => r.system === system && codes.includes(r.code))
      .sort(byCatalogOrder)
      .map((r) => r.code);
    return { system, roles };
  });
}

type GrantReader = Pick<
  PrismaService,
  'oAuthClient' | 'systemRole' | 'suiteAdmin'
>;

/**
 * `user.systems`, `user.systemRoles` and `user.suiteAdmin` for a grant answer, read fresh in the
 * grant's own transaction from the live rows the grant already read (`held`). Sequential reads,
 * since an interactive transaction runs one query at a time anyway. Never put in a token.
 */
export async function grantSystemsFor(
  db: GrantReader,
  userId: string,
  held: readonly { system: SystemType; role: string }[],
): Promise<GrantSystems> {
  const systems = await webSystemsFor(db, held);
  const codes = [
    ...new Set(
      held.filter((h) => systems.includes(h.system)).map((h) => h.role),
    ),
  ];
  const catalog =
    codes.length === 0
      ? []
      : await db.systemRole.findMany({
          where: { system: { in: systems }, code: { in: codes } },
          select: { system: true, code: true, sortOrder: true },
        });
  const suite = await db.suiteAdmin.findUnique({
    where: { userId },
    select: { userId: true },
  });
  return {
    systems,
    systemRoles: buildSystemRoles(held, systems, catalog),
    suiteAdmin: suite !== null,
  };
}

@Injectable()
export class LauncherService {
  private readonly logger = new Logger('Launcher');

  constructor(private readonly prisma: PrismaService) {}

  /**
   * The launcher body for a live session (`GET /auth/sso`): the person's systems plus the
   * session's cutoffs (suite spec 0016, AC-12a). 403 `NO_SYSTEM_ACCESS` as `systemsFor`.
   */
  async answerFor(
    user: LauncherInput,
    session: LauncherSession,
  ): Promise<LauncherAnswer> {
    return withCutoffs(await this.systemsFor(user), session);
  }

  /**
   * The person's systems, or 403 `NO_SYSTEM_ACCESS` when neither a web nor a phone only
   * system is left (spec 0007, AC-1 to AC-3; suite spec 0014, AC-5). Read only. A login calls
   * this before it creates the session, then adds the cutoffs with `withCutoffs`.
   */
  async systemsFor(user: LauncherInput): Promise<LauncherSystems> {
    const [held, suite] = await Promise.all([
      this.prisma.userRoleAssignment.findMany({
        where: { userId: user.id, ...liveRoleWhere() },
        select: { system: true, role: true },
      }),
      this.prisma.suiteAdmin.findUnique({
        where: { userId: user.id },
        select: { userId: true },
      }),
    ]);
    const suiteAdmin = suite !== null;
    const codes = launcherOrder(held);
    if (codes.length === 0) return noSystems(user, suiteAdmin);

    const [catalog, clients] = await Promise.all([
      this.prisma.system.findMany({
        where: { code: { in: codes } },
        select: {
          code: true,
          name: true,
          description: true,
          roles: { select: { code: true, name: true, sortOrder: true } },
        },
      }),
      readLauncherClients(this.prisma, codes),
    ]);

    const { systems, mobileSystems, missing, duplicates } =
      buildLauncherSystems(held, catalog, clients);
    // AC-2: name the system, never the user's email
    for (const system of missing) {
      this.logger.warn(
        `${system} is left out of the launcher: no active confidential client with a web address. Run npm run seed:clients.`,
      );
    }
    for (const system of duplicates) {
      this.logger.warn(
        `${system} has more than one active confidential client with a web address; the oldest is used.`,
      );
    }
    // Suite spec 0014, AC-5: a phone only person gets 200 with `systems: []`
    if (systems.length === 0 && mobileSystems.length === 0) {
      return noSystems(user, suiteAdmin);
    }
    return { user: launcherUser(user), systems, mobileSystems, suiteAdmin };
  }
}

/**
 * No usable system: 403 `NO_SYSTEM_ACCESS`, except for a suite admin, who may hold no system
 * and gets the empty lists (spec 0013, AC-5).
 */
function noSystems(user: LauncherInput, suiteAdmin: boolean): LauncherSystems {
  if (!suiteAdmin) throw noSystemAccess(user.email);
  return {
    user: launcherUser(user),
    systems: [],
    mobileSystems: [],
    suiteAdmin: true,
  };
}

type LauncherInput = {
  id: string;
  name: string;
  email: string;
  profilePicture: string | null;
};

function launcherUser(user: LauncherInput): LauncherSystems['user'] {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    picture: user.profilePicture,
  };
}
