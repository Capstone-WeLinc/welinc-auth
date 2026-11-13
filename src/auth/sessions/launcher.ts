import { liveRoleWhere } from '../roles/live-roles';
import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { ClientKind, SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { allowedCodes } from '../roles/allowed-roles';

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

/** The `/auth/sso` and `/auth/login` body (spec 0007, AC-1, AC-3; suite spec 0014, AC-4). */
export type LauncherAnswer = {
  user: { id: string; name: string; email: string; picture: string | null };
  systems: LauncherSystem[];
  mobileSystems: LauncherMobileSystem[];
};

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
      .sort((a, b) => a.sortOrder - b.sortOrder || a.code.localeCompare(b.code))
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

@Injectable()
export class LauncherService {
  private readonly logger = new Logger('Launcher');

  constructor(private readonly prisma: PrismaService) {}

  /**
   * The launcher body for a user, or 403 `NO_SYSTEM_ACCESS` when neither a web nor a phone only
   * system is left (spec 0007, AC-1 to AC-3; suite spec 0014, AC-5). Read only.
   */
  async answerFor(user: LauncherInput): Promise<LauncherAnswer> {
    const held = await this.prisma.userRoleAssignment.findMany({
      where: { userId: user.id, ...liveRoleWhere() },
      select: { system: true, role: true },
    });
    const codes = launcherOrder(held);
    if (codes.length === 0) return this.noSystems(user, []);

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
      return this.noSystems(user, []);
    }
    return { user: launcherUser(user), systems, mobileSystems };
  }

  /**
   * No usable system: 403 `NO_SYSTEM_ACCESS`, except for a suite admin, who holds no system by
   * design and gets the empty lists (spec 0013, AC-5).
   */
  private async noSystems(
    user: LauncherInput,
    mobileSystems: LauncherMobileSystem[],
  ): Promise<LauncherAnswer> {
    const suite = await this.prisma.suiteAdmin.findUnique({
      where: { userId: user.id },
      select: { userId: true },
    });
    if (!suite) throw noSystemAccess(user.email);
    return { user: launcherUser(user), systems: [], mobileSystems };
  }
}

type LauncherInput = {
  id: string;
  name: string;
  email: string;
  profilePicture: string | null;
};

function launcherUser(user: LauncherInput): LauncherAnswer['user'] {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    picture: user.profilePicture,
  };
}
