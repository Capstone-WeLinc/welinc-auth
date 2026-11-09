import { HttpException, HttpStatus, Injectable, Logger } from '@nestjs/common';
import { ClientKind, SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';

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

/** The `/auth/sso` and `/auth/login` body (spec 0007, AC-1, AC-3). */
export type LauncherAnswer = {
  user: { id: string; name: string; email: string; picture: string | null };
  systems: LauncherSystem[];
};

type ClientRow = {
  system: SystemType | null;
  webAddress: string | null;
  createdAt: Date;
};

type CatalogRow = {
  code: SystemType;
  name: string;
  description: string;
  roles: { code: string; name: string; sortOrder: number }[];
};

/**
 * Pure: the launcher cards from the user's role rows, the catalog and the active confidential
 * clients. A held system with no usable client is left out and named in `missing` (AC-2).
 */
export function buildLauncherSystems(
  held: readonly { system: SystemType; role: string }[],
  catalog: readonly CatalogRow[],
  clients: readonly ClientRow[],
): {
  systems: LauncherSystem[];
  missing: SystemType[];
  duplicates: SystemType[];
} {
  const systems: LauncherSystem[] = [];
  const missing: SystemType[] = [];
  const duplicates: SystemType[] = [];
  for (const code of launcherOrder(held)) {
    const usable = clients
      .filter((c) => c.system === code && c.webAddress)
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
    const entry = catalog.find((c) => c.code === code);
    if (usable.length === 0 || !entry) {
      missing.push(code);
      continue;
    }
    if (usable.length > 1) duplicates.push(code);
    const codes = new Set(
      held.filter((h) => h.system === code).map((h) => h.role),
    );
    const roles = entry.roles
      .filter((r) => codes.has(r.code))
      .sort((a, b) => a.sortOrder - b.sortOrder || a.code.localeCompare(b.code))
      .map((r) => ({ code: r.code, name: r.name }));
    systems.push({
      system: code,
      name: entry.name,
      description: entry.description,
      url: usable[0].webAddress as string,
      roles,
    });
  }
  return { systems, missing, duplicates };
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

@Injectable()
export class LauncherService {
  private readonly logger = new Logger('Launcher');

  constructor(private readonly prisma: PrismaService) {}

  /**
   * The launcher body for a user, or 403 `NO_SYSTEM_ACCESS` when no usable system is left
   * (AC-1 to AC-3). Read only: never touches the session.
   */
  async answerFor(user: {
    id: string;
    name: string;
    email: string;
    profilePicture: string | null;
  }): Promise<LauncherAnswer> {
    const held = await this.prisma.userRoleAssignment.findMany({
      where: { userId: user.id },
      select: { system: true, role: true },
    });
    const codes = launcherOrder(held);
    if (codes.length === 0) throw noSystemAccess(user.email);

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
      this.prisma.oAuthClient.findMany({
        where: {
          system: { in: codes },
          kind: ClientKind.CONFIDENTIAL,
          isActive: true,
          webAddress: { not: null },
        },
        select: { system: true, webAddress: true, createdAt: true },
      }),
    ]);

    const { systems, missing, duplicates } = buildLauncherSystems(
      held,
      catalog,
      clients,
    );
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
    if (systems.length === 0) throw noSystemAccess(user.email);
    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        picture: user.profilePicture,
      },
      systems,
    };
  }
}
