import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { Prisma, RoleEventKind, type SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { liveRoleWhere } from './live-roles';
import {
  CUSTOM_ROLE_LIMIT,
  DESCRIPTION_LENGTH_MESSAGE,
  ROLE_DESCRIPTION_MAX,
  codeBody,
  createdFromNote,
  customRoleLimitMessage,
  nameProblem,
  nameTakenMessage,
  pickRoleCode,
} from './custom-role-rules';
import { RolesAdminService, type RoleSummary } from './roles-admin.service';

// Suite spec 0018 child 0002 (AC-22, AC-23, AC-24, AC-25, AC-27): suite admins make, rename,
// describe and delete custom roles. The runtime owns custom rows; catalog:sync owns built in rows
// and never touches these (AC-30). Every write that adds or removes cells logs each cell to
// permission_changes and raises permission_matrices.version in the same transaction.

export type RoleActor = { id: string; name: string; email: string };

export type CreatedRole = {
  role: RoleSummary;
  /** The new role's allowed keys, in catalog order. */
  cells: string[];
  /** The matrix version after the create: the page's next save sends it. */
  version: number;
};

type Tx = Prisma.TransactionClient;

const bad = (code: string, message: string) =>
  coded(HttpStatus.BAD_REQUEST, code, message);
const conflict = (code: string, message: string) =>
  coded(HttpStatus.CONFLICT, code, message);
const noSuchRole = () =>
  coded(HttpStatus.NOT_FOUND, 'NOT_FOUND', 'No such role');
const builtInRole = () =>
  bad(
    'BUILT_IN_ROLE',
    "Built in roles can't be renamed, described or deleted.",
  );

function isUniqueViolation(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === 'P2002'
  );
}

function actorColumns(actor: RoleActor) {
  return {
    actorId: actor.id,
    actorName: actor.name.slice(0, 100),
    actorEmail: actor.email,
  };
}

/** The trimmed name, or 400 `VALIDATION_FAILED` with the AC-22 message. */
function cleanName(raw: string): string {
  const name = raw.trim();
  const problem = nameProblem(name);
  if (problem) throw bad('VALIDATION_FAILED', problem);
  return name;
}

function cleanDescription(raw: string | undefined): string {
  const description = (raw ?? '').trim();
  if (description.length > ROLE_DESCRIPTION_MAX) {
    throw bad('VALIDATION_FAILED', DESCRIPTION_LENGTH_MESSAGE);
  }
  return description;
}

@Injectable()
export class CustomRolesService {
  private readonly logger = new Logger(CustomRolesService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly roles: RolesAdminService,
  ) {}

  /** `POST /auth/admin/roles/:system` (AC-20 to AC-23, AC-27). */
  async create(
    actor: RoleActor,
    system: SystemType,
    input: { name: string; description?: string; from: string },
  ): Promise<CreatedRole> {
    let result: { code: string; version: number };
    try {
      result = await this.prisma.$transaction(async (tx) => {
        // One create per system at a time: the limit and the code pick can't race
        await this.lockSystem(tx, system);
        const permissions = await tx.systemPermission.findMany({
          where: { system },
          select: { key: true },
          orderBy: { sortOrder: 'asc' },
        });
        // AC-27: only a system that uses WeLinc permissions can have custom roles
        if (permissions.length === 0) {
          throw conflict(
            'CUSTOM_ROLES_NOT_SUPPORTED',
            `${system} doesn't use WeLinc permissions, so it keeps its built in roles.`,
          );
        }
        const name = cleanName(input.name);
        const description = cleanDescription(input.description);

        // The source is live and stays so; the matrix lock keeps its cells still while we copy
        const [source] = await tx.$queryRaw<{ code: string; name: string }[]>(
          Prisma.sql`SELECT "code", "name" FROM "system_roles"
            WHERE "system" = ${system}::"SystemType" AND "code" = ${input.from}
              AND "deleted_at" IS NULL
            FOR UPDATE`,
        );
        if (!source) {
          throw bad('UNKNOWN_ROLE', `${system} has no role ${input.from}`);
        }
        await this.lockMatrix(tx, system);

        const all = await tx.systemRole.findMany({
          where: { system },
          select: {
            code: true,
            name: true,
            isBuiltIn: true,
            deletedAt: true,
          },
        });
        const live = all.filter((r) => r.deletedAt === null);
        if (live.filter((r) => !r.isBuiltIn).length >= CUSTOM_ROLE_LIMIT) {
          throw conflict('CUSTOM_ROLE_LIMIT', customRoleLimitMessage(system));
        }
        this.assertNameFree(live, name, system);

        // AC-22 and the umbrella code rule: never reuse a code the system ever had
        const code = pickRoleCode(
          codeBody(name),
          new Set(all.map((r) => r.code)),
        );
        if (code === null) {
          throw bad(
            'VALIDATION_FAILED',
            'Too many roles have had a name like this one. Pick a different name.',
          );
        }

        await tx.systemRole.create({
          data: {
            system,
            code,
            name,
            description,
            // Custom roles sort by name after the built in ones; this only keeps the column filled
            sortOrder: 1000,
            isSystemAdmin: false,
            isBuiltIn: false,
            copiedFrom: source.code,
            createdById: actor.id,
          },
        });

        // AC-23: the source's saved cells, never a draft; a key with no row is off
        const saved = await tx.rolePermission.findMany({
          where: { system, role: source.code },
          select: { key: true, allowed: true },
        });
        const savedAt = new Map(saved.map((c) => [c.key, c.allowed]));
        const cells = permissions.map((p) => ({
          key: p.key,
          allowed: savedAt.get(p.key) ?? false,
        }));
        await tx.rolePermission.createMany({
          data: cells.map((c) => ({
            system,
            role: code,
            key: c.key,
            allowed: c.allowed,
            updatedById: actor.id,
          })),
        });
        const note = createdFromNote(source.name);
        await tx.permissionChange.createMany({
          data: cells.map((c) => ({
            system,
            role: code,
            key: c.key,
            before: null,
            after: c.allowed,
            ...actorColumns(actor),
            note,
          })),
        });
        await tx.roleEvent.create({
          data: {
            system,
            role: code,
            kind: RoleEventKind.CREATED,
            fromValue: source.name,
            toValue: name,
            ...actorColumns(actor),
          },
        });
        const version = await this.raiseVersion(tx, system);
        return { code, version };
      });
    } catch (error) {
      // The partial unique index on live custom names, should a check above ever miss
      if (isUniqueViolation(error)) {
        throw conflict(
          'ROLE_NAME_TAKEN',
          nameTakenMessage(input.name.trim(), system),
        );
      }
      throw error;
    }

    this.logger.log(
      `custom role created system=${system} role=${result.code} from=${input.from} actor=${actor.id}`,
    );
    const page = await this.roles.page(system, true);
    const role = page.roles.find((r) => r.code === result.code);
    if (!role) throw noSuchRole();
    return {
      role,
      cells: page.cells[result.code] ?? [],
      version: result.version,
    };
  }

  /** `PATCH /auth/admin/roles/:system/:code` (AC-24, AC-26). */
  async update(
    actor: RoleActor,
    system: SystemType,
    code: string,
    input: { name?: string; description?: string },
  ): Promise<RoleSummary> {
    if (input.name === undefined && input.description === undefined) {
      throw bad('VALIDATION_FAILED', 'Send a name or a description');
    }
    try {
      await this.prisma.$transaction(async (tx) => {
        await this.lockSystem(tx, system);
        const role = await this.lockRole(tx, system, code);
        if (role.is_built_in) throw builtInRole();

        const events: Prisma.RoleEventCreateManyInput[] = [];
        const data: Prisma.SystemRoleUpdateInput = {};
        if (input.name !== undefined) {
          const name = cleanName(input.name);
          if (name !== role.name) {
            const live = await tx.systemRole.findMany({
              where: { system, deletedAt: null, NOT: { code } },
              select: { name: true },
            });
            this.assertNameFree(live, name, system);
            data.name = name;
            events.push({
              system,
              role: code,
              kind: RoleEventKind.RENAMED,
              fromValue: role.name,
              toValue: name,
              ...actorColumns(actor),
            });
          }
        }
        if (input.description !== undefined) {
          const description = cleanDescription(input.description);
          if (description !== role.description) {
            data.description = description;
            events.push({
              system,
              role: code,
              kind: RoleEventKind.DESCRIBED,
              fromValue: role.description || null,
              toValue: description || null,
              ...actorColumns(actor),
            });
          }
        }
        if (events.length === 0) return;
        // The code never changes, so tokens, grants and VRMS's rows stay as they are
        await tx.systemRole.update({
          where: { system_code: { system, code } },
          data,
        });
        await tx.roleEvent.createMany({ data: events });
      });
    } catch (error) {
      if (isUniqueViolation(error) && input.name !== undefined) {
        throw conflict(
          'ROLE_NAME_TAKEN',
          nameTakenMessage(input.name.trim(), system),
        );
      }
      throw error;
    }

    const page = await this.roles.page(system, true);
    const role = page.roles.find((r) => r.code === code);
    if (!role) throw noSuchRole();
    return role;
  }

  /**
   * `DELETE /auth/admin/roles/:system/:code` (AC-25): archives a custom role nobody holds.
   * Holders are people who aren't soft deleted (deactivated people count) and live temporary
   * grants; people in their deletion grace period and temporary rows past their end don't block.
   */
  async remove(
    actor: RoleActor,
    system: SystemType,
    code: string,
  ): Promise<{ version: number }> {
    const version = await this.prisma.$transaction(async (tx) => {
      // The same row lock every assignment path takes, so a move and a Delete never interleave
      const role = await this.lockRole(tx, system, code);
      if (role.is_built_in) throw builtInRole();

      const holders = await tx.userRoleAssignment.count({
        where: {
          system,
          role: code,
          user: { deletedAt: null },
          ...liveRoleWhere(),
        },
      });
      if (holders > 0) {
        throw coded(
          HttpStatus.CONFLICT,
          'ROLE_IN_USE',
          `${holders === 1 ? '1 person still has' : `${holders} people still have`} ${role.name}. Give them another role first.`,
          { count: holders },
        );
      }

      await this.lockMatrix(tx, system);
      const cells = await tx.rolePermission.findMany({
        where: { system, role: code },
        select: { key: true, allowed: true },
      });
      await tx.rolePermission.deleteMany({ where: { system, role: code } });
      if (cells.length > 0) {
        await tx.permissionChange.createMany({
          data: cells.map((c) => ({
            system,
            role: code,
            key: c.key,
            before: c.allowed,
            after: null,
            ...actorColumns(actor),
          })),
        });
      }
      await tx.roleEvent.create({
        data: {
          system,
          role: code,
          kind: RoleEventKind.DELETED,
          fromValue: role.name,
          ...actorColumns(actor),
        },
      });
      await tx.systemRole.update({
        where: { system_code: { system, code } },
        data: { deletedAt: new Date() },
      });
      return this.raiseVersion(tx, system);
    });

    this.logger.log(
      `custom role deleted system=${system} role=${code} actor=${actor.id}`,
    );
    return { version };
  }

  /** 409 `ROLE_NAME_TAKEN` when a live role (built in or custom) has the name, ignoring case. */
  private assertNameFree(
    live: { name: string }[],
    name: string,
    system: SystemType,
  ): void {
    const wanted = name.toLowerCase();
    if (live.some((r) => r.name.toLowerCase() === wanted)) {
      throw conflict('ROLE_NAME_TAKEN', nameTakenMessage(name, system));
    }
  }

  /** 404 for an unknown system (the catalog was never synced for it). */
  private async lockSystem(tx: Tx, system: SystemType): Promise<void> {
    const rows = await tx.$queryRaw<{ code: string }[]>(
      Prisma.sql`SELECT "code" FROM "systems" WHERE "code" = ${system}::"SystemType" FOR UPDATE`,
    );
    if (rows.length === 0) {
      throw coded(HttpStatus.NOT_FOUND, 'NOT_FOUND', 'No such system');
    }
  }

  /** The live role row, locked; 404 when it never existed or is archived. */
  private async lockRole(
    tx: Tx,
    system: SystemType,
    code: string,
  ): Promise<{ name: string; description: string; is_built_in: boolean }> {
    const [row] = await tx.$queryRaw<
      { name: string; description: string; is_built_in: boolean }[]
    >(
      Prisma.sql`SELECT "name", "description", "is_built_in" FROM "system_roles"
        WHERE "system" = ${system}::"SystemType" AND "code" = ${code}
          AND "deleted_at" IS NULL
        FOR UPDATE`,
    );
    if (!row) throw noSuchRole();
    return row;
  }

  /** The matrix PATCH takes the same lock, so a save and a copy never see half of each other. */
  private async lockMatrix(tx: Tx, system: SystemType): Promise<void> {
    await tx.$queryRaw(
      Prisma.sql`SELECT "version" FROM "permission_matrices" WHERE "system" = ${system}::"SystemType" FOR UPDATE`,
    );
  }

  private async raiseVersion(tx: Tx, system: SystemType): Promise<number> {
    const [row] = await tx.$queryRaw<{ version: number }[]>(
      Prisma.sql`INSERT INTO "permission_matrices" ("system", "version", "updated_at")
        VALUES (${system}::"SystemType", 2, now())
        ON CONFLICT ("system") DO UPDATE
          SET "version" = "permission_matrices"."version" + 1, "updated_at" = now()
        RETURNING "version"`,
    );
    return row.version;
  }
}
