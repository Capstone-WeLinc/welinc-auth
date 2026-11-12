// `npm run permissions:import -- <SYSTEM> <file>` (suite spec 0013, AC-28): the one time move of a
// system's matrix and history into welinc-auth, from backend-vrms's `permissions:export` file.
// One transaction: it sets the cells, carries the history (imported, original times) and bumps
// the version, or refuses and writes nothing. Run catalog:sync first.
import 'dotenv/config';
import { readFileSync } from 'fs';
import { Prisma, PrismaClient, SystemType } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { CATALOG_SYNC_LOCK_KEY } from '../src/auth/roles/catalog-plan';
import { CATALOG_SYNC_ACTOR } from '../src/auth/roles/permission-plan';
import {
  fileProblems,
  planImport,
  type ImportPlan,
  type PermissionsExport,
} from '../src/auth/permissions/import-plan';

class Refused extends Error {}

const [rawSystem, file] = process.argv.slice(2);
const pool = new pg.Pool({ connectionString: process.env['DATABASE_URL'] });
const prisma = new PrismaClient({ adapter: new PrismaPg(pool) });

async function main(): Promise<number> {
  const system = (Object.values(SystemType) as string[]).includes(rawSystem ?? '')
    ? (rawSystem as SystemType)
    : null;
  if (!system || !file) {
    console.error('Usage: npm run permissions:import -- <VRMS|VMMS|BMS> <file>');
    return 1;
  }
  const data: unknown = JSON.parse(readFileSync(file, 'utf8'));
  const problems = fileProblems(data, system);
  if (problems.length > 0) {
    console.error('Import refused, nothing was written:');
    for (const p of problems) console.error(`  - ${p}`);
    return 1;
  }
  const exported = data as PermissionsExport;

  let plan: ImportPlan | undefined;
  let refusal = '';
  try {
    await prisma.$transaction(
      async (tx) => {
        // Never beside a catalog sync, and one import at a time
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(${CATALOG_SYNC_LOCK_KEY}::bigint)`;
        const matrix = await tx.$queryRaw<{ version: number }[]>(
          Prisma.sql`SELECT "version" FROM "permission_matrices" WHERE "system" = ${system}::"SystemType" FOR UPDATE`,
        );
        if (matrix.length === 0) {
          refusal = `${system} has no matrix yet. Run npm run catalog:sync first.`;
          throw new Refused();
        }
        // AC-28: only onto a matrix nobody has edited here yet (the sync's own rows don't count)
        const edits = await tx.permissionChange.count({
          where: {
            system,
            imported: false,
            OR: [{ actorName: null }, { actorName: { not: CATALOG_SYNC_ACTOR } }],
          },
        });
        if (edits > 0) {
          refusal = `${system}'s matrix already has ${edits} changes made in welinc-auth, so an import would overwrite them.`;
          throw new Refused();
        }
        const already = await tx.permissionChange.count({ where: { system, imported: true } });
        if (already > 0) {
          refusal = `${system}'s history was imported already (${already} rows).`;
          throw new Refused();
        }

        const actorIds = [
          ...new Set(exported.changes.flatMap((c) => (c.actorId ? [c.actorId] : []))),
        ];
        const [roles, permissions, cells, users] = await Promise.all([
          tx.systemRole.findMany({ where: { system }, select: { code: true } }),
          tx.systemPermission.findMany({ where: { system }, select: { key: true, lockedRoles: true } }),
          tx.rolePermission.findMany({ where: { system }, select: { role: true, key: true, allowed: true } }),
          tx.user.findMany({ where: { id: { in: actorIds } }, select: { id: true } }),
        ]);
        plan = planImport(exported, {
          roles: roles.map((r) => r.code),
          permissions: permissions.map((p) => ({ key: p.key, lockedRoles: p.lockedRoles ?? [] })),
          cells,
          userIds: new Set(users.map((u) => u.id)),
        });

        for (const cell of plan.sets) {
          await tx.rolePermission.update({
            where: { system_role_key: { system, role: cell.role, key: cell.key } },
            data: { allowed: cell.allowed, updatedById: null },
          });
        }
        if (plan.history.length > 0) {
          await tx.permissionChange.createMany({
            data: plan.history.map((h) => ({ system, ...h, imported: true })),
          });
        }
        await tx.$executeRaw(
          Prisma.sql`UPDATE "permission_matrices" SET "version" = "version" + 1, "updated_at" = now() WHERE "system" = ${system}::"SystemType"`,
        );
      },
      { timeout: 60_000 },
    );
  } catch (error) {
    if (!(error instanceof Refused)) throw error;
    console.error(`Import refused, nothing was written: ${refusal}`);
    return 1;
  }

  if (!plan) throw new Error('The import made no plan');
  console.log(
    `${system}: ${plan.sets.length} cells changed, ${plan.history.length} history rows imported, version raised.`,
  );
  if (plan.skipped.length > 0) {
    console.log(`Skipped ${plan.skipped.length} cells:`);
    for (const s of plan.skipped) console.log(`  - ${s}`);
  }
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((e: unknown) => {
    console.error('Import failed:', e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });
