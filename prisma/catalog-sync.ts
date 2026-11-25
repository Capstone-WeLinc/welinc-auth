// `npm run catalog:sync [-- --dry-run]` (spec 0004, AC-2, AC-3): makes `systems` and
// `system_roles` match prisma/catalog/*.ts in one transaction, or refuses and writes nothing.
// `npm run db:deploy` runs it right after `prisma migrate deploy` (AC-5).
import 'dotenv/config';
import { PrismaClient, SystemType } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { CATALOG } from './catalog';
import {
  CATALOG_SYNC_LOCK_KEY,
  describePlan,
  hasChanges,
  planCatalogSync,
  type CatalogPlan,
} from '../src/auth/roles/catalog-plan';
import {
  CATALOG_SYNC_ACTOR,
  describePermissionPlan,
  permissionFileErrors,
  planPermissionSync,
  type PermissionPlan,
} from '../src/auth/roles/permission-plan';

class Refused extends Error {}
class DryRun extends Error {}

const dryRun = process.argv.includes('--dry-run');
const pool = new pg.Pool({ connectionString: process.env['DATABASE_URL'] });
const prisma = new PrismaClient({ adapter: new PrismaPg(pool) });

let permissionPlans: PermissionPlan[] = [];

async function main(): Promise<CatalogPlan> {
  let plan: CatalogPlan | undefined;
  try {
    await prisma.$transaction(
      async (tx) => {
        // One sync at a time, and no role granted between the "still held" check and the delete
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(${CATALOG_SYNC_LOCK_KEY}::bigint)`;
        await tx.$executeRaw`LOCK TABLE "user_roles" IN SHARE ROW EXCLUSIVE MODE`;

        const [systems, roles, holdings, permissions, cells] = await Promise.all([
          tx.system.findMany({
            select: {
              code: true,
              name: true,
              description: true,
              maxRolesPerUser: true,
            },
          }),
          tx.systemRole.findMany({
            select: {
              system: true,
              code: true,
              name: true,
              description: true,
              sortOrder: true,
              isSystemAdmin: true,
            },
          }),
          tx.userRoleAssignment.findMany({
            select: {
              userId: true,
              system: true,
              role: true,
              user: { select: { email: true, isActive: true, deletedAt: true } },
            },
          }),
          tx.systemPermission.findMany({
            select: {
              system: true,
              key: true,
              label: true,
              group: true,
              description: true,
              sortOrder: true,
              lockedRoles: true,
              defaultRoles: true,
            },
          }),
          tx.rolePermission.findMany({
            select: { system: true, role: true, key: true, allowed: true },
          }),
        ]);

        plan = planCatalogSync(
          CATALOG,
          Object.values(SystemType),
          { systems, roles },
          holdings.map((h) => ({
            userId: h.userId,
            email: h.user.email,
            system: h.system,
            role: h.role,
            active: h.user.isActive && h.user.deletedAt === null,
          })),
        );
        // Spec 0013, AC-25: the permission matrix, refused together with the roles
        for (const definition of CATALOG) {
          plan.errors.push(...permissionFileErrors(definition));
        }
        if (plan.errors.length === 0) {
          permissionPlans = CATALOG.map((definition) =>
            planPermissionSync(definition, {
              permissions: permissions.map((p) => ({
                ...p,
                lockedRoles: p.lockedRoles ?? [],
                defaultRoles: p.defaultRoles ?? [],
              })),
              cells,
            }),
          );
        }
        if (plan.errors.length > 0) throw new Refused();
        if (dryRun) throw new DryRun();

        // Cells of keys or roles that leave go first, logged, before the cascade could hide them
        for (const p of permissionPlans) {
          if (p.changes.some((c) => c.after === null)) {
            await tx.permissionChange.createMany({
              data: p.changes
                .filter((c) => c.after === null)
                .map((c) => ({ system: p.system, ...c, actorName: CATALOG_SYNC_ACTOR })),
            });
          }
          for (const cell of p.cellDeletes) {
            await tx.rolePermission.delete({
              where: { system_role_key: { system: p.system, ...cell } },
            });
          }
          if (p.deletes.length > 0) {
            await tx.systemPermission.deleteMany({
              where: { system: p.system, key: { in: p.deletes } },
            });
          }
        }

        for (const s of plan.systems) {
          if (s.systemRow) {
            await tx.system.upsert({
              where: { code: s.system },
              create: s.systemRow,
              update: {
                name: s.systemRow.name,
                description: s.systemRow.description,
                maxRolesPerUser: s.systemRow.maxRolesPerUser,
              },
            });
          }
          if (s.deletes.length > 0) {
            await tx.systemRole.deleteMany({
              where: { system: s.system, code: { in: s.deletes } },
            });
          }
          for (const row of s.updates) {
            await tx.systemRole.update({
              where: { system_code: { system: s.system, code: row.code } },
              data: {
                name: row.name,
                description: row.description,
                sortOrder: row.sortOrder,
                isSystemAdmin: row.isSystemAdmin,
              },
            });
          }
          if (s.inserts.length > 0) {
            await tx.systemRole.createMany({
              data: s.inserts.map((row) => ({ system: s.system, ...row })),
            });
          }
        }

        for (const p of permissionPlans) {
          for (const row of p.upserts) {
            await tx.systemPermission.upsert({
              where: { system_key: { system: p.system, key: row.key } },
              create: { system: p.system, ...row },
              update: row,
            });
          }
          if (p.cellInserts.length > 0) {
            await tx.rolePermission.createMany({
              data: p.cellInserts.map((cell) => ({ system: p.system, ...cell })),
            });
          }
          for (const cell of p.cellResets) {
            await tx.rolePermission.update({
              where: { system_role_key: { system: p.system, role: cell.role, key: cell.key } },
              data: { allowed: cell.allowed, updatedById: null },
            });
          }
          const resets = p.changes.filter((c) => c.after !== null);
          if (resets.length > 0) {
            await tx.permissionChange.createMany({
              data: resets.map((c) => ({ system: p.system, ...c, actorName: CATALOG_SYNC_ACTOR })),
            });
          }
          // Every system gets its matrix row, so GET /auth/permissions/:system has a version
          await tx.permissionMatrix.upsert({
            where: { system: p.system },
            create: { system: p.system },
            update: p.bump ? { version: { increment: 1 } } : {},
          });
        }
      },
      { timeout: 30_000 },
    );
  } catch (error) {
    if (!(error instanceof Refused) && !(error instanceof DryRun)) throw error;
  }
  if (!plan) throw new Error('The sync made no plan');
  return plan;
}

main()
  .then((plan) => {
    for (const s of plan.systems) console.log(describePlan(s));
    for (const p of permissionPlans) console.log(describePermissionPlan(p));
    if (plan.errors.length > 0) {
      console.error('\nCatalog sync refused, nothing was written:');
      for (const e of plan.errors) console.error(`  - ${e}`);
      process.exitCode = 1;
    } else if (dryRun && (plan.systems.some(hasChanges) || permissionPlans.some((p) => p.bump))) {
      console.log('\nDry run: nothing was written.');
    }
  })
  .catch((e: unknown) => {
    console.error('Catalog sync failed:', e instanceof Error ? e.message : e);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });
