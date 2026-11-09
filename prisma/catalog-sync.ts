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

class Refused extends Error {}
class DryRun extends Error {}

const dryRun = process.argv.includes('--dry-run');
const pool = new pg.Pool({ connectionString: process.env['DATABASE_URL'] });
const prisma = new PrismaClient({ adapter: new PrismaPg(pool) });

async function main(): Promise<CatalogPlan> {
  let plan: CatalogPlan | undefined;
  try {
    await prisma.$transaction(
      async (tx) => {
        // One sync at a time, and no role granted between the "still held" check and the delete
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(${CATALOG_SYNC_LOCK_KEY}::bigint)`;
        await tx.$executeRaw`LOCK TABLE "user_roles" IN SHARE ROW EXCLUSIVE MODE`;

        const [systems, roles, holdings] = await Promise.all([
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
        if (plan.errors.length > 0) throw new Refused();
        if (dryRun) throw new DryRun();

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
    if (plan.errors.length > 0) {
      console.error('\nCatalog sync refused, nothing was written:');
      for (const e of plan.errors) console.error(`  - ${e}`);
      process.exitCode = 1;
    } else if (dryRun && plan.systems.some(hasChanges)) {
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
