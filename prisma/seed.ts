import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';

import {
  checkManifest,
  loadManifest,
  seedGuard,
  type CatalogView,
} from './seeds/manifest';
import {
  hashSeedPasswords,
  resetUsers,
  SeedConflictError,
  seedPeople,
} from './seeds/users.seed';
import { seedClients } from './seeds/clients.seed';
import { printSeedSummary } from './seeds/summary';

// `npm run seed` (spec 0006): upserts the people in seeds/people.json, then the client
// registry. `npm run seed -- --reset` first removes every user, on a local database only.

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

async function main() {
  // AC-9, AC-10: decided before any connection is opened
  const mode = seedGuard({
    nodeEnv: process.env['NODE_ENV'],
    seedAllow: process.env['SEED_ALLOW'],
    databaseUrl: process.env['DATABASE_URL'],
    reset: process.argv.slice(2).includes('--reset'),
  });
  if (!mode.ok) fail(mode.message);

  let manifest;
  try {
    manifest = loadManifest();
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }

  const pool = new pg.Pool({ connectionString: process.env['DATABASE_URL'] });
  const prisma = new PrismaClient({ adapter: new PrismaPg(pool) });
  try {
    // AC-2: the manifest against itself and the catalog, every problem at once
    const catalog: CatalogView = {
      systems: await prisma.system.findMany({
        select: { code: true, maxRolesPerUser: true },
      }),
      roles: await prisma.systemRole.findMany({
        select: { system: true, code: true, isSystemAdmin: true },
      }),
    };
    if (catalog.roles.length === 0) {
      fail('The role catalog is empty. Run npm run db:deploy first.');
    }
    const problems = checkManifest(manifest, catalog);
    if (problems.length > 0) {
      fail(
        `people.json has ${problems.length} problem(s), nothing was written:\n  ${problems.join('\n  ')}`,
      );
    }

    // AC-10: staging gets no broken state accounts
    const people = mode.staging
      ? manifest.people.filter((p) => p.group !== 'state')
      : manifest.people;

    console.log(
      mode.reset
        ? 'Resetting every user, then seeding people...'
        : 'Seeding people...',
    );
    const hashes = await hashSeedPasswords(manifest);
    const now = new Date();
    // Spec 0005, AC-3: one transaction, so the directory feed sees one change per person
    await prisma.$transaction(
      async (tx) => {
        if (mode.reset) await resetUsers(tx);
        await seedPeople(tx, people, hashes, now);
      },
      { timeout: 120_000, maxWait: 10_000 },
    );
    console.log(`  ${people.length} seed people applied.\n`);

    // AC-11: clients are updated in place, never cleaned (spec 0002, AC-13)
    await seedClients(prisma);

    printSeedSummary(people, manifest, mode.staging);
  } catch (e) {
    if (e instanceof SeedConflictError) fail(e.message);
    throw e;
  } finally {
    await prisma.$disconnect();
    await pool.end();
  }
}

main().catch((e) => {
  console.error('Auth seed failed:', e);
  process.exit(1);
});
