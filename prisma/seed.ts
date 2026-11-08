import 'dotenv/config';
import { Prisma, PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';

import { hashSeedPasswords, seedUsers } from './seeds/users.seed';
import { seedClients } from './seeds/clients.seed';

const pool = new pg.Pool({
  connectionString: process.env['DATABASE_URL'],
});
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function cleanDatabase(prisma: Prisma.TransactionClient) {
  console.log('Cleaning auth database...');
  await prisma.userChange.deleteMany({});
  await prisma.passwordResetToken.deleteMany({});
  await prisma.refreshToken.deleteMany({});
  await prisma.userRoleAssignment.deleteMany({});
  await prisma.user.deleteMany({});
  console.log('Auth database cleaned successfully!\n');
}

async function main() {
  console.log('Seeding auth database...\n');

  // Spec 0005, AC-3: the clean and every seeded person commit in one transaction, so the
  // directory feed's deferred triggers see each person's final state once: a first run writes
  // one row per person, a rerun that changes nothing visible writes none
  const passwords = await hashSeedPasswords();
  await prisma.$transaction(
    async (tx) => {
      await cleanDatabase(tx);
      await seedUsers(tx, passwords);
    },
    { timeout: 120_000, maxWait: 10_000 },
  );
  // Clients are updated in place, never cleaned (spec 0002, AC-13)
  await seedClients(prisma);

  console.log('Auth database seeded successfully!');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Login credentials:');
  console.log(
    '  BMS Admin  → email: bms.admin@welinc.com  password: admin1234',
  );
  console.log(
    '  VRMS Admin → email: vrms.admin@welinc.com password: admin1234',
  );
  console.log(
    '  VMMS Admin → email: vmms.admin@welinc.com password: admin1234',
  );
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

main()
  .catch((e) => {
    console.error('Auth seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });
