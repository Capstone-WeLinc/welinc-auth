import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';

import { seedUsers } from './seeds/users.seed';

const pool = new pg.Pool({
  connectionString: process.env['DATABASE_URL'],
});
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function cleanDatabase(prisma: PrismaClient) {
  console.log('Cleaning auth database...');
  await prisma.passwordResetToken.deleteMany({});
  await prisma.refreshToken.deleteMany({});
  await prisma.userRoleAssignment.deleteMany({});
  await prisma.user.deleteMany({});
  console.log('Auth database cleaned successfully!\n');
}

async function main() {
  console.log('Seeding auth database...\n');

  await cleanDatabase(prisma);
  await seedUsers(prisma);

  console.log('Auth database seeded successfully!');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('Login credentials:');
  console.log('  BMS Admin  → email: bms.admin@welinc.com  password: admin1234');
  console.log('  VRMS Admin → email: vrms.admin@welinc.com password: admin1234');
  console.log('  VMMS Admin → email: vmms.admin@welinc.com password: admin1234');
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
