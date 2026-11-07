// `npm run seed:clients`: creates or updates the client registry only (spec 0002, AC-13).
// Unlike `npm run seed`, it never touches users, so it is safe after `keys:dev` or a new client key.
import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { seedClients } from './seeds/clients.seed';

const pool = new pg.Pool({ connectionString: process.env['DATABASE_URL'] });
const prisma = new PrismaClient({ adapter: new PrismaPg(pool) });

seedClients(prisma)
  .catch((e: unknown) => {
    console.error('Client seed failed:', e instanceof Error ? e.message : e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
    await pool.end();
  });
