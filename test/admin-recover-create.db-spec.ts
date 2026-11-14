import { afterAll, beforeAll, describe, expect, it, jest } from '@jest/globals';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg, { Client } from 'pg';
import {
  AdminRecoveryService,
  RecoveryRefused,
} from '../src/auth/admin/admin-recovery.service';
import { AccountEventsService } from '../src/auth/events/account-events.service';
import { noGeo } from '../src/auth/testing/geo.fake';
import type { PrismaService } from '../src/shared/prisma.service';

// Suite spec 0013, AC-12b (from VRMS spec 0008, AC-15): `admin:recover --create` against a real
// database, the first suite admin of a hosted production that starts with nobody in it. It makes
// a throwaway database on the server DATABASE_URL points at and applies every migration. Run it
// with `npm run test:db` (locally: `docker exec welinc_auth_service npm run test:db`).

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const serverUrl = process.env.DATABASE_URL;
const dbName = `welinc_auth_recovertest_${randomBytes(4).toString('hex')}`;

function urlFor(database: string): string {
  const url = new URL(serverUrl!);
  url.pathname = `/${database}`;
  url.search = '';
  return url.toString();
}

const REASON = 'Production bootstrap';
const where = { host: 'job-host', osUser: 'node' };

(serverUrl ? describe : describe.skip)(
  'spec 0013 AC-12b admin:recover --create on a database',
  () => {
    let admin: Client;
    let pool: pg.Pool;
    let prisma: PrismaClient;
    let service: AdminRecoveryService;
    const sendSetupCode = jest.fn(() => Promise.resolve(true));

    beforeAll(async () => {
      admin = new Client({ connectionString: urlFor('postgres') });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${dbName}"`);
      pool = new pg.Pool({ connectionString: urlFor(dbName) });
      for (const folder of folders) {
        await pool.query(
          readFileSync(join(MIGRATIONS, folder, 'migration.sql'), 'utf8'),
        );
      }
      prisma = new PrismaClient({ adapter: new PrismaPg(pool) });
      const db = prisma as unknown as PrismaService;
      service = new AdminRecoveryService(
        db,
        {} as never, // sessions: create ends none
        new AccountEventsService(db, noGeo),
        {} as never, // alerts: create sends none
        { sendSetupCode } as never,
        { get: () => 'test' } as never,
      );
    });

    afterAll(async () => {
      await prisma?.$disconnect();
      await pool?.end();
      await admin?.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
      await admin?.end();
    });

    const create = (email: string, name = 'First Admin', reason = REASON) =>
      service.create({ email, name, reason, ...where });

    it('refuses a short reason, a blank name and a bad domain, writing nothing', async () => {
      await expect(create('a@welinc.com', 'A', 'short')).rejects.toThrow(
        RecoveryRefused,
      );
      await expect(create('a@welinc.com', '   ')).rejects.toThrow(
        RecoveryRefused,
      );
      await expect(create('a@no-such-domain.invalid')).rejects.toThrow(
        RecoveryRefused,
      );
      expect(await prisma.user.count()).toBe(0);
      expect(sendSetupCode).not.toHaveBeenCalled();
    });

    it('makes the first suite admin with no roles, no password and the two events', async () => {
      const made = await create('  First.Admin@Welinc.com ');
      expect(made.email).toBe('first.admin@welinc.com');
      expect(made.setupEmailSent).toBe(true);

      const user = await prisma.user.findUniqueOrThrow({
        where: { id: made.userId },
        include: { roles: true },
      });
      expect(user).toMatchObject({
        name: 'First Admin',
        isActive: true,
        passwordSet: false,
        emailVerified: false,
      });
      expect(user.roles).toHaveLength(0);

      const suite = await prisma.suiteAdmin.findUniqueOrThrow({
        where: { userId: made.userId },
      });
      expect(suite).toMatchObject({ grantedById: null, reason: REASON });

      const events = await prisma.accountEvent.findMany({
        where: { userId: made.userId },
        select: { type: true, actorId: true, reason: true },
      });
      expect(events.map((e) => e.type).sort()).toEqual([
        'ADMIN_RECOVERY',
        'SUITE_ADMIN_ACTIONED',
      ]);
      expect(
        events.every((e) => e.actorId === null && e.reason === REASON),
      ).toBe(true);
      expect(sendSetupCode).toHaveBeenCalledWith({
        id: made.userId,
        name: 'First Admin',
        email: 'first.admin@welinc.com',
      });
    });

    it('refuses once a suite admin exists, writing nothing', async () => {
      const before = await prisma.user.count();
      await expect(create('second@welinc.com')).rejects.toThrow(
        /a suite admin exists already/,
      );
      expect(await prisma.user.count()).toBe(before);
      expect(await prisma.suiteAdmin.count()).toBe(1);
    });

    it('refuses an email that already has an account', async () => {
      // No suite admin, so only the existing account can refuse it
      await prisma.suiteAdmin.deleteMany({});
      await expect(create('FIRST.admin@welinc.com')).rejects.toThrow(
        /exists already; use the plain form/,
      );
      expect(await prisma.suiteAdmin.count()).toBe(0);
    });
  },
);
