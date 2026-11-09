import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg, { Client } from 'pg';
import type { ManifestPerson } from '../prisma/seeds/manifest';
import {
  readUsersBefore,
  resetUsers,
  SeedConflictError,
  seedPeople,
} from '../prisma/seeds/users.seed';

// Spec 0006, AC-7, AC-8 and AC-9: the people seed against a real database. It makes a throwaway
// database on the server DATABASE_URL points at, applies every migration, then runs the seed's
// own functions the way prisma/seed.ts does (one transaction per run) and counts the rows the
// directory feed gets. Run it with `npm run test:db` (locally: `docker exec welinc_auth_service
// npm run test:db`).

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const serverUrl = process.env.DATABASE_URL;
const dbName = `welinc_auth_seedtest_${randomBytes(4).toString('hex')}`;

function urlFor(database: string): string {
  const url = new URL(serverUrl!);
  url.pathname = `/${database}`;
  url.search = '';
  return url.toString();
}

const id = (n: number) =>
  `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

function person(n: number, o: Partial<ManifestPerson> = {}): ManifestPerson {
  return {
    id: id(n),
    email: `seed${n}@welinc.com`,
    name: `Seed ${n}`,
    group: 'office',
    state: 'active',
    password: 'admin',
    contact: null,
    roles: [{ system: 'VRMS', role: 'ADMIN' }],
    ...o,
  };
}

const hashes = new Map([['admin', 'hash-for-tests']]);

(serverUrl ? describe : describe.skip)(
  'spec 0006 people seed on a database',
  () => {
    let admin: Client;
    let pool: pg.Pool;
    let prisma: PrismaClient;

    async function run(
      people: ManifestPerson[],
      opts: { reset?: boolean } = {},
    ) {
      await prisma.$transaction(async (tx) => {
        const before = await readUsersBefore(tx, people);
        if (opts.reset) await resetUsers(tx);
        await seedPeople(tx, people, hashes, new Date(), before, !opts.reset);
      });
    }

    const feed = async (userId?: string) =>
      (
        await pool.query<{ type: string; user_id: string }>(
          userId
            ? 'SELECT type, user_id FROM directory_changes WHERE user_id = $1 ORDER BY seq'
            : 'SELECT type, user_id FROM directory_changes ORDER BY seq',
          userId ? [userId] : [],
        )
      ).rows;

    const userCount = async () => await prisma.user.count();

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
    });

    afterAll(async () => {
      await prisma?.$disconnect();
      await pool?.end();
      await admin?.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
      await admin?.end();
    });

    it('creates the people with their roles and one created row each', async () => {
      // covers: AC-7, AC-8
      const people = [
        person(1),
        person(2, { roles: [{ system: 'VRMS', role: 'MECHANIC' }] }),
      ];
      await run(people);
      expect(await userCount()).toBe(2);
      const roles = await prisma.userRoleAssignment.findMany({
        where: { userId: id(2) },
      });
      expect(roles.map((r) => r.role)).toEqual(['MECHANIC']);
      expect((await feed()).filter((r) => r.type === 'created')).toHaveLength(
        2,
      );
    });

    it('writes no feed rows when run again unchanged', async () => {
      // covers: AC-8
      const before = (await feed()).length;
      await run([
        person(1),
        person(2, { roles: [{ system: 'VRMS', role: 'MECHANIC' }] }),
      ]);
      expect((await feed()).length).toBe(before);
    });

    it('puts a changed role set back exactly and logs one roles_changed row', async () => {
      // covers: AC-7, AC-8
      await prisma.userRoleAssignment.create({
        data: { userId: id(1), system: 'VRMS', role: 'MECHANIC' },
      });
      const feedBefore = (await feed(id(1))).length;
      await run([
        person(1),
        person(2, { roles: [{ system: 'VRMS', role: 'MECHANIC' }] }),
      ]);
      const roles = await prisma.userRoleAssignment.findMany({
        where: { userId: id(1) },
      });
      expect(roles.map((r) => r.role)).toEqual(['ADMIN']);
      const added = (await feed(id(1))).slice(feedBefore);
      expect(added.map((r) => r.type)).toEqual(['roles_changed']);
    });

    it('leaves a hand made user and their roles alone', async () => {
      // covers: AC-7
      const handId = randomUUID();
      await prisma.user.create({
        data: {
          id: handId,
          name: 'Hand Made',
          email: 'hand@example.com',
          passwordHash: 'x',
        },
      });
      await prisma.userRoleAssignment.create({
        data: { userId: handId, system: 'VRMS', role: 'ADMIN' },
      });
      const before = (await feed()).length;
      await run([
        person(1),
        person(2, { roles: [{ system: 'VRMS', role: 'MECHANIC' }] }),
      ]);
      expect(
        await prisma.user.findUnique({ where: { id: handId } }),
      ).not.toBeNull();
      expect(
        await prisma.userRoleAssignment.count({ where: { userId: handId } }),
      ).toBe(1);
      expect((await feed()).length).toBe(before);
    });

    it('refuses an email held by another id and writes nothing', async () => {
      // covers: AC-7
      const usersBefore = await userCount();
      const feedBefore = (await feed()).length;
      await expect(
        run([person(9, { email: 'hand@example.com' })]),
      ).rejects.toBeInstanceOf(SeedConflictError);
      expect(await userCount()).toBe(usersBefore);
      expect((await feed()).length).toBe(feedBefore);
    });

    it('gives a locked person five attempts and a lock, then a clean row when active again', async () => {
      // covers: AC-5
      await run([person(3, { state: 'locked' })]);
      const locked = await prisma.user.findUniqueOrThrow({
        where: { id: id(3) },
      });
      expect(locked.failedLoginAttempts).toBe(5);
      expect(locked.lockedAt).not.toBeNull();
      await run([person(3)]);
      const clean = await prisma.user.findUniqueOrThrow({
        where: { id: id(3) },
      });
      expect(clean.failedLoginAttempts).toBe(0);
      expect(clean.lockedAt).toBeNull();
    });

    it('keeps the lock time across runs', async () => {
      // covers: AC-5, AC-8
      await run([person(4, { state: 'locked' })]);
      const first = (
        await prisma.user.findUniqueOrThrow({ where: { id: id(4) } })
      ).lockedAt;
      await run([person(4, { state: 'locked' })]);
      const second = (
        await prisma.user.findUniqueOrThrow({ where: { id: id(4) } })
      ).lockedAt;
      expect(second).toEqual(first);
    });

    it('--reset removes every user, and a recreated seed person writes no new feed rows', async () => {
      // covers: AC-8, AC-9
      const handId = (
        await prisma.user.findFirstOrThrow({
          where: { email: 'hand@example.com' },
        })
      ).id;
      const people = [
        person(1),
        person(2, { roles: [{ system: 'VRMS', role: 'MECHANIC' }] }),
      ];
      const seedFeedBefore = (await feed(id(1))).length;
      await run(people, { reset: true });
      expect(
        await prisma.user.findUnique({ where: { id: handId } }),
      ).toBeNull();
      expect(await userCount()).toBe(2);
      expect((await feed(id(1))).length).toBe(seedFeedBefore);
      expect(
        (await feed(handId)).filter((r) => r.type === 'deleted'),
      ).toHaveLength(1);
    });
  },
);
