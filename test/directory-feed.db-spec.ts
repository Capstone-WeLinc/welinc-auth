import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { dropTestDatabase } from './drop-test-database';

// Spec 0005, AC-1 to AC-3 and AC-5: the directory feed's migration, triggers and safe point
// against a real database. It makes a throwaway database on the server DATABASE_URL points at,
// applies every migration before the feed, adds people, applies the feed migration (so the
// backfill runs), then makes the same writes each welinc-auth write path makes and counts the
// feed rows. Run it with `npm run test:db` (locally: `docker exec welinc_auth_service npm run
// test:db`).

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const FEED_MIGRATION = '20261111000000_directory_feed';

const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();
const before = folders.filter((f) => f < FEED_MIGRATION);
const fromFeed = folders.filter((f) => f >= FEED_MIGRATION);
const sqlOf = (folder: string) =>
  readFileSync(join(MIGRATIONS, folder, 'migration.sql'), 'utf8');

const serverUrl = process.env.DATABASE_URL;
const dbName = `welinc_auth_feedtest_${randomBytes(4).toString('hex')}`;

function urlFor(database: string): string {
  const url = new URL(serverUrl!);
  url.pathname = `/${database}`;
  url.search = '';
  return url.toString();
}

type FeedRow = {
  type: string;
  systems: string;
  snapshot: {
    name: string;
    isActive: boolean;
    deletedAt: string | null;
    roles: { system: string; role: string }[];
  };
};

/** The feed read of AC-5 (`/auth/directory/changes`), as plain SQL. */
const SAFE_FEED = `
  SELECT "user_id"::text AS "user_id"
    FROM "directory_changes"
   WHERE "txid" < pg_snapshot_xmin(pg_current_snapshot())
     AND "user_id" = ANY($1::uuid[])
   ORDER BY "txid", "seq"`;

(serverUrl ? describe : describe.skip)(
  'spec 0005 directory feed on a fixture database',
  () => {
    let admin: Client;
    let db: Client;
    let other: Client;

    const ids = {
      vrms: randomUUID(), // VRMS Mechanic before the migration: backfilled
      gone: randomUUID(), // soft deleted VRMS Mechanic before the migration: backfilled, deleted
      none: randomUUID(), // no role before the migration: not backfilled
    };

    const addUser = (c: Client, id: string, name: string) =>
      c.query(
        `INSERT INTO "users" ("id", "name", "email", "password_hash", "updated_at")
         VALUES ($1, $2, $3, 'x', CURRENT_TIMESTAMP)`,
        [id, name, `${id}@fixture.test`],
      );
    const addRole = (c: Client, id: string, system: string, role: string) =>
      c.query(
        `INSERT INTO "user_roles" ("id", "user_id", "system", "role", "updated_at")
         VALUES ($1, $2, $3::"SystemType", $4, CURRENT_TIMESTAMP)`,
        [randomUUID(), id, system, role],
      );
    const rowsOf = async (id: string) =>
      (
        await db.query<FeedRow>(
          `SELECT "type", "systems"::text AS "systems", "snapshot"
             FROM "directory_changes" WHERE "user_id" = $1 ORDER BY "txid", "seq"`,
          [id],
        )
      ).rows;
    const countOf = async (id: string) => (await rowsOf(id)).length;
    const tx = async (work: () => Promise<unknown>) => {
      await db.query('BEGIN');
      try {
        await work();
        await db.query('COMMIT');
      } catch (error) {
        await db.query('ROLLBACK');
        throw error;
      }
    };
    /** A VRMS Mechanic made the way the admin create path makes one: user and roles in one save. */
    const newMechanic = async (name = 'Juan') => {
      const id = randomUUID();
      await tx(async () => {
        await addUser(db, id, name);
        await addRole(db, id, 'VRMS', 'MECHANIC');
      });
      return id;
    };

    beforeAll(async () => {
      admin = new Client({ connectionString: urlFor('postgres') });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${dbName}"`);
      db = new Client({ connectionString: urlFor(dbName) });
      other = new Client({ connectionString: urlFor(dbName) });
      await db.connect();
      await other.connect();
      for (const folder of before) await db.query(sqlOf(folder));

      await addUser(db, ids.vrms, 'Before');
      await addRole(db, ids.vrms, 'VRMS', 'MECHANIC');
      await addUser(db, ids.gone, 'Gone');
      await addRole(db, ids.gone, 'VRMS', 'MECHANIC');
      await db.query(
        `UPDATE "users" SET "deleted_at" = now(), "is_active" = false WHERE "id" = $1`,
        [ids.gone],
      );
      await addUser(db, ids.none, 'Nobody');

      for (const folder of fromFeed) await db.query(sqlOf(folder));
    });

    afterAll(async () => {
      await db?.end();
      await other?.end();
      if (admin) {
        await dropTestDatabase(admin, dbName);
        await admin.end();
      }
    });

    describe('the migration (AC-1)', () => {
      it('creates the single feed row with an epoch', async () => {
        const { rows } = await db.query<{ epoch: string }>(
          'SELECT "epoch"::text AS "epoch" FROM "directory_feed"',
        );
        expect(rows).toHaveLength(1);
        expect(rows[0].epoch).toMatch(/^[0-9a-f-]{36}$/);
        await expect(
          db.query('INSERT INTO "directory_feed" ("id") VALUES (false)'),
        ).rejects.toThrow();
      });

      it('backfills one created row for everyone holding a role, soft deleted included', async () => {
        expect(await rowsOf(ids.vrms)).toEqual([
          expect.objectContaining({ type: 'created', systems: '{VRMS}' }),
        ]);
        const [gone] = await rowsOf(ids.gone);
        expect(gone.type).toBe('created');
        expect(gone.snapshot.deletedAt).not.toBeNull();
        expect(await countOf(ids.none)).toBe(0);
      });
    });

    describe('every write path writes exactly one row (AC-2, AC-3)', () => {
      it('admin create with roles: one created row', async () => {
        const id = await newMechanic();
        expect(await rowsOf(id)).toEqual([
          expect.objectContaining({ type: 'created', systems: '{VRMS}' }),
        ]);
      });

      it('admin edit of fields: one updated row', async () => {
        const id = await newMechanic();
        await db.query(
          `UPDATE "users" SET "name" = 'Juan Cruz', "updated_at" = now() WHERE "id" = $1`,
          [id],
        );
        const rows = await rowsOf(id);
        expect(rows.map((r) => r.type)).toEqual(['created', 'updated']);
        expect(rows[1].snapshot.name).toBe('Juan Cruz');
      });

      it('admin edit of roles (a delete plus an insert): one roles_changed row', async () => {
        const id = await newMechanic();
        await tx(async () => {
          await db.query(`DELETE FROM "user_roles" WHERE "user_id" = $1`, [id]);
          await addRole(db, id, 'VRMS', 'CHIEF_MECHANIC');
        });
        const rows = await rowsOf(id);
        expect(rows.map((r) => r.type)).toEqual(['created', 'roles_changed']);
        // Spec 0013, AC-11: each role says whether it is temporary access
        expect(rows[1].snapshot.roles).toEqual([
          { system: 'VRMS', role: 'CHIEF_MECHANIC', temporary: false },
        ]);
      });

      it('admin edit of fields and roles in one save: one row', async () => {
        const id = await newMechanic();
        await tx(async () => {
          await db.query(`UPDATE "users" SET "name" = 'Both' WHERE "id" = $1`, [
            id,
          ]);
          await addRole(db, id, 'VMMS', 'MECHANIC');
        });
        const rows = await rowsOf(id);
        expect(rows).toHaveLength(2);
        expect(rows[1]).toMatchObject({
          type: 'roles_changed',
          systems: '{VRMS,VMMS}',
        });
      });

      it('deactivate, then activate: one row each', async () => {
        const id = await newMechanic();
        await db.query(
          `UPDATE "users" SET "is_active" = false WHERE "id" = $1`,
          [id],
        );
        await db.query(
          `UPDATE "users" SET "is_active" = true WHERE "id" = $1`,
          [id],
        );
        expect((await rowsOf(id)).map((r) => r.type)).toEqual([
          'created',
          'deactivated',
          'activated',
        ]);
      });

      it('delete (soft): one deleted row, ahead of the deactivation it carries', async () => {
        const id = await newMechanic();
        await db.query(
          `UPDATE "users" SET "deleted_at" = now(), "is_active" = false, "locked_at" = NULL
           WHERE "id" = $1`,
          [id],
        );
        expect((await rowsOf(id)).map((r) => r.type)).toEqual([
          'created',
          'deleted',
        ]);
      });

      it('own profile edit and picture upload: one updated row each', async () => {
        const id = await newMechanic();
        await db.query(
          `UPDATE "users" SET "contact" = '+639171234567' WHERE "id" = $1`,
          [id],
        );
        await db.query(
          `UPDATE "users" SET "profile_picture" = '/uploads/profiles/x.jpg' WHERE "id" = $1`,
          [id],
        );
        expect((await rowsOf(id)).map((r) => r.type)).toEqual([
          'created',
          'updated',
          'updated',
        ]);
      });

      it('writes nothing for equal values, password changes and resets, locks, unlocks, failed logins and email checks', async () => {
        const id = await newMechanic('Same');
        const writes = [
          `UPDATE "users" SET "name" = 'Same', "updated_at" = now() WHERE "id" = $1`,
          `UPDATE "users" SET "password_hash" = 'changed', "updated_at" = now() WHERE "id" = $1`,
          `UPDATE "users" SET "failed_login_attempts" = "failed_login_attempts" + 1 WHERE "id" = $1`,
          `UPDATE "users" SET "locked_at" = now(), "failed_login_attempts" = 5 WHERE "id" = $1`,
          `UPDATE "users" SET "locked_at" = NULL, "failed_login_attempts" = 0 WHERE "id" = $1`,
          `UPDATE "users" SET "email_verified" = true WHERE "id" = $1`,
          `UPDATE "user_roles" SET "updated_at" = now() WHERE "user_id" = $1`,
        ];
        for (const sql of writes) await db.query(sql, [id]);
        expect(await countOf(id)).toBe(1);
      });

      it('writes nothing for a rolled back transaction', async () => {
        const id = await newMechanic();
        await db.query('BEGIN');
        await db.query(`UPDATE "users" SET "name" = 'Rolled' WHERE "id" = $1`, [
          id,
        ]);
        await db.query('ROLLBACK');
        expect(await countOf(id)).toBe(1);
      });

      it('a hard delete writes a deleted row built from the old row', async () => {
        const id = await newMechanic('Erased');
        await db.query(`DELETE FROM "users" WHERE "id" = $1`, [id]);
        const rows = await rowsOf(id);
        expect(rows.map((r) => r.type)).toEqual(['created', 'deleted']);
        expect(rows[1].snapshot).toMatchObject({
          name: 'Erased',
          roles: [{ system: 'VRMS', role: 'MECHANIC' }],
        });
        expect(rows[1].snapshot.deletedAt).not.toBeNull();
        expect(rows[1].systems).toBe('{VRMS}');
      });

      it('the seed script: a rerun in one transaction (delete, then the same person again) writes nothing', async () => {
        const id = await newMechanic('Seeded');
        await tx(async () => {
          await db.query(`DELETE FROM "users" WHERE "id" = $1`, [id]);
          await addUser(db, id, 'Seeded');
          await addRole(db, id, 'VRMS', 'MECHANIC');
        });
        expect(await countOf(id)).toBe(1);
      });
    });

    describe('losing the last role (contract 0001 section 9)', () => {
      it('sends one roles_changed with no roles, then nothing to that system', async () => {
        const id = await newMechanic();
        await db.query(`DELETE FROM "user_roles" WHERE "user_id" = $1`, [id]);
        await db.query(
          `UPDATE "users" SET "name" = 'Elsewhere' WHERE "id" = $1`,
          [id],
        );
        const rows = await rowsOf(id);
        expect(rows.map((r) => [r.type, r.systems])).toEqual([
          ['created', '{VRMS}'],
          ['roles_changed', '{VRMS}'],
          ['updated', '{}'],
        ]);
        expect(rows[1].snapshot.roles).toEqual([]);
      });
    });

    describe('the safe point (AC-5)', () => {
      it('serves neither of two commits while an older transaction is open, then both in txid order', async () => {
        const juan = await newMechanic('Juan');
        const ana = await newMechanic('Ana');
        const both = [juan, ana];
        const reader = new Client({ connectionString: urlFor(dbName) });
        await reader.connect();
        try {
          const baseline = (await reader.query(SAFE_FEED, [both])).rows.length;

          // A writes Juan and stays open; B writes Ana and commits
          await db.query('BEGIN');
          await db.query(
            `UPDATE "users" SET "name" = 'Juan A' WHERE "id" = $1`,
            [juan],
          );
          await db.query('SELECT pg_current_xact_id()');
          await other.query(
            `UPDATE "users" SET "name" = 'Ana B' WHERE "id" = $1`,
            [ana],
          );

          expect((await reader.query(SAFE_FEED, [both])).rows).toHaveLength(
            baseline,
          );

          await db.query('COMMIT');
          const after = (await reader.query(SAFE_FEED, [both])).rows.map(
            (r: { user_id: string }) => r.user_id,
          );
          expect(after.slice(baseline)).toEqual([juan, ana]);
        } finally {
          await reader.end();
        }
      });
    });
  },
);
