import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { dropTestDatabase } from './drop-test-database';

// Spec 0011, AC-8 and AC-10: the account events migration against a real database. It makes a
// throwaway database, applies every migration before 0011, inserts user_changes rows of each
// kind, applies 0011 and checks the copy, the per system role split and the append only rules.
// Run it with `npm run test:db` (locally: `docker exec welinc_auth_service npm run test:db`).

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const EVENTS_MIGRATION = '20261114000000_account_events';

const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();
const before = folders.filter((f) => f < EVENTS_MIGRATION);
const fromEvents = folders.filter((f) => f >= EVENTS_MIGRATION);
const sqlOf = (folder: string) =>
  readFileSync(join(MIGRATIONS, folder, 'migration.sql'), 'utf8');

const serverUrl = process.env.DATABASE_URL;
const dbName = `welinc_auth_migtest_${randomBytes(4).toString('hex')}`;

function urlFor(database: string): string {
  const url = new URL(serverUrl!);
  url.pathname = `/${database}`;
  url.search = '';
  return url.toString();
}

const ids = {
  admin: randomUUID(),
  person: randomUUID(),
  created: randomUUID(),
  reset: randomUUID(),
  // VRMS changed, VMMS added, BMS unchanged: two rows
  roles: randomUUID(),
  // one system fully removed: one row with a null new side
  removed: randomUUID(),
};

(serverUrl ? describe : describe.skip)(
  'spec 0011 migration on a fixture database',
  () => {
    let admin: Client;
    let db: Client;

    beforeAll(async () => {
      admin = new Client({ connectionString: urlFor('postgres') });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${dbName}"`);
      db = new Client({ connectionString: urlFor(dbName) });
      await db.connect();
      for (const folder of before) await db.query(sqlOf(folder));

      for (const [id, name] of [
        [ids.admin, 'Admin'],
        [ids.person, 'Person'],
      ]) {
        await db.query(
          `INSERT INTO "users" ("id", "name", "email", "password_hash", "updated_at")
           VALUES ($1, $2, $3, 'x', CURRENT_TIMESTAMP)`,
          [id, name, `${name.toLowerCase()}@fixture.test`],
        );
      }
      const change = (
        id: string,
        action: string,
        values: { field?: string; old?: string | null; new?: string | null },
      ) =>
        db.query(
          `INSERT INTO "user_changes" ("id", "user_id", "actor_id", "actor_email", "action", "field", "old_value", "new_value")
           VALUES ($1, $2, $3, 'admin@fixture.test', $4::"UserChangeAction", $5, $6, $7)`,
          [
            id,
            ids.person,
            ids.admin,
            action,
            values.field ?? null,
            values.old ?? null,
            values.new ?? null,
          ],
        );
      await change(ids.created, 'CREATED', {});
      await change(ids.reset, 'RESET_SENT', {});
      await change(ids.roles, 'ROLE_CHANGED', {
        field: 'roles',
        old: 'ADMIN@BMS,MECHANIC@VRMS',
        new: 'ADMIN@BMS,CHIEF_MECHANIC@VRMS,DRIVER@VMMS',
      });
      await change(ids.removed, 'ROLE_CHANGED', {
        field: 'roles',
        old: 'ADMIN@BMS,MECHANIC@VRMS',
        new: 'MECHANIC@VRMS',
      });

      for (const folder of fromEvents) await db.query(sqlOf(folder));
    });

    afterAll(async () => {
      await db?.end();
      if (admin) {
        await dropTestDatabase(admin, dbName);
        await admin.end();
      }
    });

    type Row = {
      id: string;
      category: string;
      type: string;
      reason: string | null;
      system: string | null;
      old_value: string | null;
      new_value: string | null;
    };
    const rows = async () =>
      (
        await db.query<Row>(
          `SELECT "id", "category", "type", "reason", "system", "old_value", "new_value"
           FROM "account_events" ORDER BY "type", "system" NULLS FIRST`,
        )
      ).rows;

    it('copies every row, plus one extra per extra system a role change touched (AC-10)', async () => {
      // 4 old rows, the multi system change splits into 2
      expect(await rows()).toHaveLength(5);
    });

    it('keeps plain rows and turns RESET_SENT into CODE_SENT with PASSWORD_RESET', async () => {
      const all = await rows();
      expect(all.find((r) => r.id === ids.created)).toMatchObject({
        category: 'ACCOUNT',
        type: 'CREATED',
        system: null,
      });
      expect(all.find((r) => r.id === ids.reset)).toMatchObject({
        category: 'CODE',
        type: 'CODE_SENT',
        reason: 'PASSWORD_RESET',
      });
    });

    it('splits a role change per system that differs, the first by system order keeping the id', async () => {
      // System order is the code's text order (BMS, VMMS, VRMS), as the migration ranks them
      const roles = (await rows())
        .filter((r) => r.type === 'ROLE_CHANGED' && r.id !== ids.removed)
        .sort((a, b) => (a.system ?? '').localeCompare(b.system ?? ''));
      expect(roles).toEqual([
        expect.objectContaining({
          system: 'VMMS',
          old_value: null,
          new_value: 'DRIVER@VMMS',
          id: ids.roles,
        }),
        expect.objectContaining({
          system: 'VRMS',
          old_value: 'MECHANIC@VRMS',
          new_value: 'CHIEF_MECHANIC@VRMS',
        }),
      ]);
      expect(roles[1].id).not.toBe(ids.roles);
    });

    it('writes null for a system fully removed', async () => {
      const removed = (await rows()).find((r) => r.id === ids.removed);
      expect(removed).toMatchObject({
        system: 'BMS',
        old_value: 'ADMIN@BMS',
        new_value: null,
      });
    });

    it('drops user_changes and its enum', async () => {
      const { rows: found } = await db.query<{ t: string | null; e: string }>(
        `SELECT to_regclass('public.user_changes')::text AS "t",
                (SELECT count(*)::text FROM pg_type WHERE typname = 'UserChangeAction') AS "e"`,
      );
      expect(found[0]).toEqual({ t: null, e: '0' });
    });

    const insert = (category: string, type: string) =>
      db.query<{ id: string }>(
        `INSERT INTO "account_events" ("id", "user_id", "category", "type")
         VALUES ($1, $2, $3::"AccountEventCategory", $4::"AccountEventType") RETURNING "id"`,
        [randomUUID(), ids.person, category, type],
      );

    it('holds a 500 character written reason (spec 0013, AC-9)', async () => {
      const reason = 'r'.repeat(500);
      const { rows } = await db.query<{ reason: string }>(
        `INSERT INTO "account_events" ("id", "user_id", "category", "type", "reason")
         VALUES ($1, $2, 'ACCOUNT', 'TEMP_ACCESS_STARTED', $3) RETURNING "reason"`,
        [randomUUID(), ids.person, reason],
      );
      expect(rows[0].reason).toBe(reason);
    });

    it('refuses a type outside its category', async () => {
      await expect(insert('SIGN_IN', 'CREATED')).rejects.toThrow(
        /account_events_type_category_check/,
      );
    });

    it('refuses every UPDATE and a plain DELETE (AC-8)', async () => {
      const { rows: made } = await insert('SIGN_IN', 'SIGNED_IN');
      const id = made[0].id;
      await expect(
        db.query(`UPDATE "account_events" SET "reason" = 'x' WHERE "id" = $1`, [
          id,
        ]),
      ).rejects.toThrow(/append only/);
      await expect(
        db.query(`DELETE FROM "account_events" WHERE "id" = $1`, [id]),
      ).rejects.toThrow(/append only/);
    });

    it('lets the sweep delete non ACCOUNT rows, never ACCOUNT rows', async () => {
      const { rows: made } = await insert('SIGN_IN', 'SIGNED_IN');
      const id = made[0].id;
      await db.query('BEGIN');
      await db.query(`SELECT set_config('welinc.event_sweep', 'on', true)`);
      const { rowCount } = await db.query(
        `DELETE FROM "account_events" WHERE "id" = $1`,
        [id],
      );
      expect(rowCount).toBe(1);
      await expect(
        db.query(`DELETE FROM "account_events" WHERE "id" = $1`, [ids.created]),
      ).rejects.toThrow(/kept forever/);
      await db.query('ROLLBACK');
      // The setting was local to that transaction, and the rollback brought the row back
      await expect(
        db.query(`DELETE FROM "account_events" WHERE "id" = $1`, [id]),
      ).rejects.toThrow(/only the sweep/);
    });

    it('allows TRUNCATE for the local seed reset', async () => {
      await expect(
        db.query('TRUNCATE "account_events"'),
      ).resolves.toBeDefined();
    });
  },
);
