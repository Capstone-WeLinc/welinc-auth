import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { dropTestDatabase } from './drop-test-database';

// Spec 0004, AC-7 and AC-8: the roles per system migration against a real database. It makes a
// throwaway database on the server DATABASE_URL points at, applies every migration before 0004,
// inserts rows that break the new rules, then applies 0004 and checks what is left. Needs a
// role that may CREATE DATABASE. Run it with `npm run test:db` (inside the auth container
// locally: `docker exec welinc_auth_service npm run test:db`).

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const ROLES_MIGRATION = '20261110000000_roles_per_system';

const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();
const before = folders.filter((f) => f < ROLES_MIGRATION);
const fromRoles = folders.filter((f) => f >= ROLES_MIGRATION);
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
  admin: randomUUID(), // VRMS Mechanic (older) and VRMS Admin: keeps Admin
  stray: randomUUID(), // BMS Mechanic only: not a BMS role, left with nothing
  shared: randomUUID(), // VRMS Chief Mechanic and VMMS Mechanic: untouched
  vmmsTwo: randomUUID(), // VMMS Mechanic and VMMS Chief Mechanic, same time: keeps Chief
};

type RoleRow = { user_id: string; system: string; role: string };

(serverUrl ? describe : describe.skip)(
  'spec 0004 migration on a fixture database',
  () => {
    let admin: Client;
    let db: Client;
    const notices: string[] = [];

    beforeAll(async () => {
      admin = new Client({ connectionString: urlFor('postgres') });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${dbName}"`);
      db = new Client({ connectionString: urlFor(dbName) });
      await db.connect();
      db.on('notice', (n) => notices.push(n.message ?? ''));
      for (const folder of before) await db.query(sqlOf(folder));

      const user = (id: string, name: string) =>
        db.query(
          `INSERT INTO "users" ("id", "name", "email", "password_hash", "updated_at")
           VALUES ($1, $2, $3, 'x', CURRENT_TIMESTAMP)`,
          [id, name, `${name.toLowerCase()}@fixture.test`],
        );
      const role = (userId: string, system: string, code: string, at: string) =>
        db.query(
          `INSERT INTO "user_roles" ("id", "user_id", "system", "role", "created_at", "updated_at")
           VALUES ($1, $2, $3::"SystemType", $4::"UserRole", $5::timestamptz, CURRENT_TIMESTAMP)`,
          [randomUUID(), userId, system, code, at],
        );
      await user(ids.admin, 'Admin');
      await user(ids.stray, 'Stray');
      await user(ids.shared, 'Shared');
      await user(ids.vmmsTwo, 'Vmmstwo');
      await role(ids.admin, 'VRMS', 'MECHANIC', '2026-01-01T00:00:00Z');
      await role(ids.admin, 'VRMS', 'ADMIN', '2026-02-01T00:00:00Z');
      await role(ids.stray, 'BMS', 'MECHANIC', '2026-01-01T00:00:00Z');
      await role(ids.shared, 'VRMS', 'CHIEF_MECHANIC', '2026-01-01T00:00:00Z');
      await role(ids.shared, 'VMMS', 'MECHANIC', '2026-01-01T00:00:00Z');
      await role(ids.vmmsTwo, 'VMMS', 'MECHANIC', '2026-03-01T00:00:00Z');
      await role(ids.vmmsTwo, 'VMMS', 'CHIEF_MECHANIC', '2026-03-01T00:00:00Z');

      for (const folder of fromRoles) await db.query(sqlOf(folder));
    });

    afterAll(async () => {
      await db?.end();
      if (admin) {
        await dropTestDatabase(admin, dbName);
        await admin.end();
      }
    });

    const rolesOf = async (userId: string) =>
      (
        await db.query<RoleRow>(
          `SELECT "user_id", "system"::text AS "system", "role" FROM "user_roles"
           WHERE "user_id" = $1 ORDER BY "system", "role"`,
          [userId],
        )
      ).rows.map((r) => `${r.system} ${r.role}`);

    it('keeps the most powerful role when a system holds more than its limit (AC-7)', async () => {
      expect(await rolesOf(ids.admin)).toEqual(['VRMS ADMIN']);
      expect(await rolesOf(ids.vmmsTwo)).toEqual(['VMMS CHIEF_MECHANIC']);
    });

    it('removes a role the system does not have, and keeps the account (AC-7)', async () => {
      expect(await rolesOf(ids.stray)).toEqual([]);
      const { rowCount } = await db.query(
        'SELECT 1 FROM "users" WHERE "id" = $1',
        [ids.stray],
      );
      expect(rowCount).toBe(1);
    });

    it('leaves valid rows alone', async () => {
      expect(await rolesOf(ids.shared)).toEqual([
        'VMMS MECHANIC',
        'VRMS CHIEF_MECHANIC',
      ]);
    });

    it('writes one notice per removed row, by user id and never by email (AC-7)', () => {
      const ours = notices.filter((n) => n.startsWith('user '));
      expect(ours).toEqual(
        expect.arrayContaining([
          `user ${ids.admin}: removed VRMS MECHANIC, kept VRMS ADMIN`,
          `user ${ids.vmmsTwo}: removed VMMS MECHANIC, kept VMMS CHIEF_MECHANIC`,
          `user ${ids.stray}: removed BMS MECHANIC, not a BMS role`,
          `user ${ids.stray}: no roles left`,
        ]),
      );
      expect(ours).toHaveLength(4);
      expect(ours.join('\n')).not.toContain('@');
    });

    it('turns the role into text and drops the UserRole type (AC-8)', async () => {
      const column = await db.query<{ data_type: string; len: number }>(
        `SELECT "data_type", "character_maximum_length" AS "len"
         FROM information_schema.columns
         WHERE table_name = 'user_roles' AND column_name = 'role'`,
      );
      expect(column.rows[0]).toEqual({
        data_type: 'character varying',
        len: 40,
      });
      const type = await db.query(
        `SELECT 1 FROM pg_type WHERE typname = 'UserRole'`,
      );
      expect(type.rowCount).toBe(0);
    });

    it('refuses a role outside the catalog through the foreign key (AC-8)', async () => {
      await expect(
        db.query(
          `INSERT INTO "user_roles" ("id", "user_id", "system", "role", "updated_at")
           VALUES ($1, $2, 'VRMS', 'DRIVER', CURRENT_TIMESTAMP)`,
          [randomUUID(), ids.stray],
        ),
      ).rejects.toThrow(/user_roles_system_role_fkey/);
    });
  },
);
