import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Client } from 'pg';
import { dropTestDatabase } from './drop-test-database';

// Spec 0009, AC-1 and AC-16: the email verification migration against a real database. It makes
// a throwaway database, applies every migration before 0009, inserts users in each setup state,
// applies 0009 and checks the `password_set` backfill and the new table's rules. Run it with
// `npm run test:db` (locally: `docker exec welinc_auth_service npm run test:db`).

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const CODES_MIGRATION = '20261113000000_email_verification';

const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();
const before = folders.filter((f) => f < CODES_MIGRATION);
const fromCodes = folders.filter((f) => f >= CODES_MIGRATION);
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
  verified: randomUUID(), // used a code once: email_verified true, had a token row
  typed: randomUUID(), // an admin typed the password: never had a token row
  pending: randomUUID(), // setup code sent, never used
};

(serverUrl ? describe : describe.skip)(
  'spec 0009 migration on a fixture database',
  () => {
    let admin: Client;
    let db: Client;
    let feedBefore = 0;
    const feedCount = async () =>
      Number(
        (
          await db.query<{ n: string }>(
            'SELECT count(*) AS "n" FROM "directory_changes"',
          )
        ).rows[0].n,
      );

    beforeAll(async () => {
      admin = new Client({ connectionString: urlFor('postgres') });
      await admin.connect();
      await admin.query(`CREATE DATABASE "${dbName}"`);
      db = new Client({ connectionString: urlFor(dbName) });
      await db.connect();
      for (const folder of before) await db.query(sqlOf(folder));

      const user = (id: string, name: string, verified: boolean) =>
        db.query(
          `INSERT INTO "users" ("id", "name", "email", "email_verified", "password_hash", "updated_at")
           VALUES ($1, $2, $3, $4, 'x', CURRENT_TIMESTAMP)`,
          [id, name, `${name.toLowerCase()}@fixture.test`, verified],
        );
      const token = (userId: string, used: boolean) =>
        db.query(
          `INSERT INTO "password_reset_tokens" ("id", "user_id", "otp", "expires_at", "used_at")
           VALUES ($1, $2, '123456', CURRENT_TIMESTAMP, $3)`,
          [randomUUID(), userId, used ? new Date() : null],
        );
      await user(ids.verified, 'Verified', true);
      await token(ids.verified, true);
      await user(ids.typed, 'Typed', false);
      await user(ids.pending, 'Pending', false);
      await token(ids.pending, false);
      feedBefore = await feedCount();

      for (const folder of fromCodes) await db.query(sqlOf(folder));
    });

    afterAll(async () => {
      await db?.end();
      if (admin) {
        await dropTestDatabase(admin, dbName);
        await admin.end();
      }
    });

    const flags = async (id: string) =>
      (
        await db.query<{ password_set: boolean; email_verified: boolean }>(
          'SELECT "password_set", "email_verified" FROM "users" WHERE "id" = $1',
          [id],
        )
      ).rows[0];

    it('sets password_set from email_verified or a missing code row, and keeps email_verified (AC-16)', async () => {
      expect(await flags(ids.verified)).toEqual({
        password_set: true,
        email_verified: true,
      });
      expect(await flags(ids.typed)).toEqual({
        password_set: true,
        email_verified: false,
      });
      expect(await flags(ids.pending)).toEqual({
        password_set: false,
        email_verified: false,
      });
    });

    // AC-23: password_set is not in the feed snapshot, so the backfill writes no feed row, even
    // for people with no feed row yet (no role), and the trigger is back on afterwards
    it('writes nothing to the directory feed and leaves the feed trigger on', async () => {
      expect(await feedCount()).toBe(feedBefore);
      const { rows } = await db.query<{ tgenabled: string }>(
        `SELECT tgenabled FROM pg_trigger WHERE tgname = 'directory_users_change'`,
      );
      expect(rows[0].tgenabled).toBe('O');
    });

    it('drops password_reset_tokens (AC-1)', async () => {
      const { rows } = await db.query<{ t: string | null }>(
        `SELECT to_regclass('public.password_reset_tokens')::text AS "t"`,
      );
      expect(rows[0].t).toBeNull();
    });

    const code = (
      purpose: string,
      fields: { challenge?: string; newEmail?: string } = {},
    ) =>
      db.query(
        `INSERT INTO "verification_codes" ("id", "user_id", "purpose", "code_hash", "challenge_hash", "new_email", "expires_at")
         VALUES ($1, $2, $3::"VerificationPurpose", 'h', $4, $5, CURRENT_TIMESTAMP + interval '10 minutes')`,
        [
          randomUUID(),
          ids.typed,
          purpose,
          fields.challenge ?? null,
          fields.newEmail ?? null,
        ],
      );

    it('holds challenge_hash to SIGN_IN rows and new_email to EMAIL_CHANGE rows', async () => {
      await expect(
        code('PASSWORD_RESET', { challenge: 'a'.repeat(64) }),
      ).rejects.toThrow(/verification_codes_purpose_fields_check/);
      await expect(
        code('SIGN_IN', { newEmail: 'x@fixture.test' }),
      ).rejects.toThrow(/verification_codes_purpose_fields_check/);
      await expect(
        code('EMAIL_CHANGE', { newEmail: 'x@fixture.test' }),
      ).resolves.toBeDefined();
    });

    it('keeps a ticket unique, and allows many rows without one', async () => {
      await code('SIGN_IN', { challenge: 'b'.repeat(64) });
      await expect(
        code('SIGN_IN', { challenge: 'b'.repeat(64) }),
      ).rejects.toThrow(/verification_codes_challenge_hash_key/);
      await code('SIGN_IN');
      await expect(code('SIGN_IN')).resolves.toBeDefined();
    });

    it('deletes a user’s codes with the user', async () => {
      await db.query('DELETE FROM "users" WHERE "id" = $1', [ids.typed]);
      const { rowCount } = await db.query(
        'SELECT 1 FROM "verification_codes" WHERE "user_id" = $1',
        [ids.typed],
      );
      expect(rowCount).toBe(0);
    });
  },
);
