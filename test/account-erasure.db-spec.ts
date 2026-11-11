import { afterAll, beforeAll, describe, expect, it, jest } from '@jest/globals';
import { Logger } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg, { Client } from 'pg';
import type { Env } from '../src/config/env';
import { ErasureService } from '../src/auth/deletion/erasure.service';
import { AccountEventsService } from '../src/auth/events/account-events.service';
import { noGeo } from '../src/auth/testing/geo.fake';
import type { MailService } from '../src/shared/mail.service';
import type { PrismaService } from '../src/shared/prisma.service';

// Spec 0012, AC-15 to AC-19 against a real database: the erasure transaction, the narrow
// account_events trigger exception, the directory feed rewrite and the one pending index.
// Run with `npm run test:db`.

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const serverUrl = process.env.DATABASE_URL;
const dbName = `welinc_auth_erasetest_${randomBytes(4).toString('hex')}`;

function urlFor(database: string): string {
  const url = new URL(serverUrl!);
  url.pathname = `/${database}`;
  url.search = '';
  return url.toString();
}

const DAY = 86_400_000;
const GRACE_DAYS = 30;

(serverUrl ? describe : describe.skip)('spec 0012 account erasure', () => {
  let admin: Client;
  let pool: pg.Pool;
  let prisma: PrismaClient;
  let erasure: ErasureService;
  const sent: { to: string; subject: string }[] = [];

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
    const config = {
      get: () => GRACE_DAYS,
    } as unknown as ConfigService<Env, true>;
    const mail = {
      sendMail: (options: { to: string; subject: string }) => {
        sent.push(options);
        return Promise.resolve();
      },
    } as unknown as MailService;
    erasure = new ErasureService(
      db,
      new AccountEventsService(db, noGeo),
      mail,
      config,
    );
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
    await pool.query(
      `INSERT INTO "systems" ("code", "name", "description", "updated_at")
       VALUES ('VRMS', 'VRMS', 'Repairs', CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING`,
    );
    await pool.query(
      `INSERT INTO "system_roles" ("system", "code", "name", "description", "sort_order", "is_system_admin", "updated_at")
       VALUES ('VRMS', 'MECHANIC', 'Mechanic', 'Fixes', 2, false, CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING`,
    );
    await pool.query(
      `INSERT INTO "oauth_clients" ("id", "kind", "grants", "user_audiences", "updated_at")
       VALUES ('portal', 'FIRST_PARTY_WEB', '{sso}', '{}', CURRENT_TIMESTAMP) ON CONFLICT DO NOTHING`,
    );
  });

  afterAll(async () => {
    await prisma?.$disconnect();
    await pool?.end();
    if (admin) {
      await admin.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
      await admin.end();
    }
  });

  /** A mechanic with a session, codes, events and feed history, soft deleted `ageDays` ago. */
  async function deletedPerson(ageDays: number) {
    const id = randomUUID();
    const email = `p-${id.slice(0, 8)}@fixture.test`;
    await pool.query(
      `INSERT INTO "users" ("id", "name", "email", "contact", "profile_picture", "password_hash", "email_verified", "password_set", "updated_at")
       VALUES ($1, 'Ana Cruz', $2, '+639171234567', '/uploads/profiles/x.jpg', '$argon2id$v=19$fake', true, true, CURRENT_TIMESTAMP)`,
      [id, email],
    );
    await pool.query(
      `INSERT INTO "user_roles" ("id", "user_id", "role", "system", "updated_at")
       VALUES ($1, $2, 'MECHANIC', 'VRMS', CURRENT_TIMESTAMP)`,
      [randomUUID(), id],
    );
    const sid = randomUUID();
    await pool.query(
      `INSERT INTO "sessions" ("id", "user_id", "kind", "login_client_id", "device_name", "user_agent", "created_ip", "last_seen_ip", "last_activity_at", "idle_expires_at")
       VALUES ($1, $2, 'WEB', 'portal', 'Phone', 'UA', '10.0.0.1', '10.0.0.2', now(), now())`,
      [sid, id],
    );
    await pool.query(
      `INSERT INTO "reauth_tokens" ("id", "user_id", "session_id", "purpose", "token_hash", "expires_at")
       VALUES ($1, $2, $3, 'ACCOUNT_DELETION', $4, now())`,
      [randomUUID(), id, sid, randomBytes(32).toString('hex')],
    );
    await pool.query(
      `INSERT INTO "verification_codes" ("id", "user_id", "purpose", "code_hash", "expires_at")
       VALUES ($1, $2, 'PASSWORD_RESET', 'h', now())`,
      [randomUUID(), id],
    );
    await pool.query(
      `INSERT INTO "account_events" ("id", "user_id", "actor_id", "category", "type", "field", "old_value", "new_value", "ip", "device", "user_agent", "country")
       VALUES ($1, $2, $2, 'ACCOUNT', 'UPDATED', 'name', 'Ana', 'Ana Cruz', '10.0.0.1', 'Phone', 'UA', 'PH'),
              ($3, $2, $2, 'SIGN_IN', 'SIGNED_IN', NULL, NULL, NULL, '10.0.0.1', 'Phone', 'UA', 'PH'),
              ($4, $2, NULL, 'ACCOUNT', 'ROLE_CHANGED', 'roles', 'MECHANIC@VRMS', NULL, NULL, NULL, NULL, NULL)`,
      [randomUUID(), id, randomUUID(), randomUUID()],
    );
    await pool.query(
      `UPDATE "users" SET "deleted_at" = $2, "is_active" = false WHERE "id" = $1`,
      [id, new Date(Date.now() - ageDays * DAY)],
    );
    const requestId = randomUUID();
    await pool.query(
      `INSERT INTO "account_deletion_requests" ("id", "user_id", "status", "reason", "decided_at")
       VALUES ($1, $2, 'APPROVED', 'Leaving the company', now())`,
      [requestId, id],
    );
    return { id, email, sid, requestId };
  }

  const one = async <T extends pg.QueryResultRow>(
    sql: string,
    args: unknown[],
  ) => (await pool.query<T>(sql, args)).rows[0];

  it('erases a person past the grace period in every table (AC-15, AC-16)', async () => {
    const p = await deletedPerson(GRACE_DAYS + 1);
    const counts = await erasure.sweep();
    expect(counts).toEqual({ erased: 1, failed: 0 });

    const user = await one<Record<string, unknown>>(
      `SELECT "name", "email", "contact", "profile_picture", "password_hash", "email_verified", "password_set", "erased_at"
         FROM "users" WHERE "id" = $1`,
      [p.id],
    );
    expect(user).toMatchObject({
      name: 'Deleted user',
      email: `deleted-${p.id}@erased.invalid`,
      contact: null,
      profile_picture: null,
      password_hash: '!erased',
      email_verified: false,
      password_set: false,
    });
    expect(user.erased_at).not.toBeNull();

    expect(
      await one(
        `SELECT "status", "reason", "decision_note" FROM "account_deletion_requests" WHERE "id" = $1`,
        [p.requestId],
      ),
    ).toEqual({ status: 'ERASED', reason: null, decision_note: null });

    expect(
      await one(
        `SELECT "created_ip", "last_seen_ip", "user_agent", "device_name" FROM "sessions" WHERE "id" = $1`,
        [p.sid],
      ),
    ).toEqual({
      created_ip: null,
      last_seen_ip: null,
      user_agent: null,
      device_name: null,
    });
    expect(
      (
        await pool.query(`SELECT 1 FROM "reauth_tokens" WHERE "user_id" = $1`, [
          p.id,
        ])
      ).rowCount,
    ).toBe(0);
    expect(
      (
        await pool.query(
          `SELECT 1 FROM "verification_codes" WHERE "user_id" = $1`,
          [p.id],
        )
      ).rowCount,
    ).toBe(0);

    const events = (
      await pool.query<Record<string, unknown>>(
        `SELECT "type", "field", "old_value", "new_value", "ip", "device", "user_agent", "country"
           FROM "account_events" WHERE "user_id" = $1 ORDER BY "type"`,
        [p.id],
      )
    ).rows;
    expect(events.map((e) => String(e.type)).sort()).toEqual([
      'ERASED',
      'ROLE_CHANGED',
      'SIGNED_IN',
      'UPDATED',
    ]);
    for (const e of events) {
      expect([e.ip, e.device, e.user_agent, e.country]).toEqual([
        null,
        null,
        null,
        null,
      ]);
    }
    const rename = events.find((e) => e.type === 'UPDATED')!;
    expect([rename.old_value, rename.new_value]).toEqual([null, null]);
    // Not a personal field: kept
    expect(events.find((e) => e.type === 'ROLE_CHANGED')!.old_value).toBe(
      'MECHANIC@VRMS',
    );

    expect(sent.some((m) => m.to === p.email)).toBe(true);
  });

  it('writes exactly one feed row with erasedAt and rewrites the older ones (AC-17)', async () => {
    const p = await deletedPerson(GRACE_DAYS + 2);
    const before = Number(
      (
        await one<{ n: string }>(
          `SELECT count(*) AS n FROM "directory_changes" WHERE "user_id" = $1`,
          [p.id],
        )
      ).n,
    );
    await erasure.sweep();
    const rows = (
      await pool.query<{ type: string; snapshot: Record<string, unknown> }>(
        `SELECT "type", "snapshot" FROM "directory_changes" WHERE "user_id" = $1 ORDER BY "txid", "seq"`,
        [p.id],
      )
    ).rows;
    expect(rows).toHaveLength(before + 1);
    const last = rows[rows.length - 1];
    expect(last.type).toBe('updated');
    expect(last.snapshot.erasedAt).not.toBeNull();
    for (const row of rows) {
      expect(row.snapshot.name).toBe('Deleted user');
      expect(row.snapshot.email).toBe(`deleted-${p.id}@erased.invalid`);
      expect(row.snapshot.contact).toBeNull();
    }
    for (const row of rows.slice(0, -1)) {
      expect(row.snapshot.erasedAt ?? null).toBeNull();
    }
  });

  it('leaves a person still in grace alone, and frees the old email (AC-15, AC-18)', async () => {
    const young = await deletedPerson(GRACE_DAYS - 1);
    await erasure.sweep();
    expect(
      (
        await one<{ erased_at: Date | null }>(
          `SELECT "erased_at" FROM "users" WHERE "id" = $1`,
          [young.id],
        )
      ).erased_at,
    ).toBeNull();

    const old = await deletedPerson(GRACE_DAYS + 3);
    await erasure.sweep();
    await pool.query(
      `INSERT INTO "users" ("id", "name", "email", "password_hash", "updated_at") VALUES ($1, 'New', $2, 'x', CURRENT_TIMESTAMP)`,
      [randomUUID(), old.email],
    );
  });

  it('refuses any other change to account_events, even with the erasure setting on (AC-16)', async () => {
    const p = await deletedPerson(GRACE_DAYS - 5);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(`SELECT set_config('welinc.erasure', 'on', true)`);
      await expect(
        client.query(
          `UPDATE "account_events" SET "reason" = 'X' WHERE "user_id" = $1`,
          [p.id],
        ),
      ).rejects.toThrow(/append only/);
      await client.query('ROLLBACK');
      await client.query('BEGIN');
      await client.query(`SELECT set_config('welinc.erasure', 'on', true)`);
      // A roles value is not personal: it may not be blanked
      await expect(
        client.query(
          `UPDATE "account_events" SET "old_value" = NULL WHERE "user_id" = $1 AND "field" = 'roles'`,
          [p.id],
        ),
      ).rejects.toThrow(/append only/);
      await client.query('ROLLBACK');
      // Without the setting, even a blanking update raises
      await expect(
        client.query(
          `UPDATE "account_events" SET "ip" = NULL WHERE "user_id" = $1`,
          [p.id],
        ),
      ).rejects.toThrow(/append only/);
    } finally {
      client.release();
    }
  });

  it('allows one PENDING request per person (key invariant)', async () => {
    const id = randomUUID();
    await pool.query(
      `INSERT INTO "users" ("id", "name", "email", "password_hash", "updated_at") VALUES ($1, 'P', $2, 'x', CURRENT_TIMESTAMP)`,
      [id, `pending-${id.slice(0, 8)}@fixture.test`],
    );
    await pool.query(
      `INSERT INTO "account_deletion_requests" ("id", "user_id") VALUES ($1, $2)`,
      [randomUUID(), id],
    );
    await expect(
      pool.query(
        `INSERT INTO "account_deletion_requests" ("id", "user_id") VALUES ($1, $2)`,
        [randomUUID(), id],
      ),
    ).rejects.toThrow(/account_deletion_requests_one_pending/);
  });
});
