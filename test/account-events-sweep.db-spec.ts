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
import { AccountEventsService } from '../src/auth/events/account-events.service';
import { SessionSweeper } from '../src/auth/sessions/session-sweeper';
import type { SessionSettings } from '../src/auth/sessions/session-config';
import { noGeo } from '../src/auth/testing/geo.fake';
import type { PrismaService } from '../src/shared/prisma.service';

// Spec 0011, AC-4 and AC-9 against a real database: the hourly sweep deletes only non ACCOUNT
// events past retention, through the append only trigger, and ends idle sessions with one
// SESSION_ENDED each. Run with `npm run test:db`.

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const serverUrl = process.env.DATABASE_URL;
const dbName = `welinc_auth_sweeptest_${randomBytes(4).toString('hex')}`;

function urlFor(database: string): string {
  const url = new URL(serverUrl!);
  url.pathname = `/${database}`;
  url.search = '';
  return url.toString();
}

const DAY = 86_400_000;

(serverUrl ? describe : describe.skip)('spec 0011 event sweep', () => {
  let admin: Client;
  let pool: pg.Pool;
  let prisma: PrismaClient;
  let sweeper: SessionSweeper;
  const userId = randomUUID();

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
      get: () => 365,
    } as unknown as ConfigService<Env, true>;
    sweeper = new SessionSweeper(
      db,
      { retentionDays: 90 } as SessionSettings,
      new AccountEventsService(db, noGeo),
      config,
    );
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    await pool.query(
      `INSERT INTO "users" ("id", "name", "email", "password_hash", "updated_at")
       VALUES ($1, 'Sweep', 'sweep@fixture.test', 'x', CURRENT_TIMESTAMP)`,
      [userId],
    );
    await pool.query(
      `INSERT INTO "oauth_clients" ("id", "kind", "grants", "user_audiences", "updated_at")
       VALUES ('portal', 'FIRST_PARTY_WEB', '{sso}', '{}', CURRENT_TIMESTAMP)`,
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

  const event = (category: string, type: string, ageDays: number) =>
    pool.query(
      `INSERT INTO "account_events" ("id", "user_id", "category", "type", "created_at")
       VALUES ($1, $2, $3::"AccountEventCategory", $4::"AccountEventType", $5)`,
      [
        randomUUID(),
        userId,
        category,
        type,
        new Date(Date.now() - ageDays * DAY),
      ],
    );
  const types = async () =>
    (
      await pool.query<{ type: string }>(
        `SELECT "type" FROM "account_events" WHERE "user_id" = $1 ORDER BY "type"`,
        [userId],
      )
    ).rows.map((r) => r.type);

  it('deletes only non ACCOUNT events past retention (AC-9)', async () => {
    await event('SIGN_IN', 'SIGNED_IN', 400);
    await event('CODE', 'CODE_SENT', 400);
    await event('SIGN_IN', 'SIGN_IN_FAILED', 10);
    await event('ACCOUNT', 'CREATED', 400);

    expect(await sweeper.sweepEvents()).toBe(2);
    expect((await types()).sort()).toEqual(['CREATED', 'SIGN_IN_FAILED']);
  });

  it('writes one SESSION_ENDED for a session the sweep ends (AC-4)', async () => {
    const sid = randomUUID();
    const past = new Date(Date.now() - DAY);
    await pool.query(
      `INSERT INTO "sessions" ("id", "user_id", "kind", "login_client_id", "user_agent", "last_activity_at", "idle_expires_at")
       VALUES ($1, $2, 'WEB', 'portal', 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0', $3, $3)`,
      [sid, userId, past],
    );
    const counts = await sweeper.sweep();
    expect(counts?.ended).toBe(1);
    const { rows } = await pool.query<{
      type: string;
      reason: string;
      actor_id: string | null;
      device: string;
    }>(
      `SELECT "type", "reason", "actor_id", "device" FROM "account_events" WHERE "session_id" = $1`,
      [sid],
    );
    expect(rows).toEqual([
      {
        type: 'SESSION_ENDED',
        reason: 'IDLE',
        actor_id: null,
        device: 'Chrome on Windows',
      },
    ]);
  });
});
