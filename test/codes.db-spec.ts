import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import { Logger } from '@nestjs/common';
import { PrismaClient, VerificationPurpose } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import { randomBytes, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import pg, { Client } from 'pg';
import { CodeService } from '../src/auth/codes/code.service';
import { MailFailedError } from '../src/auth/codes/code-errors';
import type { MailService } from '../src/shared/mail.service';
import type { PrismaService } from '../src/shared/prisma.service';

// Suite spec 0009, AC-1 to AC-5: the code service against a real database, since its rules live
// in row locks, transactions and timestamps. A throwaway database gets every migration; each test
// works on its own user. Run with `npm run test:db` (locally: `docker exec welinc_auth_service
// npm run test:db`).

const MIGRATIONS = join(__dirname, '..', 'prisma', 'migrations');
const folders = readdirSync(MIGRATIONS, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const serverUrl = process.env.DATABASE_URL;
const dbName = `welinc_auth_codetest_${randomBytes(4).toString('hex')}`;

function urlFor(database: string): string {
  const url = new URL(serverUrl!);
  url.pathname = `/${database}`;
  url.search = '';
  return url.toString();
}

const { PASSWORD_SETUP, PASSWORD_RESET, SIGN_IN, EMAIL_CHANGE } =
  VerificationPurpose;
const PASSWORD = [PASSWORD_SETUP, PASSWORD_RESET] as const;
const MINUTE = 60_000;

(serverUrl ? describe : describe.skip)('spec 0009 code service', () => {
  let admin: Client;
  let pool: pg.Pool;
  let prisma: PrismaClient;
  let codes: CodeService;
  const sendMail = jest.fn<(options: { text: string }) => Promise<void>>();
  let userId: string;

  /** The code in the last email sent. */
  const lastCode = () =>
    /\b(\d{6})\b/.exec(sendMail.mock.calls.at(-1)![0].text)![1];

  const issue = (
    purpose: VerificationPurpose,
    extra: { challengeHash?: string; newEmail?: string } = {},
  ) =>
    codes.issue({
      userId,
      purpose,
      ...extra,
      mail: {
        to: 'pedro@fixture.test',
        build: (code) => ({ subject: 's', text: `code ${code}`, html: code }),
      },
    });

  const rows = () =>
    prisma.verificationCode.findMany({
      where: { userId },
      orderBy: { createdAt: 'asc' },
    });

  /** Moves every row of the user back in time, so the 60 s wait or the hour has passed. */
  const age = (ms: number) =>
    pool.query(
      `UPDATE verification_codes SET created_at = created_at - ($2 || ' milliseconds')::interval
       WHERE user_id = $1`,
      [userId, String(ms)],
    );

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
    codes = new CodeService(
      prisma as unknown as PrismaService,
      { sendMail } as unknown as MailService,
    );
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  afterAll(async () => {
    await prisma?.$disconnect();
    await pool?.end();
    await admin?.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
    await admin?.end();
  });

  beforeEach(async () => {
    sendMail.mockReset();
    sendMail.mockResolvedValue(undefined);
    userId = randomUUID();
    await prisma.user.create({
      data: {
        id: userId,
        name: 'Pedro',
        email: `${userId}@fixture.test`,
        passwordHash: 'x',
      },
    });
  });

  describe('issue', () => {
    // covers: AC-1, AC-3
    it('stores only an argon2 hash and the lifetime of the purpose', async () => {
      const before = Date.now();
      const reset = await issue(PASSWORD_RESET);
      const code = lastCode();
      const [row] = await rows();

      expect(reset).toMatchObject({ kind: 'sent', resendAfter: 60 });
      expect(row.codeHash).toMatch(/^\$argon2/);
      expect(row.codeHash).not.toContain(code);
      expect(row.expiresAt.getTime() - before).toBeGreaterThanOrEqual(
        10 * MINUTE - 1000,
      );
      expect(row.expiresAt.getTime() - before).toBeLessThan(10 * MINUTE + 5000);

      await age(2 * MINUTE);
      const setup = await issue(PASSWORD_SETUP);
      expect(setup.kind).toBe('sent');
      const setupRow = (await rows()).at(-1)!;
      expect(setupRow.expiresAt.getTime() - setupRow.createdAt.getTime()).toBe(
        60 * MINUTE,
      );
    });

    // covers: AC-2
    it('retires the live code of the same family only', async () => {
      await issue(SIGN_IN);
      await issue(PASSWORD_SETUP);
      await age(2 * MINUTE);
      await issue(PASSWORD_RESET);

      const all = await rows();
      const live = all.filter((r) => r.usedAt === null).map((r) => r.purpose);
      expect(live.sort()).toEqual([PASSWORD_RESET, SIGN_IN].sort());
    });

    // covers: AC-5 (the wait binds every sender; nothing is replaced)
    it('refuses a second send inside 60 s, sends nothing and keeps the live code', async () => {
      await issue(PASSWORD_SETUP);
      const result = await issue(PASSWORD_RESET);

      expect(result).toMatchObject({ kind: 'limited', reason: 'wait' });
      expect(result.kind === 'limited' && result.retryAfter).toBeGreaterThan(
        55,
      );
      expect(sendMail).toHaveBeenCalledTimes(1);
      const all = await rows();
      expect(all).toHaveLength(1);
      expect(all[0].usedAt).toBeNull();
    });

    // covers: AC-5 (5 an hour, counted from every row, used ones too)
    it('refuses a 6th send in the hour, until the oldest of the last 5 turns an hour old', async () => {
      for (let i = 0; i < 5; i++) {
        await issue(SIGN_IN);
        await age(10 * MINUTE);
      }
      // The rows are now 50, 40, 30, 20 and 10 minutes old
      const result = await issue(SIGN_IN);

      expect(result).toMatchObject({ kind: 'limited', reason: 'hourly' });
      const retryAfter = result.kind === 'limited' ? result.retryAfter : 0;
      expect(retryAfter).toBeGreaterThan(9 * 60);
      expect(retryAfter).toBeLessThanOrEqual(10 * 60);
    });

    // covers: AC-5 (a failed send counts toward no limit and the earlier code still works)
    it('deletes the new row and brings back the retired one when the mail fails', async () => {
      await issue(EMAIL_CHANGE, { newEmail: 'a@fixture.test' });
      const first = lastCode();
      await age(2 * MINUTE);
      sendMail.mockRejectedValueOnce(new Error('SMTP down'));

      await expect(
        issue(EMAIL_CHANGE, { newEmail: 'b@fixture.test' }),
      ).rejects.toBeInstanceOf(MailFailedError);

      const all = await rows();
      expect(all).toHaveLength(1);
      expect(all[0]).toMatchObject({
        usedAt: null,
        newEmail: 'a@fixture.test',
      });
      const check = await codes.check({
        target: { userId, purposes: [EMAIL_CHANGE] },
        code: first,
        consume: false,
      });
      expect(check.kind).toBe('right');
      // Nothing counted: another send is allowed at once
      await expect(
        issue(EMAIL_CHANGE, { newEmail: 'b@fixture.test' }),
      ).resolves.toMatchObject({ kind: 'sent' });
    });

    // covers: AC-10 (the ticket moves to the new row, and back when the send fails)
    it('moves a sign in ticket to the new code, and back on a failed send', async () => {
      const ticket = 'a'.repeat(64);
      await issue(SIGN_IN, { challengeHash: ticket });
      await age(2 * MINUTE);
      await issue(SIGN_IN, { challengeHash: ticket });

      let all = await rows();
      expect(all.map((r) => [r.challengeHash, r.usedAt === null])).toEqual([
        [null, false],
        [ticket, true],
      ]);

      await age(2 * MINUTE);
      sendMail.mockRejectedValueOnce(new Error('SMTP down'));
      await expect(
        issue(SIGN_IN, { challengeHash: ticket }),
      ).rejects.toBeInstanceOf(MailFailedError);
      all = await rows();
      expect(all).toHaveLength(2);
      expect(all[1]).toMatchObject({ challengeHash: ticket, usedAt: null });
    });
  });

  describe('check', () => {
    // covers: AC-4
    it('counts wrong tries, retires the code on the 5th and then refuses even the right one', async () => {
      await issue(PASSWORD_RESET);
      const code = lastCode();
      const wrong = code === '000000' ? '111111' : '000000';
      const target = { userId, purposes: PASSWORD };

      for (const left of [4, 3, 2, 1]) {
        await expect(
          codes.check({ target, code: wrong, consume: true }),
        ).resolves.toEqual({ kind: 'wrong', attemptsLeft: left });
      }
      await expect(
        codes.check({ target, code: wrong, consume: true }),
      ).resolves.toEqual({ kind: 'dead', reason: 'tries' });
      await expect(
        codes.check({ target, code, consume: true }),
      ).resolves.toMatchObject({ kind: 'dead' });
      const [row] = await rows();
      expect(row.attempts).toBe(5);
      expect(row.usedAt).not.toBeNull();
    });

    // covers: AC-4 (row lock: two parallel guesses count as two)
    it('counts two parallel wrong guesses as exactly two', async () => {
      await issue(SIGN_IN);
      const wrong = lastCode() === '000000' ? '111111' : '000000';
      const target = { userId, purposes: [SIGN_IN] };

      const results = await Promise.all([
        codes.check({ target, code: wrong, consume: true }),
        codes.check({ target, code: wrong, consume: true }),
      ]);

      expect(results.map((r) => r.kind)).toEqual(['wrong', 'wrong']);
      expect(
        results.map((r) => (r.kind === 'wrong' ? r.attemptsLeft : -1)).sort(),
      ).toEqual([3, 4]);
      const [row] = await rows();
      expect(row.attempts).toBe(2);
    });

    // covers: AC-3, AC-4
    it('refuses an expired code even when it is right', async () => {
      await issue(SIGN_IN);
      const code = lastCode();
      await pool.query(
        `UPDATE verification_codes SET expires_at = now() - interval '1 second' WHERE user_id = $1`,
        [userId],
      );

      await expect(
        codes.check({
          target: { userId, purposes: [SIGN_IN] },
          code,
          consume: true,
        }),
      ).resolves.toEqual({ kind: 'dead', reason: 'expired' });
    });

    // covers: AC-14 (verify-otp never uses the code up)
    it('keeps the code live when consume is off, and uses it once when on', async () => {
      await issue(PASSWORD_RESET);
      const code = lastCode();
      const target = { userId, purposes: PASSWORD };

      expect((await codes.check({ target, code, consume: false })).kind).toBe(
        'right',
      );
      expect((await codes.check({ target, code, consume: true })).kind).toBe(
        'right',
      );
      expect((await codes.check({ target, code, consume: true })).kind).toBe(
        'dead',
      );
    });

    it('finds a sign in code by its ticket, and runs onRight in the same transaction', async () => {
      const ticket = 'b'.repeat(64);
      await issue(SIGN_IN, { challengeHash: ticket });
      const code = lastCode();

      const result = await codes.check({
        target: { challengeHash: ticket },
        code,
        consume: true,
        onRight: async (tx, row) => {
          await tx.user.update({
            where: { id: row.userId },
            data: { emailVerified: true },
          });
          return 'done';
        },
      });

      expect(result).toMatchObject({ kind: 'right', value: 'done' });
      const user = await prisma.user.findUniqueOrThrow({
        where: { id: userId },
      });
      expect(user.emailVerified).toBe(true);
    });

    it('counts nothing when the precheck refuses', async () => {
      await issue(SIGN_IN);
      const wrong = lastCode() === '000000' ? '111111' : '000000';

      await expect(
        codes.check({
          target: { userId, purposes: [SIGN_IN] },
          code: wrong,
          consume: true,
          precheck: () => Promise.reject(new Error('locked')),
        }),
      ).rejects.toThrow('locked');
      const [row] = await rows();
      expect(row.attempts).toBe(0);
    });
  });

  // covers: AC-2
  it('retires every live code of the user on an email change', async () => {
    await issue(SIGN_IN);
    await issue(PASSWORD_SETUP);
    await issue(EMAIL_CHANGE, { newEmail: 'n@fixture.test' });

    await prisma.$transaction((tx) => codes.retireAll(tx, userId));

    expect((await rows()).every((r) => r.usedAt !== null)).toBe(true);
    expect(await codes.liveCode(userId, [EMAIL_CHANGE])).toBeNull();
  });
});
