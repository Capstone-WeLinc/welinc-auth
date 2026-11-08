import { Inject, Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { SESSION_SETTINGS, type SessionSettings } from './session-config';

/** Rows changed per statement, so no single statement holds a large lock (AC-37). */
export const SWEEP_BATCH = 1000;

/** The key of the transaction scoped advisory lock: one replica sweeps at a time (AC-37). */
export const SWEEP_LOCK_KEY = 3_003_001;

/** Refresh token rows are kept this long after their session ended (AC-37). */
const TOKEN_KEEP_MS = 86_400_000;

export type SweepCounts = {
  ended: number;
  gracesCleared: number;
  tokensDeleted: number;
  sessionsDeleted: number;
  requestsDeleted: number;
  codesDeleted: number;
};

type Tx = Prisma.TransactionClient;

type EndedRow = {
  id: string;
  user_id: string;
  end_reason: string;
  login_client_id: string;
};

/**
 * The hourly tidy up (spec 0003, AC-37). Correctness never waits on it: every check already
 * ends a session past its cutoff on the spot (AC-3). It runs inside one transaction that first
 * takes `pg_try_advisory_xact_lock`, and skips the run when another replica holds it.
 */
@Injectable()
export class SessionSweeper {
  private readonly logger = new Logger('SessionSweep');

  constructor(
    private readonly prisma: PrismaService,
    @Inject(SESSION_SETTINGS) private readonly settings: SessionSettings,
  ) {}

  @Cron(CronExpression.EVERY_HOUR, { name: 'session-sweep' })
  async hourly(): Promise<void> {
    try {
      await this.sweep();
    } catch (error) {
      this.logger.error(`session sweep failed: ${(error as Error).message}`);
    }
  }

  /** One sweep. Answers null when another replica holds the lock. */
  async sweep(now = new Date()): Promise<SweepCounts | null> {
    const counts = await this.prisma.$transaction(
      async (tx) => {
        const [lock] = await tx.$queryRaw<{ locked: boolean }[]>`
          SELECT pg_try_advisory_xact_lock(${SWEEP_LOCK_KEY}::bigint) AS "locked"`;
        if (!lock?.locked) return null;
        return {
          ended: await this.endPastCutoff(tx, now),
          gracesCleared: await this.batches(
            (limit) => tx.$executeRaw`
              UPDATE "refresh_tokens" SET "grace_cipher" = NULL
              WHERE "id" IN (SELECT "id" FROM "refresh_tokens"
                WHERE "grace_cipher" IS NOT NULL AND "grace_until" < ${now} LIMIT ${limit})`,
          ),
          tokensDeleted: await this.batches(
            (limit) => tx.$executeRaw`
              DELETE FROM "refresh_tokens" WHERE "id" IN (
                SELECT t."id" FROM "refresh_tokens" t JOIN "sessions" s ON s."id" = t."session_id"
                WHERE s."ended_at" < ${new Date(now.getTime() - TOKEN_KEEP_MS)} LIMIT ${limit})`,
          ),
          sessionsDeleted: await this.batches(
            (limit) => tx.$executeRaw`
              DELETE FROM "sessions" WHERE "id" IN (SELECT "id" FROM "sessions"
                WHERE "ended_at" < ${new Date(now.getTime() - this.settings.retentionDays * 86_400_000)}
                LIMIT ${limit})`,
          ),
          requestsDeleted: await this.batches(
            (limit) => tx.$executeRaw`
              DELETE FROM "login_requests" WHERE "id_hash" IN (SELECT "id_hash" FROM "login_requests"
                WHERE "expires_at" < ${now} LIMIT ${limit})`,
          ),
          codesDeleted: await this.batches(
            (limit) => tx.$executeRaw`
              DELETE FROM "authorization_codes" WHERE "code_hash" IN (SELECT "code_hash" FROM "authorization_codes"
                WHERE "expires_at" < ${now} LIMIT ${limit})`,
          ),
        };
      },
      { timeout: 120_000, maxWait: 10_000 },
    );
    if (counts) {
      this.logger.log(
        `session sweep ended=${counts.ended} graces=${counts.gracesCleared} tokens=${counts.tokensDeleted} sessions=${counts.sessionsDeleted} requests=${counts.requestsDeleted} codes=${counts.codesDeleted}`,
      );
    } else {
      this.logger.log('session sweep skipped: another replica holds the lock');
    }
    return counts;
  }

  /**
   * Ends live sessions past a cutoff, 1,000 at a time: absolute first (`MAX_AGE`), else `IDLE`,
   * as `cutoffReason` decides. Their SSO handles and unused refresh tokens go with them (AC-5).
   */
  private async endPastCutoff(tx: Tx, now: Date): Promise<number> {
    let total = 0;
    for (;;) {
      const rows = await tx.$queryRaw<EndedRow[]>`
        UPDATE "sessions" SET
          "ended_at" = ${now},
          "end_reason" = (CASE WHEN "absolute_expires_at" IS NOT NULL AND "absolute_expires_at" <= ${now}
            THEN 'MAX_AGE' ELSE 'IDLE' END)::"SessionEndReason",
          "sso_handle_hash" = NULL
        WHERE "id" IN (SELECT "id" FROM "sessions" WHERE "ended_at" IS NULL
          AND ("idle_expires_at" <= ${now} OR "absolute_expires_at" <= ${now})
          LIMIT ${SWEEP_BATCH})
        RETURNING "id", "user_id", "end_reason", "login_client_id"`;
      if (rows.length === 0) break;
      const ids = rows.map((row) => row.id);
      await tx.$executeRaw`
        UPDATE "refresh_tokens" SET "used_at" = ${now}
        WHERE "session_id" = ANY(${ids}::uuid[]) AND "used_at" IS NULL`;
      // AC-39: sid, user, reason and client only
      for (const row of rows) {
        this.logger.log(
          `session ended sid=${row.id} user=${row.user_id} reason=${row.end_reason} client=${row.login_client_id}`,
        );
      }
      total += rows.length;
      if (rows.length < SWEEP_BATCH) break;
    }
    return total;
  }

  /** Repeats one batched statement until it changes fewer rows than a batch. */
  private async batches(
    run: (limit: number) => Promise<number>,
  ): Promise<number> {
    let total = 0;
    for (;;) {
      const changed = await run(SWEEP_BATCH);
      total += changed;
      if (changed < SWEEP_BATCH) return total;
    }
  }
}
