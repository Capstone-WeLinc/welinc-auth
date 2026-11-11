import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Cron, CronExpression } from '@nestjs/schedule';
import {
  AccountEventType,
  Prisma,
  SessionEndReason,
  SessionKind,
} from '@prisma/client';
import type { Env } from '../../config/env';
import { PrismaService } from '../../shared/prisma.service';
import { AccountEventsService } from '../events/account-events.service';
import { deviceLabel } from './device-label';
import { CODE_RETENTION_MS } from '../codes/code-config';
import { REAUTH_KEEP_MS } from '../reauth/password-check.service';
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
  verificationCodesDeleted: number;
  /** Spec 0012: reauth tokens older than 24 hours. */
  reauthTokensDeleted: number;
  /** Spec 0011, AC-9: sign in, session and code events past retention. */
  eventsDeleted: number;
};

type Tx = Prisma.TransactionClient;

type EndedRow = {
  id: string;
  user_id: string;
  end_reason: SessionEndReason;
  login_client_id: string;
  kind: SessionKind;
  device_name: string | null;
  user_agent: string | null;
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
    private readonly events: AccountEventsService,
    private readonly config: ConfigService<Env, true>,
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
          // Spec 0009, AC-1: every emailed code row (and its new_email) goes after 24 hours
          verificationCodesDeleted: await this.batches(
            (limit) => tx.$executeRaw`
              DELETE FROM "verification_codes" WHERE "id" IN (SELECT "id" FROM "verification_codes"
                WHERE "created_at" < ${new Date(now.getTime() - CODE_RETENTION_MS)} LIMIT ${limit})`,
          ),
          // Spec 0012: used or not, a reauth token row goes after 24 hours
          reauthTokensDeleted: await this.batches(
            (limit) => tx.$executeRaw`
              DELETE FROM "reauth_tokens" WHERE "id" IN (SELECT "id" FROM "reauth_tokens"
                WHERE "created_at" < ${new Date(now.getTime() - REAUTH_KEEP_MS)} LIMIT ${limit})`,
          ),
        };
      },
      { timeout: 120_000, maxWait: 10_000 },
    );
    if (counts) {
      // Only the replica that held the lock; each batch its own transaction (AC-9)
      const eventsDeleted = await this.sweepEvents(now);
      this.logger.log(
        `session sweep ended=${counts.ended} graces=${counts.gracesCleared} tokens=${counts.tokensDeleted} sessions=${counts.sessionsDeleted} requests=${counts.requestsDeleted} codes=${counts.codesDeleted} verificationCodes=${counts.verificationCodesDeleted} reauthTokens=${counts.reauthTokensDeleted} events=${eventsDeleted}`,
      );
      return { ...counts, eventsDeleted };
    } else {
      this.logger.log('session sweep skipped: another replica holds the lock');
    }
    return null;
  }

  /**
   * Spec 0011, AC-9: deletes non ACCOUNT events older than ACCOUNT_EVENT_RETENTION_DAYS, 1,000 at
   * a time. Each batch is its own transaction that first turns `welinc.event_sweep` on for that
   * transaction only, the one way past the append only trigger. ACCOUNT rows are never deleted.
   */
  async sweepEvents(now = new Date()): Promise<number> {
    const days = this.config.get('ACCOUNT_EVENT_RETENTION_DAYS', {
      infer: true,
    });
    const before = new Date(now.getTime() - days * 86_400_000);
    let total = 0;
    for (;;) {
      const deleted = await this.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('welinc.event_sweep', 'on', true)`;
        return tx.$executeRaw`
          DELETE FROM "account_events" WHERE "id" IN (SELECT "id" FROM "account_events"
            WHERE "category" <> 'ACCOUNT' AND "created_at" < ${before}
            LIMIT ${SWEEP_BATCH})`;
      });
      total += deleted;
      if (deleted < SWEEP_BATCH) return total;
    }
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
        RETURNING "id", "user_id", "end_reason", "login_client_id", "kind", "device_name", "user_agent"`;
      if (rows.length === 0) break;
      const ids = rows.map((row) => row.id);
      await tx.$executeRaw`
        UPDATE "refresh_tokens" SET "used_at" = ${now}
        WHERE "session_id" = ANY(${ids}::uuid[]) AND "used_at" IS NULL`;
      // Spec 0011, AC-4: one SESSION_ENDED each, nobody acting, no address, the session's device
      await this.events.recordMany(
        tx,
        rows.map((row) => ({
          userId: row.user_id,
          type: AccountEventType.SESSION_ENDED,
          reason: row.end_reason,
          sessionId: row.id,
          clientId: row.login_client_id,
          meta: {
            ip: null,
            device: deviceLabel({
              kind: row.kind,
              userAgent: row.user_agent,
              deviceName: row.device_name,
            }),
            userAgent: row.user_agent,
          },
        })),
      );
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
