import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AccountEventType, DeletionRequestStatus } from '@prisma/client';
import * as fs from 'fs/promises';
import * as path from 'path';
import type { Env } from '../../config/env';
import { MailService } from '../../shared/mail.service';
import { PrismaService } from '../../shared/prisma.service';
import { AccountEventsService } from '../events/account-events.service';
import { lockAccount } from '../user-changes';
import { dataErasedEmail } from './deletion-emails';

/** AC-15: at most this many people per hourly run. */
export const ERASURE_BATCH = 100;

/** AC-15: what an erased person becomes. */
export const ERASED_NAME = 'Deleted user';
/** Never a valid argon2 string, so every password check fails (Value sourcing). */
export const ERASED_HASH = '!erased';
export const erasedEmail = (userId: string) =>
  `deleted-${userId}@erased.invalid`;

/** Account event fields whose old and new values are personal data (AC-16). */
export const PERSONAL_FIELDS = ['name', 'email', 'contact', 'profilePicture'];

const DAY_MS = 86_400_000;

export type ErasureCounts = { erased: number; failed: number };

/**
 * Spec 0012, AC-15 to AC-19: every soft deleted account past `ACCOUNT_ERASURE_GRACE_DAYS` is
 * erased to "Deleted user", one transaction per person, so one failure rolls back only that
 * person and is tried again next hour. Runs from the hourly sweep, only on the replica that held
 * its lock.
 */
@Injectable()
export class ErasureService {
  private readonly logger = new Logger('AccountErasure');

  constructor(
    private readonly prisma: PrismaService,
    private readonly events: AccountEventsService,
    private readonly mail: MailService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  async sweep(now = new Date()): Promise<ErasureCounts> {
    const days = this.config.get('ACCOUNT_ERASURE_GRACE_DAYS', { infer: true });
    const cutoff = new Date(now.getTime() - days * DAY_MS);
    // The old address and picture are read before each transaction (Value sourcing)
    const due = await this.prisma.user.findMany({
      where: { deletedAt: { lte: cutoff }, erasedAt: null },
      orderBy: [{ deletedAt: 'asc' }, { id: 'asc' }],
      take: ERASURE_BATCH,
      select: { id: true, email: true, profilePicture: true },
    });

    const counts: ErasureCounts = { erased: 0, failed: 0 };
    for (const person of due) {
      try {
        const done = await this.eraseOne(person.id, cutoff, now);
        if (!done) continue;
        counts.erased += 1;
      } catch (error) {
        counts.failed += 1;
        // AC-19: logged with the user id only, no email, tried again next hour
        this.logger.error(
          `erasure failed user=${person.id}: ${error instanceof Error ? error.message : 'unknown error'}`,
        );
        continue;
      }
      // After commit: a last email to the old address and the picture file (never retried)
      await this.sendErasedEmail(person.id, person.email);
      await this.removePicture(person.id, person.profilePicture);
      this.logger.log(`account erased user=${person.id}`);
    }
    return counts;
  }

  /** One person in one transaction. False when someone restored them meanwhile. */
  async eraseOne(userId: string, cutoff: Date, now: Date): Promise<boolean> {
    return this.prisma.$transaction(
      async (tx) => {
        // AC-16: the first statement, the one way past the append only triggers
        await tx.$queryRaw`SELECT set_config('welinc.erasure', 'on', true)`;
        await lockAccount(tx, userId);
        const still = await tx.user.findFirst({
          where: { id: userId, deletedAt: { lte: cutoff }, erasedAt: null },
          select: { id: true },
        });
        if (!still) return false;

        await tx.user.update({
          where: { id: userId },
          data: {
            name: ERASED_NAME,
            email: erasedEmail(userId),
            contact: null,
            profilePicture: null,
            passwordHash: ERASED_HASH,
            emailVerified: false,
            passwordSet: false,
            failedLoginAttempts: 0,
            lockedAt: null,
            erasedAt: now,
          },
        });

        await tx.accountDeletionRequest.updateMany({
          where: { userId, status: DeletionRequestStatus.APPROVED },
          data: {
            status: DeletionRequestStatus.ERASED,
            erasedAt: now,
            reason: null,
            decisionNote: null,
          },
        });
        // Older requests keep no reason the person typed; an admin's note stays (data model)
        await tx.accountDeletionRequest.updateMany({
          where: { userId, reason: { not: null } },
          data: { reason: null },
        });

        // AC-15: the person's sessions keep their rows, without address or device
        await tx.$executeRaw`
          UPDATE "sessions"
             SET "created_ip" = NULL, "last_seen_ip" = NULL, "user_agent" = NULL, "device_name" = NULL
           WHERE "user_id" = ${userId}::uuid`;
        await tx.$executeRaw`
          DELETE FROM "refresh_tokens"
           WHERE "session_id" IN (SELECT "id" FROM "sessions" WHERE "user_id" = ${userId}::uuid)`;
        await tx.reauthToken.deleteMany({ where: { userId } });
        await tx.verificationCode.deleteMany({ where: { userId } });
        // login_requests hold no user: they belong to a browser before sign in, nothing to delete

        // AC-16: the person's own events lose their personal columns; rows stay
        await tx.$executeRaw`
          UPDATE "account_events"
             SET "ip" = NULL, "device" = NULL, "user_agent" = NULL,
                 "country" = NULL, "network" = NULL, "asn" = NULL,
                 "old_value" = CASE WHEN "field" = ANY(${PERSONAL_FIELDS}::text[]) THEN NULL ELSE "old_value" END,
                 "new_value" = CASE WHEN "field" = ANY(${PERSONAL_FIELDS}::text[]) THEN NULL ELSE "new_value" END
           WHERE "user_id" = ${userId}::uuid`;

        // AC-17: earlier feed snapshots get the erased values; erasedAt stays out of them, so the
        // commit time trigger writes exactly one `updated` row with erasedAt set
        await tx.$executeRaw`
          UPDATE "directory_changes"
             SET "snapshot" = "snapshot" || jsonb_build_object(
                   'name', ${ERASED_NAME}::text,
                   'email', ${erasedEmail(userId)}::text,
                   'contact', NULL,
                   'profilePicture', NULL)
           WHERE "user_id" = ${userId}::uuid AND "txid" <> pg_current_xact_id()`;

        await this.events.record(tx, {
          userId,
          actorId: null,
          type: AccountEventType.ERASED,
        });
        return true;
      },
      { timeout: 60_000, maxWait: 10_000 },
    );
  }

  private async sendErasedEmail(userId: string, to: string): Promise<void> {
    try {
      await this.mail.sendMail({
        to,
        ...dataErasedEmail(),
        tag: `user=${userId} purpose=ACCOUNT_ERASED`,
      });
    } catch (error) {
      this.logger.error(
        `erased email failed user=${userId}: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }

  /** The stored `/uploads/profiles/<file>`; only a bare file name in that folder is removed. */
  private async removePicture(
    userId: string,
    stored: string | null,
  ): Promise<void> {
    if (!stored) return;
    const file = path.basename(stored);
    if (!file || file !== stored.split('/').pop()) return;
    try {
      await fs.rm(path.resolve('uploads', 'profiles', file), { force: true });
    } catch (error) {
      this.logger.error(
        `picture removal failed user=${userId}: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }
}
