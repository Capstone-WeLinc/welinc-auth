import { Injectable, Logger } from '@nestjs/common';
import {
  AccountEventType,
  Prisma,
  VerificationPurpose,
  type VerificationCode,
} from '@prisma/client';
import * as argon2 from 'argon2';
import * as crypto from 'crypto';
import { MailService } from '../../shared/mail.service';
import { PrismaService } from '../../shared/prisma.service';
import { lockAccount } from '../user-changes';
import { AccountEventsService } from '../events/account-events.service';
import { NO_META, type RequestMeta } from '../events/request-meta';
import {
  CODE_LIFETIME_MS,
  HOUR_MS,
  MAX_ATTEMPTS,
  RESEND_WAIT_MS,
  familyOf,
} from './code-config';
import type { Email } from './code-emails';
import { MailFailedError } from './code-errors';
import { attemptsLeft, sendDecision } from './send-limit';

type Tx = Prisma.TransactionClient;

/** A 6 digit code from a secure random source (never `Math.random`), AC-1. */
export function newOtp(): string {
  return crypto.randomInt(100_000, 1_000_000).toString();
}

export type IssueInput = {
  userId: string;
  purpose: VerificationPurpose;
  /** EMAIL_CHANGE only: the lowercased address being confirmed. */
  newEmail?: string;
  /**
   * SIGN_IN only: the ticket hash the new row carries. Taken off whichever row holds it first
   * (a resend keeps the same ticket, AC-10), and put back if the send fails.
   */
  challengeHash?: string;
  /** Who gets the code, and the email around it. */
  mail: { to: string; build: (code: string) => Email };
  /**
   * Runs inside the locked transaction when the limits refuse a send, with the family's live code
   * (AC-8 moves the new ticket onto it). Nothing is sent and the live code stays.
   */
  onLimited?: (tx: Tx, live: VerificationCode | null) => Promise<void>;
  /** Spec 0011, AC-5: who asked for the code (an admin's send), the user when left out. */
  actorId?: string;
  /** Where the request came from. */
  meta?: RequestMeta;
};

export type IssueResult =
  | { kind: 'sent'; id: string; expiresAt: Date; resendAfter: number }
  | {
      kind: 'limited';
      reason: 'wait' | 'hourly';
      retryAfter: number;
      /** Seconds until a send is allowed again: the `retryAfter` (AC-8, "the seconds left"). */
      resendAfter: number;
      live: VerificationCode | null;
    };

/** Which code a check looks at: a sign in ticket, or a user's live code of some purposes. */
export type CheckTarget =
  | { challengeHash: string }
  | { userId: string; purposes: readonly VerificationPurpose[] };

export type CheckResult<T> =
  | { kind: 'right'; row: VerificationCode; value: T }
  | { kind: 'wrong'; attemptsLeft: number }
  /** Unknown, used, retired or expired, or the 5th wrong try just retired it. */
  | { kind: 'dead'; reason: 'expired' | 'tries' };

const live = (now: Date) => ({ usedAt: null, expiresAt: { gt: now } });

/**
 * Spec 0009: the one service for every emailed code (setup, reset, sign in, email change). Codes
 * are stored as argon2 hashes, live 10 or 60 minutes, die after 5 wrong tries, and each family
 * sends at most once a minute and 5 times an hour. Lock order is always the user row, then the
 * code row, the same as every other user write (spec 0004, AC-13).
 */
@Injectable()
export class CodeService {
  private readonly logger = new Logger('Codes');

  constructor(
    private readonly prisma: PrismaService,
    private readonly mail: MailService,
    private readonly events: AccountEventsService,
  ) {}

  /** One code event (spec 0011, AC-5): `reason` is the code's purpose. */
  private codeEvent(
    tx: Tx | PrismaService,
    type: AccountEventType,
    row: { userId: string; purpose: VerificationPurpose },
    actorId: string | null,
    meta: RequestMeta | undefined,
  ) {
    return this.events.record(tx, {
      userId: row.userId,
      actorId,
      type,
      reason: row.purpose,
      meta: meta ?? NO_META,
    });
  }

  /**
   * AC-2, AC-5: issue a code. Under the user row lock: check the limits, retire the family's live
   * code, insert the new row, commit; then send. A failed send deletes the new row and brings the
   * retired one back (if it hasn't expired), so it counts toward no limit, and throws
   * `MailFailedError`.
   */
  async issue(input: IssueInput): Promise<IssueResult> {
    const code = newOtp();
    // Slow work outside the lock
    const codeHash = await argon2.hash(code);
    const family = familyOf(input.purpose);

    const step = await this.prisma.$transaction(async (tx) => {
      await lockAccount(tx, input.userId);
      const now = new Date();
      const recent = await tx.verificationCode.findMany({
        where: {
          userId: input.userId,
          purpose: { in: [...family] },
          createdAt: { gt: new Date(now.getTime() - HOUR_MS) },
        },
        select: { createdAt: true },
        orderBy: { createdAt: 'desc' },
      });
      const current = await tx.verificationCode.findFirst({
        where: {
          userId: input.userId,
          purpose: { in: [...family] },
          ...live(now),
        },
        orderBy: { createdAt: 'desc' },
      });
      const decision = sendDecision(
        recent.map((r) => r.createdAt),
        now,
      );
      if (!decision.allowed) {
        await input.onLimited?.(tx, current);
        return {
          kind: 'limited' as const,
          reason: decision.reason,
          retryAfter: decision.retryAfter,
          resendAfter: decision.retryAfter,
          live: current,
        };
      }

      // AC-10: the ticket moves; the old row's is cleared first to keep the unique index
      let ticketFrom: string | null = null;
      if (input.challengeHash) {
        const holder = await tx.verificationCode.findFirst({
          where: { challengeHash: input.challengeHash },
          select: { id: true },
        });
        if (holder) {
          await tx.verificationCode.update({
            where: { id: holder.id },
            data: { challengeHash: null },
          });
          ticketFrom = holder.id;
        }
      }
      if (current) {
        await tx.verificationCode.update({
          where: { id: current.id },
          data: { usedAt: now },
        });
      }
      const row = await tx.verificationCode.create({
        data: {
          userId: input.userId,
          purpose: input.purpose,
          codeHash,
          challengeHash: input.challengeHash ?? null,
          newEmail: input.newEmail ?? null,
          expiresAt: new Date(now.getTime() + CODE_LIFETIME_MS[input.purpose]),
          createdAt: now,
        },
        select: { id: true, expiresAt: true },
      });
      return {
        kind: 'issued' as const,
        row,
        retiredId: current?.id ?? null,
        ticketFrom,
      };
    });

    if (step.kind === 'limited') return step;

    const tag = `user=${input.userId} purpose=${input.purpose}`;
    try {
      await this.mail.sendMail({
        to: input.mail.to,
        ...input.mail.build(code),
        tag,
      });
    } catch (error) {
      this.logger.error(
        `code email failed ${tag}: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
      await this.undoIssue(step, input.challengeHash ?? null);
      // Its own transaction after the undo (AC-5)
      await this.codeEvent(
        this.prisma,
        AccountEventType.CODE_MAIL_FAILED,
        input,
        input.actorId ?? input.userId,
        input.meta,
      );
      throw new MailFailedError();
    }
    // Its own transaction after the mail went out; a crash in between loses only this row
    await this.codeEvent(
      this.prisma,
      AccountEventType.CODE_SENT,
      input,
      input.actorId ?? input.userId,
      input.meta,
    );
    return {
      kind: 'sent',
      id: step.row.id,
      expiresAt: step.row.expiresAt,
      resendAfter: RESEND_WAIT_MS / 1000,
    };
  }

  /** AC-5: the second transaction after a failed send. Ids are held in memory between the two. */
  private async undoIssue(
    step: {
      row: { id: string };
      retiredId: string | null;
      ticketFrom: string | null;
    },
    challengeHash: string | null,
  ): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.verificationCode.delete({ where: { id: step.row.id } });
      if (step.retiredId) {
        await tx.verificationCode.updateMany({
          where: { id: step.retiredId, expiresAt: { gt: new Date() } },
          data: { usedAt: null },
        });
      }
      if (step.ticketFrom && challengeHash) {
        await tx.verificationCode.update({
          where: { id: step.ticketFrom },
          data: { challengeHash },
        });
      }
    });
  }

  /**
   * AC-4: check a code. The lookup, `argon2.verify` and the attempt count run in one transaction
   * holding the user row and then the code row, so parallel guesses count one by one. `precheck`
   * runs first and may throw (nothing is counted then). A right code is marked used when `consume`
   * is set, and `onRight` runs in the same transaction.
   */
  async check<T = undefined>(input: {
    target: CheckTarget;
    code: string;
    consume: boolean;
    precheck?: (tx: Tx, row: VerificationCode) => Promise<void>;
    onRight?: (tx: Tx, row: VerificationCode) => Promise<T>;
    /** Spec 0011: where the try came from, for `CODE_RETIRED` and `CODE_USED`. */
    meta?: RequestMeta;
  }): Promise<CheckResult<T>> {
    const candidate = await this.prisma.verificationCode.findFirst({
      where:
        'challengeHash' in input.target
          ? { challengeHash: input.target.challengeHash }
          : {
              userId: input.target.userId,
              purpose: { in: [...input.target.purposes] },
              ...live(new Date()),
            },
      select: { id: true, userId: true },
      orderBy: { createdAt: 'desc' },
    });
    if (!candidate) return { kind: 'dead', reason: 'expired' };

    return this.prisma.$transaction(async (tx): Promise<CheckResult<T>> => {
      await lockAccount(tx, candidate.userId);
      await tx.$queryRaw`SELECT id FROM verification_codes WHERE id = ${candidate.id}::uuid FOR UPDATE`;
      const row = await tx.verificationCode.findUnique({
        where: { id: candidate.id },
      });
      const now = new Date();
      if (!row || row.usedAt || row.expiresAt <= now) {
        return { kind: 'dead', reason: 'expired' };
      }
      await input.precheck?.(tx, row);

      if (!(await argon2.verify(row.codeHash, input.code))) {
        const attempts = row.attempts + 1;
        const retire = attempts >= MAX_ATTEMPTS;
        await tx.verificationCode.update({
          where: { id: row.id },
          data: { attempts, ...(retire ? { usedAt: now } : {}) },
        });
        if (retire) {
          this.logger.log(
            `code retired after ${MAX_ATTEMPTS} wrong tries user=${row.userId} purpose=${row.purpose}`,
          );
          // Commits with the tries update; the caller's 400 comes after (AC-5, AC-7)
          await this.codeEvent(
            tx,
            AccountEventType.CODE_RETIRED,
            row,
            null,
            input.meta,
          );
          return { kind: 'dead', reason: 'tries' };
        }
        return { kind: 'wrong', attemptsLeft: attemptsLeft(attempts) };
      }

      if (input.consume) {
        await tx.verificationCode.update({
          where: { id: row.id },
          data: { usedAt: now },
        });
        await this.codeEvent(
          tx,
          AccountEventType.CODE_USED,
          row,
          row.userId,
          input.meta,
        );
      }
      const value = (await input.onRight?.(tx, row)) as T;
      return { kind: 'right', row, value };
    });
  }

  /** AC-2: any change of `users.email` retires every live code of the user, every family. */
  async retireAll(tx: Tx, userId: string): Promise<void> {
    await tx.verificationCode.updateMany({
      where: { userId, ...live(new Date()) },
      data: { usedAt: new Date() },
    });
  }

  /** Retires the user's live codes of these purposes (AC-19 cancels a pending email change). */
  async retire(
    tx: Tx,
    userId: string,
    purposes: readonly VerificationPurpose[],
  ): Promise<void> {
    await tx.verificationCode.updateMany({
      where: { userId, purpose: { in: [...purposes] }, ...live(new Date()) },
      data: { usedAt: new Date() },
    });
  }

  /** The user's live code of these purposes, newest first, or null (AC-20 `pendingEmail`). */
  liveCode(
    userId: string,
    purposes: readonly VerificationPurpose[],
  ): Promise<VerificationCode | null> {
    return this.prisma.verificationCode.findFirst({
      where: { userId, purpose: { in: [...purposes] }, ...live(new Date()) },
      orderBy: { createdAt: 'desc' },
    });
  }
}
