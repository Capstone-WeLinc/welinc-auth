import {
  BadRequestException,
  ForbiddenException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { AccountEventType, Prisma, ReauthPurpose } from '@prisma/client';
import * as argon2 from 'argon2';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { AccountEventsService } from '../events/account-events.service';
import { PasswordCheckReason, SignInFailReason } from '../events/event-types';
import type { RequestMeta } from '../events/request-meta';
import { hashOpaque, isOpaqueShape, newOpaque } from '../sessions/opaque';

/** The same 5 try lockout as sign in (spec 0012, AC-2). */
export const MAX_FAILED_ATTEMPTS = 5;

/** Contract section 7: a reauth token is good for 5 minutes (AC-1). */
export const REAUTH_TTL_MS = 5 * 60_000;

/** Reauth rows the hourly sweep deletes, by age (spec 0012, data model). */
export const REAUTH_KEEP_MS = 86_400_000;

/** argon2 hashes start like this; the erased `!erased` never does (AC-2, AC-15). */
const ARGON2_PREFIX = '$argon2';

type Tx = Prisma.TransactionClient;

/** Who is checking their password, and where from. */
export type PasswordCheck = {
  userId: string;
  password: string;
  reason: PasswordCheckReason;
  sid: string;
  meta: RequestMeta;
};

/** 403 ACCOUNT_LOCKED, the same body as a locked sign in. */
export const accountLocked = () =>
  new ForbiddenException({
    statusCode: HttpStatus.FORBIDDEN,
    error: 'Forbidden',
    code: 'ACCOUNT_LOCKED',
    message: 'Account is locked. Contact your Admin to unlock.',
    remainingAttempts: 0,
    isLocked: true,
  });

/** 400 WRONG_PASSWORD with the tries left before the lock (AC-2). */
export const wrongPassword = (attemptsLeft: number) =>
  new BadRequestException({
    statusCode: HttpStatus.BAD_REQUEST,
    error: 'Bad Request',
    code: 'WRONG_PASSWORD',
    message: 'That password is not right',
    attemptsLeft,
  });

/** 403 REAUTH_REQUIRED for any token that can't be used (AC-3). */
export const reauthRequired = () =>
  coded(
    HttpStatus.FORBIDDEN,
    'REAUTH_REQUIRED',
    'Confirm your password again to continue',
  );

/**
 * Spec 0012, AC-1 to AC-3: the one password recheck for a signed in person, and the one use
 * reauth tokens it hands out. Wrong passwords share `failed_login_attempts` with sign in.
 */
@Injectable()
export class PasswordCheckService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly events: AccountEventsService,
  ) {}

  /**
   * AC-2: checks the person's own password. Wrong: 400 `WRONG_PASSWORD` with `attemptsLeft`
   * (the 5th locks, 403 `ACCOUNT_LOCKED`). Locked already: 403 `ACCOUNT_LOCKED` even when right.
   * Every outcome writes its event (and the counter moves) before the error is thrown.
   */
  async verifyOwnPassword(check: PasswordCheck): Promise<void> {
    const user = await this.prisma.user.findFirst({
      where: { id: check.userId, deletedAt: null },
      select: { passwordHash: true, lockedAt: true, failedLoginAttempts: true },
    });
    if (!user) throw new NotFoundException('User not found');

    if (user.lockedAt !== null) {
      await this.prisma.$transaction((tx) =>
        this.failed(tx, check, SignInFailReason.ACCOUNT_LOCKED),
      );
      throw accountLocked();
    }

    // An unusable hash (the erased `!erased`) never matches and never counts
    if (!user.passwordHash.startsWith(ARGON2_PREFIX)) {
      throw wrongPassword(
        Math.max(0, MAX_FAILED_ATTEMPTS - user.failedLoginAttempts),
      );
    }

    let right = false;
    try {
      right = await argon2.verify(user.passwordHash, check.password);
    } catch {
      right = false;
    }

    if (right) {
      await this.prisma.$transaction(async (tx) => {
        await tx.user.update({
          where: { id: check.userId },
          data: { failedLoginAttempts: 0 },
        });
        await this.events.record(tx, {
          userId: check.userId,
          actorId: check.userId,
          type: AccountEventType.PASSWORD_CONFIRMED,
          reason: check.reason,
          sessionId: check.sid,
          meta: check.meta,
        });
      });
      return;
    }

    const outcome = await this.prisma.$transaction(async (tx) => {
      const [row] = await tx.$queryRaw<{ attempts: number; locked: boolean }[]>`
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_at = CASE WHEN failed_login_attempts + 1 >= ${MAX_FAILED_ATTEMPTS}
                             THEN now() ELSE locked_at END
        WHERE id = ${check.userId}::uuid AND locked_at IS NULL
        RETURNING failed_login_attempts AS attempts, locked_at IS NOT NULL AS locked`;
      if (!row) {
        // Locked by a parallel try between the read and this update
        await this.failed(tx, check, SignInFailReason.ACCOUNT_LOCKED);
        return { locked: true, attemptsLeft: 0 };
      }
      if (row.locked) {
        // As sign in: the 5th writes LOCKED_OUT and no failure row
        await this.events.record(tx, {
          userId: check.userId,
          actorId: check.userId,
          type: AccountEventType.LOCKED_OUT,
          sessionId: check.sid,
          meta: check.meta,
        });
        return { locked: true, attemptsLeft: 0 };
      }
      const attemptsLeft = Math.max(0, MAX_FAILED_ATTEMPTS - row.attempts);
      await this.failed(tx, check, check.reason, attemptsLeft);
      return { locked: false, attemptsLeft };
    });
    if (outcome.locked) throw accountLocked();
    throw wrongPassword(outcome.attemptsLeft);
  }

  /** AC-1: a fresh token for `purpose`, bound to the user and the caller's session. */
  async issueReauthToken(
    userId: string,
    sid: string,
    purpose: ReauthPurpose,
    now = new Date(),
  ): Promise<{ reauthToken: string; expiresAt: string }> {
    const token = newOpaque();
    const expiresAt = new Date(now.getTime() + REAUTH_TTL_MS);
    await this.prisma.reauthToken.create({
      data: {
        userId,
        sessionId: sid,
        purpose,
        tokenHash: hashOpaque(token),
        expiresAt,
      },
    });
    return { reauthToken: token, expiresAt: expiresAt.toISOString() };
  }

  /**
   * AC-3: uses the token up inside the caller's transaction, or throws 403 `REAUTH_REQUIRED`
   * (missing, wrong, used, expired, other purpose, another session). One atomic UPDATE, so two
   * uses at once can't both pass.
   */
  async consumeReauthToken(
    tx: Tx,
    token: string | undefined,
    userId: string,
    sid: string,
    purpose: ReauthPurpose,
  ): Promise<void> {
    if (!isOpaqueShape(token)) throw reauthRequired();
    const used = await tx.$executeRaw`
      UPDATE "reauth_tokens" SET "used_at" = now()
      WHERE "token_hash" = ${hashOpaque(token)}
        AND "user_id" = ${userId}::uuid
        AND "session_id" = ${sid}::uuid
        AND "purpose" = ${purpose}::"ReauthPurpose"
        AND "used_at" IS NULL
        AND "expires_at" > now()`;
    if (used !== 1) throw reauthRequired();
  }

  private failed(
    tx: Tx,
    check: PasswordCheck,
    reason: string,
    attemptsLeft: number | null = null,
  ) {
    return this.events.record(tx, {
      userId: check.userId,
      actorId: check.userId,
      type: AccountEventType.PASSWORD_CONFIRM_FAILED,
      reason,
      attemptsLeft,
      sessionId: check.sid,
      meta: check.meta,
    });
  }
}
