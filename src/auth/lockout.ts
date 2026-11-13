import { ForbiddenException, HttpStatus } from '@nestjs/common';
import { Prisma } from '@prisma/client';

/**
 * Suite spec 0015: the account lockout. Five wrong passwords in a row lock an account for
 * `LOCK_MINUTES`, after which it unlocks on its own (the next try starts a fresh count). An
 * admin unlock or a used reset code ends it sooner. `locked_at` keeps the moment it locked; a
 * row whose lock ran out is cleared lazily, so every check goes through `lockActive`.
 */
export const MAX_FAILED_ATTEMPTS = 5;
export const LOCK_MINUTES = 15;
const LOCK_MS = LOCK_MINUTES * 60_000;

/** True while the lock that started at `lockedAt` still runs. */
export const lockActive = (lockedAt: Date | null, now = new Date()) =>
  lockedAt !== null && now.getTime() - lockedAt.getTime() < LOCK_MS;

/** When the lock that started at `lockedAt` ends (a fresh lock when null). */
export const lockedUntil = (lockedAt: Date | null, now = new Date()) =>
  new Date((lockedAt ?? now).getTime() + LOCK_MS);

/** A `lockedAt` filter for accounts whose lock still runs. */
export const lockRunning = (
  now = new Date(),
): Prisma.DateTimeNullableFilter => ({
  gt: new Date(now.getTime() - LOCK_MS),
});

/** Accounts with no running lock: never locked, or the lock ran out. */
export const notLocked = (now = new Date()): Prisma.UserWhereInput => ({
  OR: [
    { lockedAt: null },
    { lockedAt: { lte: new Date(now.getTime() - LOCK_MS) } },
  ],
});

/**
 * The counter UPDATE every wrong password runs: a running lock is left alone (no row comes
 * back), a lock that ran out starts again at 1, and the 5th in a row stamps `locked_at`.
 */
export const countWrongPassword = (userId: string) => Prisma.sql`
  UPDATE users
  SET failed_login_attempts =
        CASE WHEN locked_at IS NULL THEN failed_login_attempts + 1 ELSE 1 END,
      locked_at =
        CASE WHEN (CASE WHEN locked_at IS NULL THEN failed_login_attempts + 1 ELSE 1 END)
                  >= ${MAX_FAILED_ATTEMPTS}
             THEN now() ELSE NULL END
  WHERE id = ${userId}::uuid
    AND (locked_at IS NULL OR locked_at <= now() - (${LOCK_MINUTES}::int * interval '1 minute'))
  RETURNING failed_login_attempts AS attempts, locked_at IS NOT NULL AS locked`;

/** 403 ACCOUNT_LOCKED, the one body every locked answer uses. */
export const accountLocked = (lockedAt: Date | null = null) =>
  new ForbiddenException({
    statusCode: HttpStatus.FORBIDDEN,
    error: 'Forbidden',
    code: 'ACCOUNT_LOCKED',
    message:
      'Too many wrong passwords. Try again after lockedUntil, or reset your password.',
    remainingAttempts: 0,
    isLocked: true,
    lockedUntil: lockedUntil(lockedAt).toISOString(),
  });
