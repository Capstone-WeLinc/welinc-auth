import { VerificationPurpose } from '@prisma/client';

// Spec 0009: the one place for code lifetimes and limits. No environment variables on purpose.

const MINUTE_MS = 60_000;

/** AC-3: how long a code of each kind lives. */
export const CODE_LIFETIME_MS: Record<VerificationPurpose, number> = {
  PASSWORD_SETUP: 60 * MINUTE_MS,
  PASSWORD_RESET: 10 * MINUTE_MS,
  SIGN_IN: 10 * MINUTE_MS,
  EMAIL_CHANGE: 10 * MINUTE_MS,
};

/** The lifetime as code emails say it (AC-24). */
export function lifetimeText(purpose: VerificationPurpose): string {
  const minutes = CODE_LIFETIME_MS[purpose] / MINUTE_MS;
  return minutes === 60 ? '1 hour' : `${minutes} minutes`;
}

/** AC-4: the 5th wrong try retires a code. */
export const MAX_ATTEMPTS = 5;

/** AC-5: one send per family per 60 s, and 5 per rolling hour. */
export const RESEND_WAIT_MS = 60_000;
export const SENDS_PER_HOUR = 5;
export const HOUR_MS = 60 * MINUTE_MS;

/** AC-1: the hourly sweep deletes code rows older than this. */
export const CODE_RETENTION_MS = 24 * HOUR_MS;

/** AC-6: 10 calls a minute per client address on the public code routes. */
export const PUBLIC_CODE_LIMIT = { limit: 10, ttlMs: MINUTE_MS };

/**
 * AC-2: the families. One live code per user per family; issuing retires only its own family.
 * Setup and reset share one, so a reset replaces a setup code and the other way round.
 */
export const FAMILIES: readonly (readonly VerificationPurpose[])[] = [
  [VerificationPurpose.PASSWORD_SETUP, VerificationPurpose.PASSWORD_RESET],
  [VerificationPurpose.SIGN_IN],
  [VerificationPurpose.EMAIL_CHANGE],
];

export function familyOf(
  purpose: VerificationPurpose,
): readonly VerificationPurpose[] {
  return FAMILIES.find((family) => family.includes(purpose))!;
}
