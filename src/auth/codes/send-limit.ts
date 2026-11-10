import {
  HOUR_MS,
  MAX_ATTEMPTS,
  RESEND_WAIT_MS,
  SENDS_PER_HOUR,
} from './code-config';

/** Whole seconds, rounded up, never below 1 (a `Retry-After` of 0 would invite a retry storm). */
const seconds = (ms: number) => Math.max(1, Math.ceil(ms / 1000));

export type SendDecision =
  | { allowed: true }
  | { allowed: false; reason: 'wait' | 'hourly'; retryAfter: number };

/**
 * AC-5, pure: may the family send now? `createdAts` are every row of the family in the last hour,
 * used and retired ones too. Inside the 60 s wait: the seconds left. Over 5 in the hour: when the
 * oldest of the last 5 turns an hour old (Value sourcing, `Retry-After`).
 */
export function sendDecision(
  createdAts: readonly Date[],
  now: Date,
): SendDecision {
  const inHour = createdAts
    .map((d) => d.getTime())
    .filter((t) => t > now.getTime() - HOUR_MS)
    .sort((a, b) => b - a);
  const newest = inHour[0];
  if (newest !== undefined && now.getTime() - newest < RESEND_WAIT_MS) {
    return {
      allowed: false,
      reason: 'wait',
      retryAfter: seconds(newest + RESEND_WAIT_MS - now.getTime()),
    };
  }
  if (inHour.length >= SENDS_PER_HOUR) {
    const oldestOfLastFive = inHour[SENDS_PER_HOUR - 1];
    return {
      allowed: false,
      reason: 'hourly',
      retryAfter: seconds(oldestOfLastFive + HOUR_MS - now.getTime()),
    };
  }
  return { allowed: true };
}

/** `resendAfter`: 60 minus the seconds since the family's newest send, at least 0 (Value sourcing). */
export function resendAfter(newest: Date | null, now: Date): number {
  if (!newest) return 0;
  return Math.max(
    0,
    Math.ceil((newest.getTime() + RESEND_WAIT_MS - now.getTime()) / 1000),
  );
}

/** `attemptsLeft` after a wrong try (Value sourcing). */
export function attemptsLeft(attempts: number): number {
  return Math.max(0, MAX_ATTEMPTS - attempts);
}
