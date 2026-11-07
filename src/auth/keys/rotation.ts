import { exportJWK, generateKeyPair } from 'jose';
import { newKid } from './kid';
import {
  parseSigningKeys,
  type SigningKeyJwk,
  type SigningKeySet,
} from './signing-keys';

/** A `next` key is published at least this long before it may sign (spec 0001 section 5). */
export const PUBLISH_BEFORE_PROMOTE_MS = 60 * 60_000;
/** A retired key stays published this long after its last token expired (spec 0001 section 5). */
export const KEEP_AFTER_LAST_TOKEN_MS = 30 * 60_000;

export type RotationStep = 'add' | 'promote' | 'remove';

export type RotationOptions = {
  now: Date;
  /** Skip the timing checks, for a leaked key. */
  force: boolean;
  /** For `remove --now <kid>`: the one key to remove. */
  kid?: string;
  /** The longer token life in minutes: max(ACCESS_TOKEN_MINUTES, SERVICE_TOKEN_MINUTES). */
  tokenMinutes: number;
};

export type RotationResult = {
  set: SigningKeySet;
  /** Lines to print: never key material. */
  notes: string[];
};

/** Thrown for a step the rules refuse. The message says why and when it becomes allowed. */
export class RotationRefusedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RotationRefusedError';
  }
}

const iso = (date: Date) => date.toISOString().replace(/\.\d{3}Z$/, 'Z');

async function newSigningKey(now: Date): Promise<SigningKeyJwk> {
  const { privateKey } = await generateKeyPair('ES256', { extractable: true });
  return {
    ...(await exportJWK(privateKey)),
    kid: newKid('auth', now),
    alg: 'ES256',
    use: 'sig',
    status: 'next',
    addedAt: iso(now),
  };
}

function removableAt(key: SigningKeyJwk, tokenMinutes: number): Date | null {
  if (!key.retiredAt) return null;
  return new Date(
    Date.parse(key.retiredAt) +
      tokenMinutes * 60_000 +
      KEEP_AFTER_LAST_TOKEN_MS,
  );
}

/**
 * One rotation step on the key set (spec 0002, AC-24). Pure apart from making a new key, so the
 * script and the rotation test run the same rules.
 */
export async function rotate(
  raw: string | undefined,
  step: RotationStep,
  options: RotationOptions,
): Promise<RotationResult> {
  const now = options.now;
  const keys: SigningKeyJwk[] =
    raw && raw.trim() !== ''
      ? parseSigningKeys(raw, { allowNoCurrent: true }).keys.map((key) => ({
          ...key,
        }))
      : [];
  const notes: string[] = [];
  const next = keys.find((key) => key.status === 'next');
  const current = keys.find((key) => key.status === 'current');

  if (step === 'add') {
    if (next) {
      throw new RotationRefusedError(
        `Key ${next.kid} is already next. Promote it before adding another.`,
      );
    }
    const key = await newSigningKey(now);
    keys.push(key);
    notes.push(`Added ${key.kid} as next.`);
  }

  if (step === 'promote') {
    if (!next)
      throw new RotationRefusedError(
        'There is no next key to promote. Run add first.',
      );
    const allowedAt = new Date(
      Date.parse(next.addedAt ?? '') + PUBLISH_BEFORE_PROMOTE_MS,
    );
    if (!options.force && !(allowedAt.getTime() <= now.getTime())) {
      throw new RotationRefusedError(
        `Key ${next.kid} must be published for 60 minutes first. Promote it at ${iso(allowedAt)} or later.`,
      );
    }
    if (options.force) {
      notes.push(
        'WARNING: promoted without the 60 minute wait. Verifiers that cached the key set before the add may refuse new tokens for up to 5 minutes.',
      );
    }
    if (current) {
      current.status = 'retired';
      current.retiredAt = iso(now);
      notes.push(`Retired ${current.kid}.`);
    }
    next.status = 'current';
    notes.push(`Promoted ${next.kid} to current.`);
  }

  if (step === 'remove') {
    let doomed: SigningKeyJwk[];
    if (options.force) {
      const target = keys.find((key) => key.kid === options.kid);
      if (!options.kid || !target) {
        throw new RotationRefusedError(
          'remove --now needs the kid of a key in the set.',
        );
      }
      if (target.status === 'current') {
        throw new RotationRefusedError(
          `Key ${target.kid} is current. Run add and promote --now first, then remove it.`,
        );
      }
      doomed = [target];
      notes.push(
        `WARNING: ${target.kid} removed at once. Live tokens it signed stop working, and verifiers may keep accepting it for up to 5 more minutes from their cache.`,
      );
    } else {
      const retired = keys.filter((key) => key.status === 'retired');
      doomed = retired.filter((key) => {
        const at = removableAt(key, options.tokenMinutes);
        return at !== null && at.getTime() <= now.getTime();
      });
      if (doomed.length === 0) {
        const soonest = retired
          .map((key) => removableAt(key, options.tokenMinutes))
          .filter((at): at is Date => at !== null)
          .sort((a, b) => a.getTime() - b.getTime())[0];
        throw new RotationRefusedError(
          soonest
            ? `No retired key may be removed yet. The first may go at ${iso(soonest)} or later.`
            : 'There is no retired key to remove.',
        );
      }
    }
    for (const key of doomed) {
      keys.splice(keys.indexOf(key), 1);
      notes.push(`Removed ${key.kid}.`);
    }
  }

  const set = { keys };
  // The result must still be a set welinc-auth will start with (or a lone next key on a new environment)
  parseSigningKeys(JSON.stringify(set), {
    allowNoCurrent: !keys.some((k) => k.status !== 'next'),
  });
  notes.push(...describe(set, options.tokenMinutes));
  return { set, notes };
}

/** The keys and their statuses, and the next step with its earliest time. */
export function describe(set: SigningKeySet, tokenMinutes: number): string[] {
  const lines = set.keys.map(
    (key) =>
      `  ${key.kid}  ${key.status}${key.addedAt ? `  added ${key.addedAt}` : ''}${key.retiredAt ? `  retired ${key.retiredAt}` : ''}`,
  );
  const next = set.keys.find((key) => key.status === 'next');
  const retired = set.keys.filter((key) => key.status === 'retired');
  let hint: string;
  if (next) {
    const at = new Date(
      Date.parse(next.addedAt ?? '') + PUBLISH_BEFORE_PROMOTE_MS,
    );
    hint = `Next: promote, at ${iso(at)} or later.`;
  } else if (retired.length > 0) {
    const at = retired
      .map((key) => removableAt(key, tokenMinutes))
      .filter((d): d is Date => d !== null)
      .sort((a, b) => a.getTime() - b.getTime())[0];
    hint = at ? `Next: remove, at ${iso(at)} or later.` : 'Next: remove.';
  } else {
    hint = 'Next: add, when you want to rotate.';
  }
  return ['Keys:', ...lines, hint];
}
