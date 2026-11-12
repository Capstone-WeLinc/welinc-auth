import { z } from 'zod';

/**
 * Every environment variable welinc-auth reads at runtime, checked once at boot (spec 0010).
 * Nothing else in `src/` reads `process.env`: inject `ConfigService<Env, true>` instead.
 * `validateEnv` is pure: no logging, no side effects.
 */

// Empty or blank strings count as missing: .env.example ships some names empty.
const blank = (v: unknown) =>
  typeof v === 'string' && v.trim() === '' ? undefined : v;
const required = z.preprocess(blank, z.string({ error: 'is required' }).trim());
const optional = <T extends z.ZodType>(s: T) =>
  z.preprocess(blank, s.optional());
const httpUrl = z.url({
  protocol: /^https?$/,
  error: 'must be an http or https URL',
});
/** "is required" first, then "must be a URL". */
const url = required.pipe(httpUrl);
const whole = (min: number, max: number, fallback: number) => {
  const error = `must be a whole number from ${min} to ${max}`;
  return z.preprocess(
    blank,
    z.coerce
      .number({ error })
      .int({ error })
      .min(min, { error })
      .max(max, { error })
      .default(fallback),
  );
};
const flag = z
  .preprocess(
    blank,
    z
      .enum(['true', 'false'], { error: 'must be true or false' })
      .default('false'),
  )
  .transform((v) => v === 'true');
/** A flag that is on unless set to `false`. */
const flagOn = z
  .preprocess(
    blank,
    z
      .enum(['true', 'false'], { error: 'must be true or false' })
      .default('true'),
  )
  .transform((v) => v === 'true');
/** "a, b," → ['a', 'b']; each entry must be a bare origin (no path, no trailing slash). */
const originList = required.transform((v, ctx) => {
  const items = v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const item of items) {
    if (!isOrigin(item)) {
      ctx.addIssue({
        code: 'custom',
        message: 'each entry must be an origin like https://host',
      });
    }
  }
  return items;
});

function isOrigin(value: string): boolean {
  return URL.canParse(value) && new URL(value).origin === value;
}

export const envSchema = z.object({
  NODE_ENV: z.preprocess(
    blank,
    z
      .enum(['development', 'production', 'test'], {
        error: 'must be development, production or test',
      })
      .default('development'),
  ),
  PORT: whole(1, 65535, 3000),
  /** Proxy hops in front of welinc-auth (spec 0002, AC-18): 1 locally (nginx), 2 hosted. */
  TRUST_PROXY_HOPS: whole(0, 10, 0),
  CORS_ORIGINS: originList,
  /** The portal: setup and reset links, and the one Origin the SSO cookie routes accept. */
  PORTAL_URL: url,
  DATABASE_URL: required,

  // Tokens (spec 0002)
  /** An identifier compared character for character, never fetched, so not held to the URL rules. */
  AUTH_ISSUER: required,
  /** Parsed and self tested by `signing-keys.ts` at boot (AC-13). */
  AUTH_SIGNING_KEYS: required,
  ACCESS_TOKEN_MINUTES: whole(1, 60, 15),
  SERVICE_TOKEN_MINUTES: whole(1, 60, 5),

  // Sessions (spec 0003)
  WEB_SESSION_IDLE_MINUTES: whole(1, 1440, 30),
  WEB_SESSION_MAX_HOURS: whole(1, 168, 12),
  MOBILE_SESSION_IDLE_DAYS: whole(1, 90, 7),
  REFRESH_REUSE_GRACE_SECONDS: whole(1, 60, 10),
  MAX_SESSIONS_PER_USER: whole(1, 100, 10),
  SESSION_RETENTION_DAYS: whole(1, 3650, 90),
  SSO_COOKIE_SECURE: flag,
  // Spec 0013, AC-8: admins confirm each portal sign in with an emailed code; false is local only
  ADMIN_SIGN_IN_CODE: flagOn,

  // Spec 0011: sign in, session and code events are kept this long; account changes forever
  ACCOUNT_EVENT_RETENTION_DAYS: whole(30, 3650, 365),
  // Spec 0012: days between a soft delete and the erasure of the person's personal data
  ACCOUNT_ERASURE_GRACE_DAYS: whole(1, 365, 30),
  // Spec 0011: the offline DB-IP Lite files (npm run geo:fetch). Missing files only leave places empty
  GEOIP_COUNTRY_FILE: z.preprocess(
    blank,
    z.string().trim().default('geo/dbip-country-lite.mmdb'),
  ),
  GEOIP_ASN_FILE: z.preprocess(
    blank,
    z.string().trim().default('geo/dbip-asn-lite.mmdb'),
  ),

  // Email: all three of host, user and pass are required in production
  SMTP_HOST: optional(z.string().trim()),
  SMTP_PORT: whole(1, 65535, 587),
  SMTP_USER: optional(z.string().trim()),
  SMTP_PASS: optional(z.string()),
  SMTP_FROM: z.preprocess(
    blank,
    z.string().trim().default('WeLinc Logistics <no-reply@welinc.com>'),
  ),
});

export type Env = z.infer<typeof envSchema>;

/** URL variables held to https and no localhost in production (AC-4). */
const PRODUCTION_URLS = ['PORTAL_URL'] as const;

const SMTP_NAMES = ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASS'] as const;

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/** Why `value` can't be used in production, or null. Unparseable values are left to the field rules. */
function productionUrlProblem(value: string): string | null {
  if (!URL.canParse(value)) return null;
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:') return 'must use https in production';
  if (LOCAL_HOSTS.has(parsed.hostname)) {
    return 'must not point at localhost in production';
  }
  return null;
}

const text = (
  raw: Record<string, unknown>,
  name: string,
): string | undefined => {
  const value = blank(raw[name]);
  return typeof value === 'string' ? value.trim() : undefined;
};

/** Production rules, checked on the blank normalised raw values so they run even when a field failed. */
function productionIssues(raw: Record<string, unknown>): string[] {
  if (text(raw, 'NODE_ENV') !== 'production') return [];
  const lines: string[] = [];

  // AC-3
  for (const name of SMTP_NAMES) {
    if (!text(raw, name)) lines.push(`${name}: is required in production`);
  }
  if (text(raw, 'SSO_COOKIE_SECURE') !== 'true') {
    lines.push('SSO_COOKIE_SECURE: must be true in production');
  }
  // Spec 0013, AC-8
  if (text(raw, 'ADMIN_SIGN_IN_CODE') === 'false') {
    lines.push('ADMIN_SIGN_IN_CODE: must not be false in production');
  }
  const hops = text(raw, 'TRUST_PROXY_HOPS');
  if (hops === undefined || Number(hops) === 0) {
    lines.push('TRUST_PROXY_HOPS: must be at least 1 in production');
  }

  // AC-4
  for (const name of PRODUCTION_URLS) {
    const value = text(raw, name);
    const problem = value === undefined ? null : productionUrlProblem(value);
    if (problem) lines.push(`${name}: ${problem}`);
  }
  const origins = text(raw, 'CORS_ORIGINS')?.split(',') ?? [];
  for (const origin of origins.map((o) => o.trim()).filter(Boolean)) {
    const problem = productionUrlProblem(origin);
    if (problem) {
      lines.push(`CORS_ORIGINS: each entry ${problem}`);
      break;
    }
  }
  return lines;
}

type NumberName =
  | 'ACCESS_TOKEN_MINUTES'
  | 'WEB_SESSION_IDLE_MINUTES'
  | 'WEB_SESSION_MAX_HOURS';

/** Session limits that only make sense together. Skipped for a value that failed its own rule. */
function crossIssues(raw: Record<string, unknown>): string[] {
  const read = (name: NumberName): number | undefined => {
    const result = envSchema.shape[name].safeParse(raw[name]);
    return result.success ? result.data : undefined;
  };
  const access = read('ACCESS_TOKEN_MINUTES');
  const idle = read('WEB_SESSION_IDLE_MINUTES');
  const maxHours = read('WEB_SESSION_MAX_HOURS');
  const lines: string[] = [];
  if (idle !== undefined && maxHours !== undefined && idle > maxHours * 60) {
    lines.push(
      'WEB_SESSION_IDLE_MINUTES: must be at most WEB_SESSION_MAX_HOURS × 60',
    );
  }
  if (access !== undefined && idle !== undefined && access > idle) {
    lines.push(
      'ACCESS_TOKEN_MINUTES: must be at most WEB_SESSION_IDLE_MINUTES',
    );
  }
  return lines;
}

/** ConfigModule's validate hook. Throws one Error listing every problem; never includes a value. */
export function validateEnv(raw: Record<string, unknown>): Env {
  const result = envSchema.safeParse(raw);
  const lines = [
    ...(result.success
      ? []
      : result.error.issues.map((i) => `${String(i.path[0])}: ${i.message}`)),
    ...crossIssues(raw),
    ...productionIssues(raw),
  ];
  if (lines.length) {
    const unique = [...new Set(lines)];
    throw new Error(`Environment check failed:\n  ${unique.join('\n  ')}`);
  }
  return result.data!;
}

/** The AC-5 warnings, logged by bootstrap() once the app's logger is set. */
export function envWarnings(
  get: <K extends keyof Env>(key: K) => Env[K],
): string[] {
  const missing = SMTP_NAMES.filter((name) => !get(name));
  if (missing.length === SMTP_NAMES.length) {
    return [
      'Mail is off: SMTP_HOST, SMTP_USER and SMTP_PASS are not set, so emails are logged instead of sent',
    ];
  }
  if (missing.length) {
    return [
      `Mail is off: SMTP is only partly set, missing ${missing.join(', ')}, so emails are logged instead of sent`,
    ];
  }
  return [];
}

/** Valid values for tests (no secrets, no network): loaded by Jest setupFiles (AC-9). */
export const testEnv: Record<string, string> = {
  NODE_ENV: 'test',
  CORS_ORIGINS: 'http://localhost:8000,http://localhost:8001',
  PORTAL_URL: 'http://localhost:8000',
  DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
  AUTH_ISSUER: 'http://localhost:3000/auth',
  // Present only: no test loads the key ring from the environment
  AUTH_SIGNING_KEYS: 'test-only-not-a-key',
};
