import { readFileSync } from 'fs';
import { join } from 'path';
import {
  apiDocsEnabled,
  envSchema,
  envWarnings,
  sentrySettings,
  testEnv,
  validateEnv,
  type Env,
} from './env';

// covers: spec 0010 AC-1 to AC-6, AC-10, and the session cross checks

const errorOf = (raw: Record<string, unknown>): string => {
  try {
    validateEnv(raw);
  } catch (error) {
    return (error as Error).message;
  }
  throw new Error('expected the environment check to fail');
};

/** A full production set that passes every rule. */
const PRODUCTION: Record<string, string> = {
  ...testEnv,
  NODE_ENV: 'production',
  TRUST_PROXY_HOPS: '2',
  SSO_COOKIE_SECURE: 'true',
  CORS_ORIGINS: 'https://portal.welinc.test,https://vrms.welinc.test',
  PORTAL_URL: 'https://portal.welinc.test',
  AUTH_ISSUER: 'https://api.welinc.test/auth',
  SMTP_HOST: 'smtp.welinc.test',
  SMTP_USER: 'mailer',
  SMTP_PASS: 'secret',
};

describe('validateEnv', () => {
  it('passes a full valid set and fills the documented defaults (AC-6)', () => {
    const env = validateEnv(testEnv);
    expect(env).toMatchObject({
      NODE_ENV: 'test',
      PORT: 3000,
      TRUST_PROXY_HOPS: 0,
      ACCESS_TOKEN_MINUTES: 15,
      SERVICE_TOKEN_MINUTES: 5,
      WEB_SESSION_IDLE_MINUTES: 30,
      WEB_SESSION_MAX_HOURS: 12,
      MOBILE_SESSION_IDLE_DAYS: 7,
      REFRESH_REUSE_GRACE_SECONDS: 10,
      MAX_SESSIONS_PER_USER: 10,
      SESSION_RETENTION_DAYS: 90,
      SSO_COOKIE_SECURE: false,
      SMTP_PORT: 587,
      SMTP_FROM: 'WeLinc Logistics <no-reply@welinc.com>',
      CORS_ORIGINS: ['http://localhost:8000', 'http://localhost:8001'],
    });
    expect(env.SMTP_HOST).toBeUndefined();
  });

  it('defaults NODE_ENV to development', () => {
    expect(validateEnv({ ...testEnv, NODE_ENV: undefined }).NODE_ENV).toBe(
      'development',
    );
  });

  it('passes a full production set', () => {
    expect(validateEnv(PRODUCTION).NODE_ENV).toBe('not-production');
  });

  it('lists every missing or blank required name at once, one line each (AC-1)', () => {
    const message = errorOf({
      ...testEnv,
      AUTH_ISSUER: '',
      DATABASE_URL: '   ',
      PORTAL_URL: undefined,
      AUTH_SIGNING_KEYS: undefined,
    });
    expect(message).toContain('Environment check failed:');
    expect(message).toContain('AUTH_ISSUER: is required');
    expect(message).toContain('DATABASE_URL: is required');
    expect(message).toContain('PORTAL_URL: is required');
    expect(message).toContain('AUTH_SIGNING_KEYS: is required');
  });

  it.each([
    ['PORTAL_URL', 'ftp://portal.test', 'must be an http or https URL'],
    ['PORTAL_URL', 'not a url', 'must be an http or https URL'],
    ['PORT', '99999', 'must be a whole number from 1 to 65535'],
    ['PORT', '30.5', 'must be a whole number from 1 to 65535'],
    ['TRUST_PROXY_HOPS', 'two', 'must be a whole number from 0 to 10'],
    ['ACCESS_TOKEN_MINUTES', '0', 'must be a whole number from 1 to 60'],
    ['WEB_SESSION_MAX_HOURS', '200', 'must be a whole number from 1 to 168'],
    ['SESSION_RETENTION_DAYS', '-1', 'must be a whole number from 1 to 3650'],
    ['SMTP_PORT', 'abc', 'must be a whole number from 1 to 65535'],
    ['SSO_COOKIE_SECURE', 'yes', 'must be true or false'],
    ['SSO_COOKIE_SECURE', '1', 'must be true or false'],
    ['NODE_ENV', 'staging', 'must be development, production or test'],
    [
      'CORS_ORIGINS',
      'https://a.test/',
      'each entry must be an origin like https://host',
    ],
    [
      'CORS_ORIGINS',
      'https://a.test,https://b.test/app',
      'each entry must be an origin like https://host',
    ],
  ])('refuses %s=%s with a named reason (AC-2)', (name, value, reason) => {
    expect(errorOf({ ...testEnv, [name]: value })).toContain(
      `${name}: ${reason}`,
    );
  });

  it('accepts a comma list of origins with spaces and a trailing comma', () => {
    const env = validateEnv({
      ...testEnv,
      CORS_ORIGINS: ' https://a.test , https://b.test:8443, ',
    });
    expect(env.CORS_ORIGINS).toEqual(['https://a.test', 'https://b.test:8443']);
  });

  describe('session limits that must fit together', () => {
    it('refuses an idle limit longer than the session itself', () => {
      expect(
        errorOf({
          ...testEnv,
          WEB_SESSION_IDLE_MINUTES: '90',
          WEB_SESSION_MAX_HOURS: '1',
        }),
      ).toContain(
        'WEB_SESSION_IDLE_MINUTES: must be at most WEB_SESSION_MAX_HOURS × 60',
      );
    });

    it('refuses an access token that outlives the idle limit', () => {
      expect(
        errorOf({
          ...testEnv,
          ACCESS_TOKEN_MINUTES: '20',
          WEB_SESSION_IDLE_MINUTES: '10',
        }),
      ).toContain(
        'ACCESS_TOKEN_MINUTES: must be at most WEB_SESSION_IDLE_MINUTES',
      );
    });

    it('checks the pair against the defaults when one is unset', () => {
      expect(errorOf({ ...testEnv, ACCESS_TOKEN_MINUTES: '45' })).toContain(
        'ACCESS_TOKEN_MINUTES: must be at most WEB_SESSION_IDLE_MINUTES',
      );
      expect(() =>
        validateEnv({ ...testEnv, WEB_SESSION_IDLE_MINUTES: '720' }),
      ).not.toThrow();
    });

    it('skips the pair when one side already failed its own rule', () => {
      const message = errorOf({
        ...testEnv,
        WEB_SESSION_IDLE_MINUTES: 'abc',
        ACCESS_TOKEN_MINUTES: '45',
      });
      expect(message).toContain('WEB_SESSION_IDLE_MINUTES: must be a whole');
      expect(message).not.toContain('must be at most');
    });
  });

  describe('in production', () => {
    it('lists a bad URL and missing mail together with field problems (AC-1, AC-3)', () => {
      const message = errorOf({
        ...PRODUCTION,
        PORTAL_URL: 'http://portal.welinc.test',
        SMTP_HOST: '',
        SMTP_PASS: undefined,
        DATABASE_URL: '',
      });
      expect(message).toContain('DATABASE_URL: is required');
      expect(message).toContain('PORTAL_URL: must use https in production');
      expect(message).toContain('SMTP_HOST: is required in production');
      expect(message).toContain('SMTP_PASS: is required in production');
      expect(message).not.toContain('SMTP_USER');
    });

    it.each([
      ['SSO_COOKIE_SECURE', 'false', 'must be true in production'],
      ['SSO_COOKIE_SECURE', '', 'must be true in production'],
      ['TRUST_PROXY_HOPS', '0', 'must be at least 1 in production'],
      ['TRUST_PROXY_HOPS', '', 'must be at least 1 in production'],
    ])('refuses %s=%j (AC-3)', (name, value, reason) => {
      expect(errorOf({ ...PRODUCTION, [name]: value })).toContain(
        `${name}: ${reason}`,
      );
    });

    it.each([
      'https://localhost:8000',
      'https://127.0.0.1',
      'https://[::1]/portal',
    ])('refuses PORTAL_URL=%s (AC-4)', (value) => {
      expect(errorOf({ ...PRODUCTION, PORTAL_URL: value })).toContain(
        'PORTAL_URL: must not point at localhost in production',
      );
    });

    it('refuses an http or localhost CORS entry (AC-4)', () => {
      expect(
        errorOf({
          ...PRODUCTION,
          CORS_ORIGINS: 'https://ok.test,http://localhost:8001',
        }),
      ).toContain('CORS_ORIGINS: each entry must use https in production');
    });

    it('leaves development free of the production rules', () => {
      expect(() =>
        validateEnv({ ...testEnv, NODE_ENV: 'development' }),
      ).not.toThrow();
    });
  });

  it('never puts a secret value in the message, whatever fails (AC-1)', () => {
    const SENTINEL = 'SENTINEL-9f2c';
    const secrets = {
      DATABASE_URL: `postgresql://u:${SENTINEL}@db/x`,
      AUTH_SIGNING_KEYS: SENTINEL,
      SMTP_PASS: SENTINEL,
    };
    const failures: Record<string, string>[] = [
      { ...testEnv, ...secrets, PORT: SENTINEL },
      { ...testEnv, ...secrets, PORTAL_URL: SENTINEL },
      { ...testEnv, ...secrets, CORS_ORIGINS: `https://${SENTINEL}.test/` },
      { ...testEnv, ...secrets, SSO_COOKIE_SECURE: SENTINEL },
      { ...testEnv, ...secrets, ACCESS_TOKEN_MINUTES: SENTINEL },
      { ...PRODUCTION, ...secrets, PORTAL_URL: `http://${SENTINEL}.test` },
      { ...PRODUCTION, ...secrets, TRUST_PROXY_HOPS: '0', SMTP_HOST: '' },
    ];
    for (const raw of failures) {
      expect(errorOf(raw)).not.toContain(SENTINEL);
    }
  });
});

describe('API_DOCS_ENABLED (VRMS spec 0026, AC-2 and AC-12)', () => {
  const enabled = (raw: Record<string, unknown>): boolean => {
    const env = validateEnv(raw);
    return apiDocsEnabled((key) => env[key]);
  };

  it('follows NODE_ENV when unset or blank', () => {
    expect(enabled(testEnv)).toBe(true);
    expect(enabled({ ...testEnv, NODE_ENV: 'development' })).toBe(true);
    expect(enabled({ ...testEnv, API_DOCS_ENABLED: '  ' })).toBe(true);
    expect(enabled(PRODUCTION)).toBe(false);
    expect(enabled({ ...PRODUCTION, API_DOCS_ENABLED: '' })).toBe(false);
  });

  it('takes true or false over the NODE_ENV default', () => {
    expect(enabled({ ...testEnv, API_DOCS_ENABLED: 'false' })).toBe(false);
    expect(enabled({ ...PRODUCTION, API_DOCS_ENABLED: 'true' })).toBe(true);
  });

  it('refuses anything else', () => {
    expect(errorOf({ ...testEnv, API_DOCS_ENABLED: 'yes' })).toContain(
      'API_DOCS_ENABLED: must be true or false',
    );
  });
});

describe('envWarnings (AC-5)', () => {
  const warnings = (extra: Record<string, string>) => {
    const env = validateEnv({ ...testEnv, ...extra });
    return envWarnings(<K extends keyof Env>(key: K) => env[key]);
  };

  it('warns once when mail is off', () => {
    const lines = warnings({});
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(
      /^Mail is off: SMTP_HOST, SMTP_USER and SMTP_PASS/,
    );
  });

  it('names the missing names when mail is only partly set', () => {
    expect(warnings({ SMTP_HOST: 'smtp.welinc.test' })).toEqual([
      expect.stringContaining('missing SMTP_USER, SMTP_PASS'),
    ]);
  });

  it('says nothing when mail is set up', () => {
    expect(
      warnings({ SMTP_HOST: 'h', SMTP_USER: 'u', SMTP_PASS: 'p' }),
    ).toEqual([]);
  });
});

describe('.env.example and the schema stay in step (AC-10)', () => {
  /** Names only scripts, compose or the platform read. */
  const SKIP_NAMES = new Set([
    'SEED_ALLOW',
    'API_PUBLIC_URL',
    'TZ',
    'NODE_OPTIONS',
  ]);
  const SKIP_PREFIXES = ['CLIENT_', 'AZURE_', 'POSTGRES_', 'PRISMA_'];
  const skipped = (name: string) =>
    SKIP_NAMES.has(name) || SKIP_PREFIXES.some((p) => name.startsWith(p));

  /** Lines like `NAME=` or `# NAME=`: commented names count as documented. */
  const exampleNames = readFileSync(
    join(__dirname, '..', '..', '.env.example'),
    'utf8',
  )
    .split(/\r?\n/)
    .map((line) => /^#?\s*([A-Z][A-Z0-9_]*)=/.exec(line)?.[1])
    .filter((name): name is string => Boolean(name) && !skipped(name!));
  const schemaNames = Object.keys(envSchema.shape);

  it('documents every schema name in .env.example', () => {
    expect(schemaNames.filter((n) => !exampleNames.includes(n))).toEqual([]);
  });

  it('has every .env.example name in the schema', () => {
    expect(exampleNames.filter((n) => !schemaNames.includes(n))).toEqual([]);
  });

  it('gives testEnv every required name', () => {
    expect(() => validateEnv(testEnv)).not.toThrow();
  });
});

describe('Sentry settings (VRMS spec 0025 AC-14, AC-15)', () => {
  const DSN = 'https://abc@o1.ingest.us.sentry.io/2';

  it('passes with every Sentry value blank, and monitoring stays off', () => {
    const raw = {
      ...testEnv,
      SENTRY_DSN: '',
      SENTRY_ENVIRONMENT: '',
      SENTRY_RELEASE: '',
      SENTRY_TEST_ROUTES: '',
    };
    expect(validateEnv(raw).SENTRY_TEST_ROUTES).toBe(false);
    expect(sentrySettings(raw)).toBeNull();
  });

  it('refuses a DSN without a valid environment', () => {
    expect(errorOf({ ...testEnv, SENTRY_DSN: DSN })).toContain(
      'SENTRY_ENVIRONMENT: must be staging or production when SENTRY_DSN is set',
    );
    expect(
      errorOf({ ...testEnv, SENTRY_DSN: DSN, SENTRY_ENVIRONMENT: 'dev' }),
    ).toContain('SENTRY_ENVIRONMENT: must be staging or production');
  });

  it('refuses the test routes in production', () => {
    expect(
      errorOf({
        ...PRODUCTION,
        SENTRY_DSN: DSN,
        SENTRY_ENVIRONMENT: 'production',
        SENTRY_TEST_ROUTES: 'true',
      }),
    ).toContain('SENTRY_TEST_ROUTES: must not be true in production');
  });

  it('refuses SEED_MAIL_TO_LOG in production (spec 0009 AC-32)', () => {
    expect(
      errorOf({
        ...PRODUCTION,
        SENTRY_DSN: DSN,
        SENTRY_ENVIRONMENT: 'production',
        SEED_MAIL_TO_LOG: 'true',
      }),
    ).toContain('SEED_MAIL_TO_LOG: must not be true in production');
  });

  it('reads SEED_MAIL_TO_LOG strictly: only true or false (spec 0009 AC-32)', () => {
    expect(errorOf({ ...testEnv, SEED_MAIL_TO_LOG: '1' })).toContain(
      'SEED_MAIL_TO_LOG: must be true or false',
    );
    expect(validateEnv({ ...testEnv }).SEED_MAIL_TO_LOG).toBe(false);
    expect(
      validateEnv({ ...PRODUCTION, SEED_MAIL_TO_LOG: 'true' }).SEED_MAIL_TO_LOG,
    ).toBe(true);
  });

  it('reads SEED_MAIL_REDIRECT as a template with one {tag} before the @ (spec 0009 AC-33)', () => {
    for (const bad of [
      'team@gmail.com',
      'team+{tag}{tag}@gmail.com',
      'team@gmail.com{tag}',
      '{tag}',
      'team+{tag}@',
    ]) {
      expect(errorOf({ ...testEnv, SEED_MAIL_REDIRECT: bad })).toContain(
        'SEED_MAIL_REDIRECT: must be an email address with one {tag}',
      );
    }
    expect(validateEnv({ ...testEnv }).SEED_MAIL_REDIRECT).toBeUndefined();
    expect(
      validateEnv({ ...PRODUCTION, SEED_MAIL_REDIRECT: 'team+{tag}@gmail.com' })
        .SEED_MAIL_REDIRECT,
    ).toBe('team+{tag}@gmail.com');
  });

  it('refuses SEED_MAIL_REDIRECT in production (spec 0009 AC-33)', () => {
    expect(
      errorOf({
        ...PRODUCTION,
        SENTRY_DSN: DSN,
        SENTRY_ENVIRONMENT: 'production',
        SEED_MAIL_REDIRECT: 'team+{tag}@gmail.com',
      }),
    ).toContain('SEED_MAIL_REDIRECT: must not be set in production');
  });

  it('allows the test routes on staging', () => {
    const env = validateEnv({
      ...testEnv,
      SENTRY_DSN: DSN,
      SENTRY_ENVIRONMENT: 'staging',
      SENTRY_TEST_ROUTES: 'true',
    });
    expect(env.SENTRY_TEST_ROUTES).toBe(true);
  });

  it('starts in production without a DSN and warns once', () => {
    const env = validateEnv({
      ...PRODUCTION,
      SENTRY_ENVIRONMENT: 'production',
    });
    expect(envWarnings((key) => env[key])).toEqual([
      expect.stringMatching(/^Error monitoring is off: SENTRY_DSN/),
    ]);
  });

  it('gives instrument.ts the DSN, environment and release only when the pair is valid', () => {
    expect(
      sentrySettings({
        SENTRY_DSN: DSN,
        SENTRY_ENVIRONMENT: 'staging',
        SENTRY_RELEASE: ' abc123 ',
      }),
    ).toEqual({ dsn: DSN, environment: 'staging', release: 'abc123' });
    expect(sentrySettings({ SENTRY_DSN: DSN })).toBeNull();
    expect(
      sentrySettings({
        SENTRY_DSN: 'not a url',
        SENTRY_ENVIRONMENT: 'staging',
      }),
    ).toBeNull();
  });
});
