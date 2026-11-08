import type { Provider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

/** Session limits and cookie settings (spec 0003, Configuration required). */
export type SessionSettings = {
  webIdleMinutes: number;
  webMaxHours: number;
  mobileIdleDays: number;
  graceSeconds: number;
  maxSessionsPerUser: number;
  retentionDays: number;
  /** `SSO_COOKIE_SECURE`: `Secure` plus the `__Secure-` prefix on the SSO cookie when hosted. */
  ssoCookieSecure: boolean;
  /** The portal's origin: the only `Origin` the cookie routes accept (AC-17). */
  portalOrigin: string;
  /** Where the portal lives, for `/login?request=` and `/?error=` redirects. */
  portalUrl: string;
};

export const SESSION_SETTINGS = Symbol('SESSION_SETTINGS');

/** How long a login request and a login code live (spec 0001 section 5). */
export const LOGIN_REQUEST_SECONDS = 10 * 60;
export const LOGIN_CODE_SECONDS = 60;

function whole(
  config: ConfigService,
  name: string,
  fallback: number,
  min = 1,
): number {
  const raw = config.get<string>(name);
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min) {
    throw new Error(`${name} must be a whole number, at least ${min}`);
  }
  return value;
}

function flag(config: ConfigService, name: string): boolean {
  const raw = config.get<string>(name)?.trim().toLowerCase();
  return raw === 'true' || raw === '1';
}

export function readSessionSettings(config: ConfigService): SessionSettings {
  const rawPortal = config.get<string>('PORTAL_URL')?.trim();
  if (!rawPortal && config.get<string>('NODE_ENV') === 'production') {
    throw new Error('PORTAL_URL is required in production');
  }
  const portalUrl = (rawPortal || 'http://localhost:8000').replace(/\/+$/, '');
  return {
    webIdleMinutes: whole(config, 'WEB_SESSION_IDLE_MINUTES', 30),
    webMaxHours: whole(config, 'WEB_SESSION_MAX_HOURS', 12),
    mobileIdleDays: whole(config, 'MOBILE_SESSION_IDLE_DAYS', 7),
    graceSeconds: whole(config, 'REFRESH_REUSE_GRACE_SECONDS', 10),
    maxSessionsPerUser: whole(config, 'MAX_SESSIONS_PER_USER', 10),
    retentionDays: whole(config, 'SESSION_RETENTION_DAYS', 90),
    ssoCookieSecure: flag(config, 'SSO_COOKIE_SECURE'),
    portalOrigin: new URL(portalUrl).origin,
    portalUrl,
  };
}

export const sessionSettingsProvider: Provider = {
  provide: SESSION_SETTINGS,
  inject: [ConfigService],
  useFactory: readSessionSettings,
};
