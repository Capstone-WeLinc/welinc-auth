import type { Provider } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../../config/env';

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

/** Values arrive checked and defaulted by the boot check (spec 0010). */
export function readSessionSettings(
  config: ConfigService<Env, true>,
): SessionSettings {
  const portalUrl = config
    .get('PORTAL_URL', { infer: true })
    .replace(/\/+$/, '');
  return {
    webIdleMinutes: config.get('WEB_SESSION_IDLE_MINUTES', { infer: true }),
    webMaxHours: config.get('WEB_SESSION_MAX_HOURS', { infer: true }),
    mobileIdleDays: config.get('MOBILE_SESSION_IDLE_DAYS', { infer: true }),
    graceSeconds: config.get('REFRESH_REUSE_GRACE_SECONDS', { infer: true }),
    maxSessionsPerUser: config.get('MAX_SESSIONS_PER_USER', { infer: true }),
    retentionDays: config.get('SESSION_RETENTION_DAYS', { infer: true }),
    ssoCookieSecure: config.get('SSO_COOKIE_SECURE', { infer: true }),
    portalOrigin: new URL(portalUrl).origin,
    portalUrl,
  };
}

export const sessionSettingsProvider: Provider = {
  provide: SESSION_SETTINGS,
  inject: [ConfigService],
  useFactory: readSessionSettings,
};
