import type { CookieOptions, Request, Response } from 'express';
import type { SessionSettings } from './session-config';

/**
 * The portal's SSO cookie (spec 0001 section 7): `welinc_sso`, `__Secure-welinc_sso` when hosted.
 * Path `/auth`, HttpOnly, SameSite=Lax, host only, lives for the session's remaining 12 hours.
 */
export function ssoCookieName(settings: SessionSettings): string {
  return settings.ssoCookieSecure ? '__Secure-welinc_sso' : 'welinc_sso';
}

function options(settings: SessionSettings): CookieOptions {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: settings.ssoCookieSecure,
    path: '/auth',
  };
}

export function readSsoCookie(
  request: Request,
  settings: SessionSettings,
): unknown {
  const cookies = request.cookies as Record<string, unknown> | undefined;
  return cookies?.[ssoCookieName(settings)];
}

export function setSsoCookie(
  response: Response,
  settings: SessionSettings,
  handle: string,
  absoluteExpiresAt: Date,
): void {
  response.cookie(ssoCookieName(settings), handle, {
    ...options(settings),
    maxAge: Math.max(0, absoluteExpiresAt.getTime() - Date.now()),
  });
}

export function clearSsoCookie(
  response: Response,
  settings: SessionSettings,
): void {
  response.clearCookie(ssoCookieName(settings), options(settings));
}
