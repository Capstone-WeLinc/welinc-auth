import type { ErrorMap } from './decorators';

/**
 * The errors shared guards and pipes answer, per VRMS spec 0026 AC-4 (listed on every route the
 * guard runs on). Traced from the code on 2026-11-16; the code wins over contract 0001.
 */

/** The global `ValidationPipe` (and `ParseUUIDPipe`): a bad body, query or id, with no code. */
export const VALIDATION: ErrorMap = { 400: [null] };

/** `JwtAuthGuard` on a user route (`request-authenticator.ts`, `lockout.ts`); a service token gets `WRONG_TOKEN_USE`. */
export const USER_TOKEN: ErrorMap = {
  401: ['TOKEN_EXPIRED', 'SESSION_ENDED', null],
  403: ['ACCOUNT_LOCKED', 'WRONG_AUDIENCE', 'WRONG_TOKEN_USE'],
};

/** `@SystemAdmin()`: `JwtAuthGuard` plus `SystemAdminGuard` (a non admin gets a 403 with no code). */
export const SYSTEM_ADMIN: ErrorMap = {
  ...USER_TOKEN,
  403: [...USER_TOKEN[403]!, 'ADMIN_CODE_REQUIRED', null],
};

/** The code mail steps (`CodeErrorFilter`): the send limit and a failed send. */
export const CODE_MAIL: ErrorMap = {
  429: ['CODE_SEND_LIMIT'],
  503: ['MAIL_FAILED'],
};

/** The per address code route counter, 10 a minute (`codes/address-limit.ts`). */
export const CODE_ROUTE_LIMIT: ErrorMap = { 429: ['RATE_LIMITED'] };

/** A route that can't find its target: a bare 404 "User not found". */
export const NOT_FOUND: ErrorMap = { 404: [null] };

/** The password recheck (`reauth/password-check.service.ts`): a wrong password, and the lock it leads to. */
export const PASSWORD_CHECK: ErrorMap = {
  400: ['WRONG_PASSWORD'],
  403: ['ACCOUNT_LOCKED'],
};

/** `PortalCsrfGuard` on a cookie POST (`sessions/csrf.ts`). */
export const CSRF: ErrorMap = { 403: ['CSRF_REJECTED'] };

/** A password sign in (`checkCredentials`): a wrong password is a bare 401 so no account is revealed. */
export const SIGN_IN: ErrorMap = {
  401: [null],
  403: ['ACCOUNT_INACTIVE', 'ACCOUNT_LOCKED'],
};

/** `DirectoryGuard` and `PermissionsReadGuard`: a service token with the route's scope, 120 a minute per client. */
export const SERVICE_SCOPE: ErrorMap = {
  401: ['TOKEN_EXPIRED', null],
  403: ['FORBIDDEN'],
  429: ['RATE_LIMITED'],
};

/** A `private_key_jwt` client assertion form (`/auth/logout`, `/auth/session/activity`), OAuth errors. */
export const CLIENT_ASSERTION: ErrorMap = {
  400: ['invalid_request'],
  401: ['invalid_client'],
  429: ['rate_limited'],
};

/** `AdminSessionGuard` at the `signed-in` level (`GET /auth/admin/me`): the portal cookie only. */
export const ADMIN_SIGNED_IN: ErrorMap = {
  401: ['NOT_SIGNED_IN'],
  403: ['ACCOUNT_LOCKED'],
};

/** `AdminSessionGuard` at the `admin` level (the code step and `verify-password`): no code needed yet. */
export const ADMIN_STEP: ErrorMap = {
  401: ['NOT_SIGNED_IN'],
  403: ['ACCOUNT_LOCKED', 'NOT_AN_ADMIN'],
};

/** `AdminSessionGuard` at its default level: an admin who passed the admin code when it is on. */
export const ADMIN_SESSION: ErrorMap = {
  401: ['NOT_SIGNED_IN'],
  403: ['ACCOUNT_LOCKED', 'ADMIN_CODE_REQUIRED', 'NOT_AN_ADMIN'],
};
