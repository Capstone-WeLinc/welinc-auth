import { HttpStatus } from '@nestjs/common';
import { coded } from '../errors';

// Spec 0013: the error answers of the admin routes, one place so both route families match.

/** AC-14: no `welinc_sso` cookie, or its session ended. */
export const notSignedIn = () =>
  coded(
    HttpStatus.UNAUTHORIZED,
    'NOT_SIGNED_IN',
    'Sign in to the portal first',
  );

/** AC-14, AC-15: the caller is neither a suite admin nor any system's admin. */
export const notAnAdmin = () =>
  coded(HttpStatus.FORBIDDEN, 'NOT_AN_ADMIN', 'This needs an admin account');

/** AC-6: the session has not passed the emailed code yet. */
export const adminCodeRequired = () =>
  coded(
    HttpStatus.FORBIDDEN,
    'ADMIN_CODE_REQUIRED',
    'Confirm this sign in with the code we email you first',
  );

/** AC-7: the step up routes while `ADMIN_SIGN_IN_CODE` is off. */
export const codeNotRequired = () =>
  coded(
    HttpStatus.CONFLICT,
    'CODE_NOT_REQUIRED',
    'Admin sign in codes are turned off here',
  );

/** AC-16: a system admin passed a system they are not the admin of. */
export const notAdminOfSystem = () =>
  coded(
    HttpStatus.FORBIDDEN,
    'NOT_ADMIN_OF_SYSTEM',
    "You aren't an admin of that system",
  );

/** AC-9, AC-14, AC-27: a suite admin only action. */
export const notSuiteAdmin = () =>
  coded(HttpStatus.FORBIDDEN, 'NOT_SUITE_ADMIN', 'This needs a suite admin');

/** AC-14b: only the suite admin changes their own email, through their profile. */
export const suiteAdminSelfOnly = () =>
  coded(
    HttpStatus.FORBIDDEN,
    'SUITE_ADMIN_SELF_ONLY',
    "A suite admin's email is changed only by that person, from their profile",
  );

const conflict = (code: string, message: string) =>
  coded(HttpStatus.CONFLICT, code, message);

/** AC-1: three suite admins exist already. */
export const suiteAdminLimit = () =>
  conflict(
    'SUITE_ADMIN_LIMIT',
    'There are 3 suite admins already. Remove one first',
  );

/** AC-1 */
export const alreadySuiteAdmin = () =>
  conflict('ALREADY_SUITE_ADMIN', 'This person is a suite admin already');

/** AC-1: a suite admin holds no system role, so the person must use a separate account. */
export const holdsSystemRoles = () =>
  conflict(
    'HOLDS_SYSTEM_ROLES',
    'This account holds a system role. A suite admin needs a separate account with no roles',
  );

/** AC-1: inactive, deleted, locked or with an unverified email. */
export const notEligible = () =>
  conflict(
    'NOT_ELIGIBLE',
    'Only an active, unlocked account with a verified email can be a suite admin',
  );

/** AC-2 */
export const lastSuiteAdmin = () =>
  conflict(
    'LAST_SUITE_ADMIN',
    'The suite needs at least one suite admin. Add another one first',
  );

/** AC-2: nobody changes their own admin standing. */
export const selfSuiteAdmin = () =>
  conflict('SELF_ROLE', "You can't remove yourself as a suite admin");

/** AC-3: a suite admin holds no permanent system role. */
export const suiteAdminNoRoles = () =>
  conflict(
    'SUITE_ADMIN_NO_ROLES',
    "A suite admin can't hold a system role. Use temporary access instead",
  );

/** AC-3: remove the suite admin row first. */
export const isSuiteAdmin = () =>
  conflict(
    'IS_SUITE_ADMIN',
    'This person is a suite admin. Remove them as a suite admin first',
  );

/** AC-9: one live grant per person and system. */
export const grantActive = () =>
  conflict(
    'GRANT_ACTIVE',
    'You already have temporary access to this system. End it first',
  );

/** AC-11: a temporary role is ended, never edited. */
export const temporaryRole = () =>
  conflict(
    'TEMPORARY_ROLE',
    'This role is temporary access. End the grant instead of editing it',
  );

/**
 * AC-3: the deferred trigger's error at commit (`suite_admin_no_roles`), however Prisma wraps it.
 */
export function isSuiteAdminNoRolesError(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const text = [
    (error as { message?: unknown }).message,
    JSON.stringify((error as { meta?: unknown }).meta ?? null),
  ]
    .filter((part) => typeof part === 'string')
    .join(' ');
  return text.includes('suite_admin_no_roles');
}
