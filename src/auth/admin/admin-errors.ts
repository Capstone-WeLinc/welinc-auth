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
