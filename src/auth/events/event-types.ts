import {
  AccountEventCategory,
  AccountEventType,
  SessionEndReason,
  VerificationPurpose,
} from '@prisma/client';

// Spec 0011: the one place that says which category each event type belongs to, and the
// English labels the public catalog serves (AC-15). The migration's CHECK constraint is written
// from TYPE_CATEGORY; event-types.spec.ts keeps the map, the catalog and the enums equal.

const C = AccountEventCategory;
const T = AccountEventType;

export const TYPE_CATEGORY: Record<AccountEventType, AccountEventCategory> = {
  [T.SIGNED_IN]: C.SIGN_IN,
  [T.SIGN_IN_FAILED]: C.SIGN_IN,
  [T.LOCKED_OUT]: C.SIGN_IN,
  [T.SYSTEM_OPENED]: C.SESSION,
  [T.SIGNED_OUT]: C.SESSION,
  [T.SESSION_ENDED]: C.SESSION,
  [T.CODE_SENT]: C.CODE,
  [T.CODE_MAIL_FAILED]: C.CODE,
  [T.CODE_USED]: C.CODE,
  [T.CODE_RETIRED]: C.CODE,
  [T.CREATED]: C.ACCOUNT,
  [T.UPDATED]: C.ACCOUNT,
  [T.ROLE_CHANGED]: C.ACCOUNT,
  [T.ACTIVATED]: C.ACCOUNT,
  [T.DEACTIVATED]: C.ACCOUNT,
  [T.UNLOCKED]: C.ACCOUNT,
  [T.DELETED]: C.ACCOUNT,
  [T.SESSIONS_ENDED]: C.ACCOUNT,
  [T.PASSWORD_CHANGED]: C.ACCOUNT,
  [T.PICTURE_CHANGED]: C.ACCOUNT,
  // Spec 0012
  [T.PASSWORD_CONFIRMED]: C.SIGN_IN,
  [T.PASSWORD_CONFIRM_FAILED]: C.SIGN_IN,
  [T.DELETION_REQUESTED]: C.ACCOUNT,
  [T.DELETION_CANCELLED]: C.ACCOUNT,
  [T.DELETION_REJECTED]: C.ACCOUNT,
  [T.RESTORED]: C.ACCOUNT,
  [T.ERASED]: C.ACCOUNT,
  // Spec 0013
  [T.SUITE_ADMIN_ACTIONED]: C.ACCOUNT,
  [T.SUITE_ADMIN_REMOVED]: C.ACCOUNT,
  [T.TEMP_ACCESS_STARTED]: C.ACCOUNT,
  [T.TEMP_ACCESS_ENDED]: C.ACCOUNT,
  [T.ADMIN_RECOVERY]: C.ACCOUNT,
  [T.ADMIN_CODE_PASSED]: C.SIGN_IN,
};

/** Why a sign in was refused (AC-1). */
export const SignInFailReason = {
  WRONG_PASSWORD: 'WRONG_PASSWORD',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  ACCOUNT_INACTIVE: 'ACCOUNT_INACTIVE',
  NO_SYSTEM_ACCESS: 'NO_SYSTEM_ACCESS',
  APP_NOT_ALLOWED: 'APP_NOT_ALLOWED',
} as const;
export type SignInFailReason =
  (typeof SignInFailReason)[keyof typeof SignInFailReason];

/** Spec 0012, AC-2: what a password recheck was for (the `reason` of PASSWORD_CONFIRM*). */
export const PasswordCheckReason = {
  ACCOUNT_DELETION: 'ACCOUNT_DELETION',
  EMAIL_CHANGE: 'EMAIL_CHANGE',
  PASSWORD_CHANGE: 'PASSWORD_CHANGE',
  // Spec 0013, AC-14
  ADMIN_ACTION: 'ADMIN_ACTION',
  TEMPORARY_ACCESS: 'TEMPORARY_ACCESS',
} as const;
export type PasswordCheckReason =
  (typeof PasswordCheckReason)[keyof typeof PasswordCheckReason];

/** Spec 0012, AC-10, AC-13: the `reason` of a DELETED that closed a person's own request. */
export const DELETION_REQUEST_REASON = 'DELETION_REQUEST';

const CATEGORY_LABELS: Record<AccountEventCategory, string> = {
  [C.SIGN_IN]: 'Sign in',
  [C.SESSION]: 'Sessions',
  [C.CODE]: 'Email codes',
  [C.ACCOUNT]: 'Account changes',
};

/** `label` for everyone; `labelAdmin` for the person's own view of an admin's action. */
const TYPE_LABELS: Record<
  AccountEventType,
  { label: string; labelAdmin?: string }
> = {
  [T.SIGNED_IN]: { label: 'Signed in' },
  [T.SIGN_IN_FAILED]: { label: 'Sign in failed' },
  [T.LOCKED_OUT]: { label: 'Locked out after too many wrong passwords' },
  [T.SYSTEM_OPENED]: { label: 'Opened a system' },
  [T.SIGNED_OUT]: { label: 'Signed out' },
  [T.SESSION_ENDED]: {
    label: 'Session ended',
    labelAdmin: 'An admin ended a session',
  },
  [T.CODE_SENT]: {
    label: 'Code sent by email',
    labelAdmin: 'An admin sent you a code',
  },
  [T.CODE_MAIL_FAILED]: { label: 'Code email could not be sent' },
  [T.CODE_USED]: { label: 'Code used' },
  [T.CODE_RETIRED]: { label: 'Code stopped working after 5 wrong tries' },
  [T.CREATED]: {
    label: 'Account created',
    labelAdmin: 'An admin created your account',
  },
  [T.UPDATED]: {
    label: 'Details changed',
    labelAdmin: 'An admin changed your details',
  },
  [T.ROLE_CHANGED]: {
    label: 'Role changed',
    labelAdmin: 'An admin changed your role',
  },
  [T.ACTIVATED]: {
    label: 'Account activated',
    labelAdmin: 'An admin activated your account',
  },
  [T.DEACTIVATED]: {
    label: 'Account deactivated',
    labelAdmin: 'An admin deactivated your account',
  },
  [T.UNLOCKED]: {
    label: 'Account unlocked',
    labelAdmin: 'An admin unlocked your account',
  },
  [T.DELETED]: {
    label: 'Account deleted',
    labelAdmin: 'An admin deleted your account',
  },
  [T.SESSIONS_ENDED]: {
    label: 'Signed out everywhere',
    labelAdmin: 'An admin signed you out everywhere',
  },
  [T.PASSWORD_CHANGED]: { label: 'Password changed' },
  [T.PICTURE_CHANGED]: { label: 'Profile picture changed' },
  [T.PASSWORD_CONFIRMED]: { label: 'Password confirmed' },
  [T.PASSWORD_CONFIRM_FAILED]: { label: 'Password confirmation failed' },
  [T.DELETION_REQUESTED]: { label: 'Asked for account deletion' },
  [T.DELETION_CANCELLED]: { label: 'Cancelled the deletion request' },
  [T.DELETION_REJECTED]: {
    label: 'Deletion request rejected',
    labelAdmin: 'An admin rejected your deletion request',
  },
  [T.RESTORED]: {
    label: 'Account restored',
    labelAdmin: 'An admin restored your account',
  },
  [T.ERASED]: { label: 'Personal data erased' },
  [T.SUITE_ADMIN_ACTIONED]: {
    label: 'Made a suite admin',
    labelAdmin: 'A suite admin made you a suite admin',
  },
  [T.SUITE_ADMIN_REMOVED]: {
    label: 'No longer a suite admin',
    labelAdmin: 'A suite admin removed you as suite admin',
  },
  [T.TEMP_ACCESS_STARTED]: { label: 'Temporary access started' },
  // No admin wording: the minute sweep ends most grants, and `newValue` says how it ended
  [T.TEMP_ACCESS_ENDED]: { label: 'Temporary access ended' },
  [T.ADMIN_RECOVERY]: { label: 'Admin access recovered from the server' },
  [T.ADMIN_CODE_PASSED]: { label: 'Admin sign in confirmed with a code' },
};

/** Every `reason` value: sign in fails, session end reasons and code purposes. */
const REASON_LABELS: Record<string, string> = {
  [SignInFailReason.WRONG_PASSWORD]: 'Wrong password',
  [SignInFailReason.ACCOUNT_LOCKED]: 'Account locked',
  [SignInFailReason.ACCOUNT_INACTIVE]: 'Account not active',
  [SignInFailReason.NO_SYSTEM_ACCESS]: 'No access to any system',
  [SignInFailReason.APP_NOT_ALLOWED]: 'This app is not allowed for the role',
  [SessionEndReason.LOGOUT]: 'Signed out',
  [SessionEndReason.IDLE]: 'Idle too long',
  [SessionEndReason.MAX_AGE]: 'Session reached its time limit',
  [SessionEndReason.USER_ENDED]: 'Ended from your sessions list',
  [SessionEndReason.ADMIN_ENDED]: 'Ended by an admin',
  [SessionEndReason.DEACTIVATED]: 'Account deactivated',
  [SessionEndReason.DELETED]: 'Account deleted',
  [SessionEndReason.PASSWORD_CHANGED]: 'Password changed',
  [SessionEndReason.REFRESH_REUSE]: 'An old sign in token was used again',
  [SessionEndReason.CODE_REUSE]: 'An old login code was used again',
  [SessionEndReason.MAX_SESSIONS]: 'Too many sessions at once',
  [SessionEndReason.TEMP_ACCESS_ENDED]: 'Temporary access ended',
  [VerificationPurpose.PASSWORD_SETUP]: 'Password setup',
  [VerificationPurpose.PASSWORD_RESET]: 'Password reset',
  [VerificationPurpose.SIGN_IN]: 'Sign in',
  [VerificationPurpose.EMAIL_CHANGE]: 'Email change',
  // Spec 0012 (ACCOUNT_LOCKED above doubles as the locked recheck reason)
  [PasswordCheckReason.ACCOUNT_DELETION]: 'Account deletion',
  [PasswordCheckReason.PASSWORD_CHANGE]: 'Password change',
  [PasswordCheckReason.ADMIN_ACTION]: 'Admin action',
  [PasswordCheckReason.TEMPORARY_ACCESS]: 'Temporary access',
  [DELETION_REQUEST_REASON]: 'The person asked for it',
};

export type EventCatalog = {
  categories: { code: AccountEventCategory; label: string }[];
  types: {
    code: AccountEventType;
    category: AccountEventCategory;
    label: string;
    labelAdmin: string;
  }[];
  reasons: { code: string; label: string }[];
};

/** The `GET /auth/activity/catalog` body, in enum order (AC-15). */
export const EVENT_CATALOG: EventCatalog = {
  categories: Object.values(C).map((code) => ({
    code,
    label: CATEGORY_LABELS[code],
  })),
  types: Object.values(T).map((code) => ({
    code,
    category: TYPE_CATEGORY[code],
    label: TYPE_LABELS[code].label,
    labelAdmin: TYPE_LABELS[code].labelAdmin ?? TYPE_LABELS[code].label,
  })),
  reasons: Object.entries(REASON_LABELS).map(([code, label]) => ({
    code,
    label,
  })),
};
