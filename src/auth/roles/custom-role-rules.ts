import { CUSTOM_ROLE_PREFIX } from './catalog-plan';

// Suite spec 0018 (umbrella rules, child 0002 AC-22): the pure rules of a custom role's name,
// description and code. The service runs them inside its transaction.

/** At most this many live custom roles per system (AC-22). */
export const CUSTOM_ROLE_LIMIT = 20;
export const ROLE_NAME_MIN = 2;
export const ROLE_NAME_MAX = 40;
export const ROLE_DESCRIPTION_MAX = 200;

/** The code body (after `C_`) is cut to this, so a code with `_99` stays within 30 characters. */
const CODE_BODY_MAX = 24;
const SUFFIX_MAX = 99;

export const NAME_LENGTH_MESSAGE = `Name needs ${ROLE_NAME_MIN} to ${ROLE_NAME_MAX} characters.`;
export const NAME_LETTERS_MESSAGE = 'Use letters or numbers in the name.';
export const DESCRIPTION_LENGTH_MESSAGE = `Description can have at most ${ROLE_DESCRIPTION_MAX} characters.`;

/** The upper case code body a name makes: every run of other characters becomes `_`. */
export function codeBody(name: string): string {
  return name
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, CODE_BODY_MAX)
    .replace(/_+$/, '');
}

/** The problem with a trimmed name, or null when it is fine. */
export function nameProblem(name: string): string | null {
  if (name.length < ROLE_NAME_MIN || name.length > ROLE_NAME_MAX) {
    return NAME_LENGTH_MESSAGE;
  }
  if (codeBody(name) === '') return NAME_LETTERS_MESSAGE;
  return null;
}

/**
 * `C_<body>`, then `_2` to `_99` on a clash with any code the system ever had (live, archived,
 * or the catalog's). Null when every suffix is taken. A code starting with a digit is fine:
 * `C_` keeps it within `ROLE_CODE_RE`.
 */
export function pickRoleCode(
  body: string,
  taken: ReadonlySet<string>,
): string | null {
  const base = `${CUSTOM_ROLE_PREFIX}${body}`;
  if (!taken.has(base)) return base;
  for (let n = 2; n <= SUFFIX_MAX; n += 1) {
    const code = `${base}_${n}`;
    if (!taken.has(code)) return code;
  }
  return null;
}

/** "There's already a role called Tire specialist in VRMS." (AC-22) */
export function nameTakenMessage(name: string, system: string): string {
  return `There's already a role called ${name} in ${system}.`;
}

/** AC-22: the limit message the portal also shows on the disabled buttons. */
export function customRoleLimitMessage(system: string): string {
  return `${system} has ${CUSTOM_ROLE_LIMIT} custom roles, the most it can have. Delete one to make another.`;
}

/** AC-23: the note on every cell a create copies. */
export function createdFromNote(source: string): string {
  return `Created from ${source}`.slice(0, 500);
}
