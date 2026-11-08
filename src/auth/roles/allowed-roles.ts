import type { SystemType } from '@prisma/client';
import type { RoleAssignment } from './catalog.types';

// Spec 0004, AC-18, AC-19: which roles a client (an app) may serve, per audience.

/**
 * The role codes `client` allows for `aud`, or null when it names no list for that system (every
 * role may use the client). Anything but an array of strings reads as no list.
 */
export function allowedCodes(
  allowedRoles: unknown,
  aud: SystemType,
): string[] | null {
  if (!allowedRoles || typeof allowedRoles !== 'object') return null;
  const list = (allowedRoles as Record<string, unknown>)[aud];
  if (!Array.isArray(list)) return null;
  return list.filter((code): code is string => typeof code === 'string');
}

/** The held roles the client may carry in a token for `aud`. */
export function filterAllowed<T extends RoleAssignment>(
  held: T[],
  allowed: string[] | null,
): T[] {
  return allowed === null ? held : held.filter((r) => allowed.includes(r.role));
}

/** `Mechanic`, `Mechanic and Chief Mechanic`, `Driver, Helper and Admin`. */
export function joinNames(names: string[]): string {
  if (names.length <= 1) return names.join('');
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/** The APP_NOT_ALLOWED message (AC-19). */
export function appNotAllowedMessage(names: string[]): string {
  return names.length === 0
    ? 'This app is not for your account.'
    : `This app is for ${joinNames(names)} accounts.`;
}
