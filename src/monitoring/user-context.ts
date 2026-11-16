import * as Sentry from '@sentry/nestjs';
import type { AdminStanding } from '../auth/admin/admin-standing.service';
import type { UserCaller } from '../auth/guards/request-authenticator';

// VRMS spec 0025, AC-1: the signed in caller on this request's events, as an id and role names
// only (never an email, a name, a permission key or an address). Sentry keeps one scope per
// request, so this never leaks into another caller's events.

/** A bearer caller: the role names it holds in its token's system. None there, no tag. */
export function setSentryUser(caller: UserCaller): void {
  Sentry.setUser({ id: caller.sub });
  const roles = caller.roles
    .filter((entry) => entry.system === caller.system)
    .map((entry) => entry.role);
  Sentry.setTag('role', roles.length ? roles.join(',') : undefined);
}

/** A portal cookie caller of `/auth/admin/*`: the same role names the portal tags its events with. */
export function setSentryPortalUser(
  userId: string,
  standing: AdminStanding,
): void {
  Sentry.setUser({ id: userId });
  Sentry.setTag('role', portalRole(standing));
}

export function portalRole(standing: AdminStanding): string {
  if (standing.suiteAdmin) return 'suite_admin';
  return standing.adminOf.length ? 'system_admin' : 'user';
}
