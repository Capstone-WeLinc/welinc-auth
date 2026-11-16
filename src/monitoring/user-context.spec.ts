import * as Sentry from '@sentry/nestjs';
import type { UserCaller } from '../auth/guards/request-authenticator';
import { portalRole, setSentryPortalUser, setSentryUser } from './user-context';

// covers: VRMS spec 0025 AC-1, AC-6

jest.mock('@sentry/nestjs', () => ({ setUser: jest.fn(), setTag: jest.fn() }));

const caller = (roles: UserCaller['roles']): UserCaller => ({
  kind: 'user',
  sub: 'u1',
  email: 'maria@welinc.com',
  roles,
  system: 'VRMS',
  sid: 's1',
  signInCodeAt: null,
});

describe('setSentryUser', () => {
  beforeEach(() => jest.clearAllMocks());

  it('sets only the id, and the role names for the token system', () => {
    setSentryUser(
      caller([
        { system: 'VRMS', role: 'ADMIN' },
        { system: 'VRMS', role: 'MECHANIC' },
        { system: 'BMS', role: 'DRIVER' },
      ] as UserCaller['roles']),
    );
    expect(Sentry.setUser).toHaveBeenCalledWith({ id: 'u1' });
    expect(Sentry.setTag).toHaveBeenCalledWith('role', 'ADMIN,MECHANIC');
  });

  it('clears the role tag when the caller has no role in the system', () => {
    setSentryUser(caller([]));
    expect(Sentry.setTag).toHaveBeenCalledWith('role', undefined);
  });
});

describe('setSentryPortalUser', () => {
  it('maps the admin standing to the portal role names', () => {
    expect(portalRole({ suiteAdmin: true, adminOf: [] })).toBe('suite_admin');
    expect(portalRole({ suiteAdmin: false, adminOf: ['VRMS'] })).toBe(
      'system_admin',
    );
    expect(portalRole({ suiteAdmin: false, adminOf: [] })).toBe('user');
    setSentryPortalUser('u2', { suiteAdmin: false, adminOf: [] });
    expect(Sentry.setUser).toHaveBeenCalledWith({ id: 'u2' });
    expect(Sentry.setTag).toHaveBeenCalledWith('role', 'user');
  });
});
