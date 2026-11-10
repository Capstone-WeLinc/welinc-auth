import { describe, it, expect } from '@jest/globals';
import { fakeConfig } from '../../config/fake-config.setup';
import { readTokenSettings } from './token-config';

// covers: spec 0002 Decisions (issuer from AUTH_ISSUER, token lifetimes in minutes). Presence,
// ranges and defaults are checked at boot by src/config/env.ts (spec 0010, env.spec.ts).
describe('readTokenSettings', () => {
  it('reads the issuer and falls back to 15 and 5 minutes', () => {
    expect(readTokenSettings(fakeConfig())).toEqual({
      issuer: 'http://localhost:3000/auth',
      accessTokenMinutes: 15,
      serviceTokenMinutes: 5,
    });
  });

  it('takes lifetimes from the environment', () => {
    const settings = readTokenSettings(
      fakeConfig({ ACCESS_TOKEN_MINUTES: '30', SERVICE_TOKEN_MINUTES: '2' }),
    );

    expect(settings.accessTokenMinutes).toBe(30);
    expect(settings.serviceTokenMinutes).toBe(2);
  });

  it('trims the issuer but keeps it otherwise exact', () => {
    const settings = readTokenSettings(
      fakeConfig({ AUTH_ISSUER: '  https://a/b  ' }),
    );

    expect(settings.issuer).toBe('https://a/b');
  });
});
