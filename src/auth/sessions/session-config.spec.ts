import { fakeConfig } from '../../config/fake-config.setup';
import { readSessionSettings } from './session-config';

// covers: spec 0003 configuration; limits, defaults and the production rules are checked at boot
// by src/config/env.ts (spec 0010, env.spec.ts)
describe('readSessionSettings', () => {
  it('maps the checked environment, defaults included', () => {
    expect(readSessionSettings(fakeConfig())).toEqual({
      webIdleMinutes: 30,
      webMaxHours: 12,
      mobileIdleDays: 7,
      graceSeconds: 10,
      maxSessionsPerUser: 10,
      retentionDays: 90,
      ssoCookieSecure: false,
      portalOrigin: 'http://localhost:8000',
      portalUrl: 'http://localhost:8000',
    });
  });

  it('reads overrides', () => {
    const s = readSessionSettings(
      fakeConfig({
        WEB_SESSION_IDLE_MINUTES: '5',
        ACCESS_TOKEN_MINUTES: '5',
        REFRESH_REUSE_GRACE_SECONDS: '3',
        SSO_COOKIE_SECURE: 'true',
      }),
    );
    expect(s.webIdleMinutes).toBe(5);
    expect(s.graceSeconds).toBe(3);
    expect(s.ssoCookieSecure).toBe(true);
  });

  it('strips trailing slashes from the portal URL and derives its origin', () => {
    const s = readSessionSettings(
      fakeConfig({ PORTAL_URL: 'https://portal.example.com/app///' }),
    );
    expect(s.portalUrl).toBe('https://portal.example.com/app');
    expect(s.portalOrigin).toBe('https://portal.example.com');
  });
});
