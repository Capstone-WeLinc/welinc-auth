import type { ConfigService } from '@nestjs/config';
import { readSessionSettings } from './session-config';

const config = (values: Record<string, string | undefined>) =>
  ({ get: (name: string) => values[name] }) as unknown as ConfigService;

describe('readSessionSettings (spec 0003 configuration)', () => {
  it('uses the spec defaults when nothing is set', () => {
    expect(readSessionSettings(config({}))).toEqual({
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

  it('reads overrides and treats an empty value as unset', () => {
    const s = readSessionSettings(
      config({
        WEB_SESSION_IDLE_MINUTES: '5',
        MAX_SESSIONS_PER_USER: '',
        REFRESH_REUSE_GRACE_SECONDS: '3',
      }),
    );
    expect(s.webIdleMinutes).toBe(5);
    expect(s.maxSessionsPerUser).toBe(10);
    expect(s.graceSeconds).toBe(3);
  });

  it.each(['0', '-1', '1.5', 'abc'])('rejects %p as a limit', (bad) => {
    expect(() =>
      readSessionSettings(config({ WEB_SESSION_MAX_HOURS: bad })),
    ).toThrow('WEB_SESSION_MAX_HOURS must be a whole number, at least 1');
  });

  it('strips trailing slashes from the portal URL and derives its origin', () => {
    const s = readSessionSettings(
      config({ PORTAL_URL: 'https://portal.example.com/app///' }),
    );
    expect(s.portalUrl).toBe('https://portal.example.com/app');
    expect(s.portalOrigin).toBe('https://portal.example.com');
  });

  it('requires PORTAL_URL in production only', () => {
    expect(() =>
      readSessionSettings(config({ NODE_ENV: 'production' })),
    ).toThrow('PORTAL_URL is required in production');
    expect(() =>
      readSessionSettings(config({ NODE_ENV: 'development' })),
    ).not.toThrow();
  });

  it.each([
    ['true', true],
    ['1', true],
    [' TRUE ', true],
    ['false', false],
    ['yes', false],
    [undefined, false],
  ])('reads SSO_COOKIE_SECURE=%p as %p', (raw, expected) => {
    expect(
      readSessionSettings(config({ SSO_COOKIE_SECURE: raw })).ssoCookieSecure,
    ).toBe(expected);
  });
});
