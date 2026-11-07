import { describe, it, expect } from '@jest/globals';
import { ConfigService } from '@nestjs/config';
import { readTokenSettings } from './token-config';

const config = (values: Record<string, string>) => new ConfigService(values);

// covers: spec 0002 Decisions (issuer from AUTH_ISSUER, token lifetimes in minutes)
describe('readTokenSettings', () => {
  it('reads the issuer and falls back to 15 and 5 minutes', () => {
    const settings = readTokenSettings(
      config({ AUTH_ISSUER: 'http://localhost:3000/auth' }),
    );

    expect(settings).toEqual({
      issuer: 'http://localhost:3000/auth',
      accessTokenMinutes: 15,
      serviceTokenMinutes: 5,
    });
  });

  it('takes lifetimes from the environment', () => {
    const settings = readTokenSettings(
      config({
        AUTH_ISSUER: 'x',
        ACCESS_TOKEN_MINUTES: '30',
        SERVICE_TOKEN_MINUTES: '2',
      }),
    );

    expect(settings.accessTokenMinutes).toBe(30);
    expect(settings.serviceTokenMinutes).toBe(2);
  });

  it('trims the issuer but keeps it otherwise exact', () => {
    const settings = readTokenSettings(
      config({ AUTH_ISSUER: '  https://a/b  ' }),
    );

    expect(settings.issuer).toBe('https://a/b');
  });

  it('refuses to start without an issuer', () => {
    expect(() => readTokenSettings(config({}))).toThrow(
      /AUTH_ISSUER is missing/,
    );
    expect(() => readTokenSettings(config({ AUTH_ISSUER: '   ' }))).toThrow(
      /AUTH_ISSUER is missing/,
    );
  });

  it.each(['0', '-3', '1.5', 'abc'])(
    'rejects %s as a token lifetime',
    (bad) => {
      expect(() =>
        readTokenSettings(
          config({ AUTH_ISSUER: 'x', ACCESS_TOKEN_MINUTES: bad }),
        ),
      ).toThrow(/ACCESS_TOKEN_MINUTES must be a whole number/);
    },
  );

  it('treats an empty lifetime as unset', () => {
    const settings = readTokenSettings(
      config({ AUTH_ISSUER: 'x', SERVICE_TOKEN_MINUTES: '' }),
    );

    expect(settings.serviceTokenMinutes).toBe(5);
  });
});
