import type { Request, Response } from 'express';
import {
  clearSsoCookie,
  readSsoCookie,
  setSsoCookie,
  ssoCookieName,
} from './sso-cookie';
import type { SessionSettings } from './session-config';

const local = { ssoCookieSecure: false } as SessionSettings;
const hosted = { ssoCookieSecure: true } as SessionSettings;

function fakeResponse() {
  return {
    cookie: jest.fn(),
    clearCookie: jest.fn(),
  } as unknown as Response & {
    cookie: jest.Mock;
    clearCookie: jest.Mock;
  };
}

describe('SSO cookie (spec 0001 section 7)', () => {
  it('is welinc_sso locally and __Secure-welinc_sso when hosted', () => {
    expect(ssoCookieName(local)).toBe('welinc_sso');
    expect(ssoCookieName(hosted)).toBe('__Secure-welinc_sso');
  });

  it('sets an HttpOnly, SameSite=Lax cookie on /auth that lives to the absolute end', () => {
    jest.useFakeTimers().setSystemTime(new Date('2026-11-08T00:00:00Z'));
    const res = fakeResponse();
    setSsoCookie(res, local, 'handle', new Date('2026-11-08T12:00:00Z'));
    expect(res.cookie).toHaveBeenCalledWith('welinc_sso', 'handle', {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      path: '/auth',
      maxAge: 12 * 3600 * 1000,
    });
    jest.useRealTimers();
  });

  it('marks the hosted cookie Secure', () => {
    const res = fakeResponse();
    setSsoCookie(res, hosted, 'h', new Date(Date.now() + 1000));
    expect((res.cookie.mock.calls[0] as unknown[])[2]).toMatchObject({
      secure: true,
    });
  });

  it('never gives a negative maxAge for a session already past its end', () => {
    const res = fakeResponse();
    setSsoCookie(res, local, 'h', new Date(Date.now() - 60_000));
    expect(
      (res.cookie.mock.calls[0] as [string, string, { maxAge: number }])[2]
        .maxAge,
    ).toBe(0);
  });

  it('clears with the same path and flags it was set with', () => {
    const res = fakeResponse();
    clearSsoCookie(res, hosted);
    expect(res.clearCookie).toHaveBeenCalledWith('__Secure-welinc_sso', {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,
      path: '/auth',
    });
  });

  it('reads the cookie by its environment name, and answers undefined without cookies', () => {
    const req = {
      cookies: { welinc_sso: 'abc', '__Secure-welinc_sso': 'secure' },
    } as unknown as Request;
    expect(readSsoCookie(req, local)).toBe('abc');
    expect(readSsoCookie(req, hosted)).toBe('secure');
    expect(readSsoCookie({} as Request, local)).toBeUndefined();
  });
});
