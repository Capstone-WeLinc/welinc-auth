import { describe, it, expect, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import type { Request, Response } from 'express';
import type { PrismaService } from '../../shared/prisma.service';
import type { AuthService } from '../auth.service';
import type { TokenService } from '../tokens/token.service';
import type { AuthorizeService } from './authorize.service';
import type { LauncherService } from './launcher';
import type { SessionSettings } from './session-config';
import type { SessionService } from './session.service';
import { SSO_LIMIT, SsoController } from './sso.controller';

// covers: spec 0007 AC-1 (401, no-store, no activity), AC-3 (no session without a system), AC-4

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const ANSWER = {
  user: { id: 'u1', name: 'Mara', email: 'm@welinc.com', picture: null },
  systems: [],
};
const USER = {
  id: 'u1',
  name: 'Mara',
  email: 'm@welinc.com',
  profilePicture: null,
};

function build(hits = 1) {
  const auth = { checkCredentials: fn().mockResolvedValue({ user: USER }) };
  const sessions = {
    liveBySsoHandle: fn().mockResolvedValue({ id: 'sid', user: USER }),
    createWeb: fn().mockResolvedValue({
      session: { absoluteExpiresAt: new Date() },
      handle: 'h',
    }),
    touch: fn(),
  };
  const launcher = { answerFor: fn().mockResolvedValue(ANSWER) };
  const storage = {
    increment: fn().mockResolvedValue({ totalHits: hits, timeToExpire: 42 }),
  };
  const controller = new SsoController(
    auth as unknown as AuthService,
    sessions as unknown as SessionService,
    {} as AuthorizeService,
    {} as TokenService,
    {} as PrismaService,
    launcher as unknown as LauncherService,
    { ssoCookieSecure: false } as SessionSettings,
    storage,
  );
  const cookie = fn();
  const headers: Record<string, string> = {};
  const res = {
    setHeader: (k: string, v: string) => (headers[k] = v),
    cookie,
  } as unknown as Response;
  const req = {
    ip: '10.0.0.1',
    cookies: { welinc_sso: 'h' },
    headers: {},
  } as unknown as Request;
  return {
    controller,
    auth,
    sessions,
    launcher,
    storage,
    res,
    req,
    headers,
    cookie,
  };
}

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  const http = error as HttpException;
  return [http.getStatus(), (http.getResponse() as { code: string }).code];
}

describe('GET /auth/sso', () => {
  it('answers the launcher body with no-store, counted per address', async () => {
    const t = build();
    expect(await t.controller.sso(t.req, t.res)).toBe(ANSWER);
    expect(t.headers['Cache-Control']).toBe('no-store');
    expect(t.storage.increment).toHaveBeenCalledWith(
      'sso:10.0.0.1',
      SSO_LIMIT.ttlMs,
      60,
      0,
      'sso',
    );
    expect(t.launcher.answerFor).toHaveBeenCalledWith(USER);
  });

  it('answers 401 SESSION_ENDED without a live session', async () => {
    const t = build();
    t.sessions.liveBySsoHandle.mockResolvedValue(null);
    expect(await refusal(t.controller.sso(t.req, t.res))).toEqual([
      401,
      'SESSION_ENDED',
    ]);
    expect(t.launcher.answerFor).not.toHaveBeenCalled();
  });

  it('answers 429 RATE_LIMITED with Retry-After on the 61st call', async () => {
    const t = build(61);
    expect(await refusal(t.controller.sso(t.req, t.res))).toEqual([
      429,
      'RATE_LIMITED',
    ]);
    expect(t.headers['Retry-After']).toBe('42');
    expect(t.sessions.liveBySsoHandle).not.toHaveBeenCalled();
  });
});

describe('POST /auth/login', () => {
  it('answers the launcher body and sets the SSO cookie', async () => {
    const t = build();
    const answer = await t.controller.login(
      { email: 'm@welinc.com', password: 'x' },
      t.req,
      t.res,
    );
    expect(answer).toBe(ANSWER);
    expect(t.sessions.createWeb).toHaveBeenCalled();
    expect(t.cookie).toHaveBeenCalled();
  });

  it('creates no session and no cookie when no usable system is left', async () => {
    const t = build();
    t.launcher.answerFor.mockRejectedValue(
      new HttpException({ code: 'NO_SYSTEM_ACCESS' }, 403),
    );
    expect(
      await refusal(
        t.controller.login(
          { email: 'm@welinc.com', password: 'x' },
          t.req,
          t.res,
        ),
      ),
    ).toEqual([403, 'NO_SYSTEM_ACCESS']);
    expect(t.sessions.createWeb).not.toHaveBeenCalled();
    expect(t.cookie).not.toHaveBeenCalled();
  });
});
