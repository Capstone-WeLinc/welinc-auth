import { describe, it, expect, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import type { Request, Response } from 'express';
import type { PrismaService } from '../../shared/prisma.service';
import type { AdminStandingService } from '../admin/admin-standing.service';
import type { AuthService } from '../auth.service';
import type { SignInStepService } from '../codes/sign-in-step.service';
import type { TokenService } from '../tokens/token.service';
import type { AuthorizeService } from './authorize.service';
import type { LauncherService } from './launcher';
import type { SessionSettings } from './session-config';
import type { SessionService } from './session.service';
import { LOGIN_LIMIT, SSO_LIMIT, SsoController } from './sso.controller';

// covers: spec 0007 AC-1 (401, no-store, no activity), AC-3 (no session without a system), AC-4;
// suite spec 0009 AC-6, AC-7, AC-9 (the sign in step on the portal routes)

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
  emailVerified: true,
};
const STEP = {
  status: 'EMAIL_VERIFICATION_REQUIRED',
  challengeId: 'c'.repeat(43),
  email: 'm@welinc.com',
  resendAfter: 60,
};

function build(hits = 1) {
  const auth = {
    checkCredentials: fn().mockResolvedValue({ user: USER }),
    assertCanSignIn: fn().mockResolvedValue(USER),
    // Runs the check as is; the real one also records a refusal (spec 0011)
    withSignInCheck: fn().mockImplementation(
      (_userId: string, _meta: unknown, check: () => Promise<unknown>) =>
        check(),
    ),
  };
  const signInStep = {
    start: fn().mockResolvedValue(STEP),
    // Runs the precheck the way the real service does, then answers the user id
    verify: fn().mockImplementation(
      async (_c: string, _code: string, pre: (id: string) => Promise<void>) => {
        await pre('u1');
        return 'u1';
      },
    ),
    resend: fn().mockResolvedValue({ resendAfter: 60 }),
  };
  const sessions = {
    liveBySsoHandle: fn().mockResolvedValue({ id: 'sid', user: USER }),
    createWeb: fn().mockResolvedValue({
      session: { absoluteExpiresAt: new Date() },
      handle: 'h',
    }),
    touch: fn(),
  };
  const launcher = { answerFor: fn().mockResolvedValue(ANSWER) };
  const admins = { asksCodeAtLogin: fn().mockResolvedValue(false) };
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
    signInStep as unknown as SignInStepService,
    admins as unknown as AdminStandingService,
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
    signInStep,
    admins,
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

  // covers: AC-1 (the call never counts as activity)
  it('never counts as activity, with or without a live session', async () => {
    const live = build();
    await live.controller.sso(live.req, live.res);
    expect(live.sessions.touch).not.toHaveBeenCalled();

    const ended = build();
    ended.sessions.liveBySsoHandle.mockResolvedValue(null);
    await refusal(ended.controller.sso(ended.req, ended.res));
    expect(ended.sessions.touch).not.toHaveBeenCalled();
  });

  // covers: AC-1 (the no access 403 keeps its body: the launcher service builds the email)
  it('passes the no access answer through unchanged, with its email', async () => {
    const t = build();
    const body = { code: 'NO_SYSTEM_ACCESS', user: { email: 'm@welinc.com' } };
    t.launcher.answerFor.mockRejectedValue(new HttpException(body, 403));
    const error = await t.controller.sso(t.req, t.res).then(
      () => null,
      (e: unknown) => e as HttpException,
    );
    expect(error?.getStatus()).toBe(403);
    expect(error?.getResponse()).toEqual(body);
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
  // covers: contract 0001 section 12 (10 a minute per address, 429 RATE_LIMITED with Retry-After)
  it('answers 429 RATE_LIMITED with Retry-After on the 11th call, before any password check', async () => {
    const t = build(LOGIN_LIMIT.limit + 1);
    expect(
      await refusal(
        t.controller.login(
          { email: 'm@welinc.com', password: 'x' },
          t.req,
          t.res,
        ),
      ),
    ).toEqual([429, 'RATE_LIMITED']);
    expect(t.headers['Retry-After']).toBe('42');
    expect(t.auth.checkCredentials).not.toHaveBeenCalled();
  });

  it('counts the 10th call as allowed', async () => {
    const t = build(LOGIN_LIMIT.limit);
    await t.controller.login(
      { email: 'm@welinc.com', password: 'x' },
      t.req,
      t.res,
    );
    expect(t.auth.checkCredentials).toHaveBeenCalled();
  });

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

  // covers: AC-3 (the systems list is built after the password check, before the session)
  it('checks the password first, then builds the answer for that user, then creates the session', async () => {
    const t = build();
    await t.controller.login(
      { email: 'm@welinc.com', password: 'x' },
      t.req,
      t.res,
    );
    const check = t.auth.checkCredentials.mock.invocationCallOrder[0];
    const answer = t.launcher.answerFor.mock.invocationCallOrder[0];
    const create = t.sessions.createWeb.mock.invocationCallOrder[0];
    expect(check).toBeLessThan(answer);
    expect(answer).toBeLessThan(create);
    expect(t.launcher.answerFor).toHaveBeenCalledWith(USER);
  });

  // covers: AC-3, security (a wrong password leaks nothing and starts nothing)
  it('builds no answer, session or cookie when the credentials are refused', async () => {
    const t = build();
    t.auth.checkCredentials.mockRejectedValue(
      new HttpException({ code: 'INVALID_CREDENTIALS' }, 401),
    );
    expect(
      await refusal(
        t.controller.login(
          { email: 'm@welinc.com', password: 'wrong' },
          t.req,
          t.res,
        ),
      ),
    ).toEqual([401, 'INVALID_CREDENTIALS']);
    expect(t.launcher.answerFor).not.toHaveBeenCalled();
    expect(t.sessions.createWeb).not.toHaveBeenCalled();
    expect(t.cookie).not.toHaveBeenCalled();
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

describe('the admin sign in code (suite spec 0013)', () => {
  const login = (t: ReturnType<typeof build>) =>
    t.controller.login({ email: 'm@welinc.com', password: 'x' }, t.req, t.res);

  // covers: AC-5
  it('answers SIGN_IN_CODE_REQUIRED for a verified admin, with no session and no cookie', async () => {
    const t = build();
    t.admins.asksCodeAtLogin.mockResolvedValue(true);
    await login(t);
    expect(t.admins.asksCodeAtLogin).toHaveBeenCalledWith('u1');
    expect(t.signInStep.start).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'u1' }),
      expect.objectContaining({ ip: '10.0.0.1' }),
      'SIGN_IN_CODE_REQUIRED',
    );
    expect(t.sessions.createWeb).not.toHaveBeenCalled();
    expect(t.cookie).not.toHaveBeenCalled();
  });

  // covers: AC-5 (one code only, even for an unverified admin)
  it('asks the email code, not a second one, for an unverified admin', async () => {
    const t = build();
    t.admins.asksCodeAtLogin.mockResolvedValue(true);
    t.auth.checkCredentials.mockResolvedValue({
      user: { ...USER, emailVerified: false },
    });
    await login(t);
    expect(t.signInStep.start).toHaveBeenCalledTimes(1);
    expect(t.signInStep.start.mock.calls[0]).toHaveLength(2);
  });

  it('starts a session with no code mark after a plain password login', async () => {
    const t = build();
    await login(t);
    expect(t.sessions.createWeb).toHaveBeenCalledWith(
      expect.objectContaining({ codePassed: undefined }),
    );
  });

  // covers: AC-5, AC-7 (sign_in_code_at on any code finish; ADMIN_CODE_PASSED only for an admin)
  it.each([
    [true, { admin: true }],
    [false, { admin: false }],
  ])(
    'marks the session after the code step (admin %s)',
    async (admin, codePassed) => {
      const t = build();
      t.admins.asksCodeAtLogin.mockResolvedValue(admin);
      await t.controller.verifyEmail(
        { challengeId: STEP.challengeId, code: '123456' },
        t.req,
        t.res,
      );
      expect(t.sessions.createWeb).toHaveBeenCalledWith(
        expect.objectContaining({ codePassed }),
      );
    },
  );
});

describe('the sign in step (suite spec 0009)', () => {
  const login = (t: ReturnType<typeof build>) =>
    t.controller.login({ email: 'm@welinc.com', password: 'x' }, t.req, t.res);

  // covers: AC-7
  it('answers the step body for an unverified email, with no session and no cookie', async () => {
    const t = build();
    t.auth.checkCredentials.mockResolvedValue({
      user: { ...USER, emailVerified: false },
    });
    expect(await login(t)).toBe(STEP);
    expect(t.headers['Cache-Control']).toBe('no-store');
    expect(t.signInStep.start).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'u1', email: 'm@welinc.com' }),
      expect.objectContaining({ ip: '10.0.0.1' }),
    );
    expect(t.sessions.createWeb).not.toHaveBeenCalled();
    expect(t.cookie).not.toHaveBeenCalled();
  });

  // covers: AC-7 (the step comes after NO_SYSTEM_ACCESS: no code to someone without a system)
  it('sends no code to someone with no system', async () => {
    const t = build();
    t.auth.checkCredentials.mockResolvedValue({
      user: { ...USER, emailVerified: false },
    });
    t.launcher.answerFor.mockRejectedValue(
      new HttpException({ code: 'NO_SYSTEM_ACCESS' }, 403),
    );
    expect(await refusal(login(t))).toEqual([403, 'NO_SYSTEM_ACCESS']);
    expect(t.signInStep.start).not.toHaveBeenCalled();
  });

  it('never starts the step for a verified email', async () => {
    const t = build();
    await login(t);
    expect(t.signInStep.start).not.toHaveBeenCalled();
  });

  // covers: AC-9 (step 2 then step 5: account and systems checked again, login finished the same way)
  it('finishes a right code exactly as a login does', async () => {
    const t = build();
    const answer = await t.controller.verifyEmail(
      { challengeId: STEP.challengeId, code: '123456' },
      t.req,
      t.res,
    );
    expect(answer).toBe(ANSWER);
    expect(t.auth.assertCanSignIn).toHaveBeenCalledWith(
      'u1',
      expect.objectContaining({ ip: '10.0.0.1' }),
    );
    expect(t.launcher.answerFor).toHaveBeenCalledWith(USER);
    expect(t.sessions.createWeb).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'u1',
        previousHandle: 'h',
        meta: expect.objectContaining({ ip: '10.0.0.1' }),
      }),
    );
    expect(t.cookie).toHaveBeenCalled();
    expect(t.headers['Cache-Control']).toBe('no-store');
  });

  it('creates no session when the account check refuses', async () => {
    const t = build();
    t.auth.assertCanSignIn.mockRejectedValue(
      new HttpException({ code: 'ACCOUNT_LOCKED' }, 403),
    );
    expect(
      await refusal(
        t.controller.verifyEmail(
          { challengeId: STEP.challengeId, code: '123456' },
          t.req,
          t.res,
        ),
      ),
    ).toEqual([403, 'ACCOUNT_LOCKED']);
    expect(t.sessions.createWeb).not.toHaveBeenCalled();
  });

  // covers: AC-6
  it.each([
    [
      'verify',
      (t: ReturnType<typeof build>) =>
        t.controller.verifyEmail(
          { challengeId: STEP.challengeId, code: '123456' },
          t.req,
          t.res,
        ),
    ],
    [
      'resend',
      (t: ReturnType<typeof build>) =>
        t.controller.resendEmailCode(
          { challengeId: STEP.challengeId },
          t.req,
          t.res,
        ),
    ],
  ])(
    'counts %s per address as code-signin and refuses the 11th call',
    async (_l, call) => {
      const allowed = build(10);
      await call(allowed);
      expect(allowed.storage.increment).toHaveBeenCalledWith(
        'code-signin:10.0.0.1',
        60_000,
        10,
        0,
        'code-signin',
      );

      const refused = build(11);
      expect(await refusal(call(refused))).toEqual([429, 'RATE_LIMITED']);
      expect(refused.headers['Retry-After']).toBe('42');
      expect(refused.signInStep.verify).not.toHaveBeenCalled();
      expect(refused.signInStep.resend).not.toHaveBeenCalled();
    },
  );

  // covers: AC-10
  it('resends on the same ticket', async () => {
    const t = build();
    expect(
      await t.controller.resendEmailCode(
        { challengeId: STEP.challengeId },
        t.req,
        t.res,
      ),
    ).toEqual({ resendAfter: 60 });
    expect(t.signInStep.resend).toHaveBeenCalledWith(
      STEP.challengeId,
      expect.objectContaining({ ip: '10.0.0.1' }),
    );
  });
});
