import { describe, it, expect, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import type { Request, Response } from 'express';
import type { AuthService } from '../auth.service';
import type { TokenEndpointService } from '../clients/token-endpoint.service';
import type { SignInStepService } from '../codes/sign-in-step.service';
import { MobileController } from './mobile.controller';
import type { UserGrantsService } from './user-grants.service';

// covers: suite spec 0009 AC-6 (mobile shape), AC-11 (the email step on the mobile login)

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const CLIENT = { id: 'vmms-mobile', system: 'VMMS', grants: ['mobile_login'] };
const USER = {
  id: 'u1',
  name: 'Bong',
  email: 'b@welinc.com',
  profilePicture: null,
  emailVerified: true,
};
const GRANT = {
  client: CLIENT,
  aud: 'VMMS',
  roles: [],
  grant: {
    systems: ['VMMS'],
    systemRoles: [{ system: 'VMMS', roles: [] }],
    suiteAdmin: false,
  },
};
const STEP = {
  status: 'EMAIL_VERIFICATION_REQUIRED',
  challengeId: 'c'.repeat(43),
  email: 'b@welinc.com',
  resendAfter: 60,
};
const TOKENS = {
  access_token: 'a',
  refresh_token: 'r',
  expires_in: 900,
  sid: 'sid',
  session_expires_at: '2026-11-18T00:00:00.000Z',
  user: {
    id: 'u1',
    name: 'Bong',
    email: 'b@welinc.com',
    roles: [],
    systems: [],
    systemRoles: [],
    suiteAdmin: false,
  },
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
  const endpoint = { publicClient: fn().mockResolvedValue(CLIENT) };
  const grants = {
    checkMobileGrant: fn().mockResolvedValue(GRANT),
    startMobile: fn().mockResolvedValue(TOKENS),
  };
  const signInStep = {
    start: fn().mockResolvedValue(STEP),
    verify: fn().mockImplementation(
      async (_c: string, _code: string, pre: (id: string) => Promise<void>) => {
        await pre('u1');
        return 'u1';
      },
    ),
    resend: fn().mockResolvedValue({ resendAfter: 60 }),
  };
  const storage = {
    increment: fn().mockResolvedValue({ totalHits: hits, timeToExpire: 42 }),
  };
  const controller = new MobileController(
    auth as unknown as AuthService,
    endpoint as unknown as TokenEndpointService,
    grants as unknown as UserGrantsService,
    signInStep as unknown as SignInStepService,
    storage,
  );
  const headers: Record<string, string> = {};
  const res = {
    setHeader: (k: string, v: string) => (headers[k] = v),
  } as unknown as Response;
  const req = { ip: '10.0.0.2', headers: {} } as unknown as Request;
  return {
    controller,
    auth,
    endpoint,
    grants,
    signInStep,
    storage,
    res,
    req,
    headers,
  };
}

const LOGIN = {
  email: 'b@welinc.com',
  password: 'x',
  clientId: 'vmms-mobile',
  deviceName: ' Pixel 8 ',
};
const VERIFY = {
  challengeId: STEP.challengeId,
  code: '123456',
  clientId: 'vmms-mobile',
  deviceName: 'Pixel 8',
};

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => null,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(HttpException);
  return error as HttpException;
}

describe('POST /auth/mobile/login', () => {
  it('answers tokens for a verified email, after the grant check', async () => {
    const t = build();
    const answer = await t.controller.login(LOGIN, t.req, t.res);
    expect(answer).toMatchObject({
      accessToken: 'a',
      refreshToken: 'r',
      sid: 'sid',
    });
    expect(t.grants.startMobile).toHaveBeenCalledWith(GRANT, {
      user: { id: 'u1', name: 'Bong', email: 'b@welinc.com' },
      deviceName: 'Pixel 8',
      meta: { ip: '10.0.0.2', device: 'Pixel 8', userAgent: null },
    });
    expect(t.signInStep.start).not.toHaveBeenCalled();
  });

  it('answers the step body for an unverified email and starts no session', async () => {
    const t = build();
    t.auth.checkCredentials.mockResolvedValue({
      user: { ...USER, emailVerified: false },
    });
    expect(await t.controller.login(LOGIN, t.req, t.res)).toBe(STEP);
    expect(t.grants.startMobile).not.toHaveBeenCalled();
  });

  it('runs NO_SYSTEM_ACCESS and APP_NOT_ALLOWED before the step, so no code is sent', async () => {
    const t = build();
    t.auth.checkCredentials.mockResolvedValue({
      user: { ...USER, emailVerified: false },
    });
    t.grants.checkMobileGrant.mockRejectedValue(
      new HttpException({ code: 'APP_NOT_ALLOWED' }, 403),
    );
    expect(
      (await refusal(t.controller.login(LOGIN, t.req, t.res))).getStatus(),
    ).toBe(403);
    expect(t.signInStep.start).not.toHaveBeenCalled();
  });
});

describe('POST /auth/mobile/login/verify-email and resend', () => {
  it('checks the client, the account and the grant again, then answers tokens', async () => {
    const t = build();
    const answer = await t.controller.verifyEmail(VERIFY, t.req, t.res);
    expect(answer).toMatchObject({ accessToken: 'a' });
    expect(t.endpoint.publicClient).toHaveBeenCalledWith('vmms-mobile');
    expect(t.auth.assertCanSignIn).toHaveBeenCalledWith(
      'u1',
      expect.objectContaining({ ip: '10.0.0.2' }),
    );
    expect(t.grants.checkMobileGrant).toHaveBeenCalledWith(CLIENT, 'u1');
    expect(t.headers['Cache-Control']).toBe('no-store');
  });

  it('answers INVALID_CLIENT for an app that may not sign in, and issues nothing', async () => {
    const t = build();
    t.endpoint.publicClient.mockResolvedValue(null);
    const error = await refusal(t.controller.verifyEmail(VERIFY, t.req, t.res));
    expect(error.getStatus()).toBe(400);
    expect((error.getResponse() as { code: string }).code).toBe(
      'INVALID_CLIENT',
    );
    expect(t.grants.startMobile).not.toHaveBeenCalled();
  });

  it.each([
    [
      'verify',
      (t: ReturnType<typeof build>) =>
        t.controller.verifyEmail(VERIFY, t.req, t.res),
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
    'refuses the 11th %s call a minute with the mobile 429 body',
    async (_l, call) => {
      const t = build(11);
      const error = await refusal(call(t));
      expect(error.getStatus()).toBe(429);
      expect(error.getResponse()).toMatchObject({ error: 'rate_limited' });
      expect(t.headers['Retry-After']).toBe('42');
      expect(t.storage.increment.mock.calls[0][0]).toBe('code-signin:10.0.0.2');
      expect(t.signInStep.verify).not.toHaveBeenCalled();
      expect(t.signInStep.resend).not.toHaveBeenCalled();
    },
  );
});
