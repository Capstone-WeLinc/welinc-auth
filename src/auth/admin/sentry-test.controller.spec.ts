import { HttpException, NotFoundException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import type { Env } from '../../config/env';
import type { AdminRequest, PortalAdmin } from './admin-session.guard';
import {
  SentryTestController,
  SentryTestSwitch,
} from './sentry-test.controller';

// covers: VRMS spec 0025 AC-16

const config = (on: boolean) =>
  ({ get: () => on }) as unknown as ConfigService<Env, true>;

const requestFor = (suiteAdmin: boolean): AdminRequest =>
  ({
    portalAdmin: {
      standing: { suiteAdmin, adminOf: [] },
    } as unknown as PortalAdmin,
  }) as AdminRequest;

describe('SentryTestSwitch', () => {
  it('answers 404 when SENTRY_TEST_ROUTES is off', () => {
    expect(() => new SentryTestSwitch(config(false)).canActivate()).toThrow(
      NotFoundException,
    );
  });

  it('lets the request through when it is on', () => {
    expect(new SentryTestSwitch(config(true)).canActivate()).toBe(true);
  });
});

describe('SentryTestController', () => {
  const controller = new SentryTestController();

  it('refuses a system admin with NOT_SUITE_ADMIN', () => {
    let thrown: unknown;
    try {
      controller.sentryTest(requestFor(false));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(HttpException);
    expect((thrown as HttpException).getResponse()).toMatchObject({
      code: 'NOT_SUITE_ADMIN',
    });
  });

  it('throws the test error for a suite admin', () => {
    expect(() => controller.sentryTest(requestFor(true))).toThrow(
      'Sentry test error from welinc-auth (spec 0025)',
    );
  });
});
