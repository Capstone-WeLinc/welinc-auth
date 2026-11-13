import { fakeAdminAlerts, fakeAdminStanding } from './testing/admin.fake';
import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { fakeConfig } from '../config/fake-config.setup';
import type { ForbiddenException } from '@nestjs/common';
import { SystemType } from '@prisma/client';
import { FakeCatalogService } from './testing/catalog.fake';
import { fakeCodes } from './testing/codes.fake';
import type { RoleCode } from './roles/catalog.types';
import * as argon2 from 'argon2';
import type { PrismaService } from '../shared/prisma.service';
import type { MailService } from '../shared/mail.service';
import { AuthService, emailDomain } from './auth.service';
import { LOCK_MINUTES } from './lockout';
import { AccountEventsService } from './events/account-events.service';
import { PasswordCheckService } from './reauth/password-check.service';
import { noGeo } from './testing/geo.fake';
import type { RequestMeta } from './events/request-meta';
import { SessionService } from './sessions/session.service';
import { testTokenService } from './testing/test-keys';
import type { TokenService } from './tokens/token.service';

const meta: RequestMeta = {
  ip: '203.0.113.7',
  device: 'Chrome on Windows',
  userAgent: 'Mozilla/5.0',
};

// covers: spec 0003 AC-11 (no token in the answer); spec 0007 AC-3 (no system pick here);
// spec 0011 AC-1, AC-1b, AC-2 (the sign in rows and the atomic counter)
describe('AuthService.checkCredentials', () => {
  let tokens: TokenService;
  let passwordHash: string;

  beforeAll(async () => {
    tokens = await testTokenService();
    passwordHash = await argon2.hash('secret123');
  });

  function build(
    roles: { role: RoleCode; system: SystemType }[],
    row: Record<string, unknown> = {},
    found = true,
  ) {
    const account = {
      id: 'user-1',
      name: 'Pedro',
      email: 'pedro@welinc.com',
      contact: null,
      profilePicture: null,
      passwordHash,
      isActive: true,
      failedLoginAttempts: 0,
      lockedAt: null as Date | null,
      roles,
      ...row,
    };
    const findFirst = jest.fn<(args: unknown) => Promise<unknown>>();
    // A fresh copy per read, so the counter below can move after the read (a race)
    findFirst.mockImplementation(() =>
      Promise.resolve(found ? { ...account } : null),
    );
    const update = jest.fn<(args: unknown) => Promise<unknown>>();
    update.mockResolvedValue({});
    const events: Record<string, unknown>[] = [];
    // The atomic counter: moves only while unlocked, locks on the 5th
    const queryRaw = jest.fn(() => {
      if (account.lockedAt) return Promise.resolve([]);
      account.failedLoginAttempts += 1;
      if (account.failedLoginAttempts >= 5) account.lockedAt = new Date();
      return Promise.resolve([
        {
          attempts: account.failedLoginAttempts,
          locked: account.lockedAt !== null,
        },
      ]);
    });
    const tx = {
      $queryRaw: queryRaw,
      accountEvent: {
        create: jest.fn(({ data }: { data: Record<string, unknown> }) => {
          events.push(data);
          return Promise.resolve(data);
        }),
      },
    };
    const prisma = {
      user: { findFirst, update },
      $transaction: (fn: (t: typeof tx) => Promise<unknown>) => fn(tx),
    } as unknown as PrismaService;
    const sessions = {
      endAllForUser: jest.fn(() => Promise.resolve(0)),
    } as unknown as SessionService;
    const service = new AuthService(
      prisma,
      tokens,
      {} as MailService,
      fakeConfig(),
      sessions,
      new FakeCatalogService(),
      fakeCodes(),
      new AccountEventsService(prisma, noGeo),
      new PasswordCheckService(prisma, new AccountEventsService(prisma, noGeo)),
      fakeAdminStanding(),
      fakeAdminAlerts(),
    );
    return { service, events, account, update };
  }

  const both = [
    { role: 'MECHANIC', system: SystemType.VRMS },
    { role: 'OPERATIONS', system: SystemType.BMS },
  ];
  const right = { email: 'pedro@welinc.com', password: 'secret123' };
  const wrong = { email: 'pedro@welinc.com', password: 'wrong' };

  it('answers the user with no token and no system pick', async () => {
    const { service, events } = build(both);
    const answer = await service.checkCredentials(right, meta);
    expect(answer).toEqual({
      user: {
        id: 'user-1',
        name: 'Pedro',
        email: 'pedro@welinc.com',
        profilePicture: null,
      },
    });
    // SIGNED_IN comes with the session, not from the password check
    expect(events).toEqual([]);
  });

  it('leaves the no system check to the caller (spec 0007, AC-3)', async () => {
    const answer = await build([]).service.checkCredentials(right, meta);
    expect(answer.user.id).toBe('user-1');
  });

  it('records a wrong password with the tries left and the address (AC-1, AC-3)', async () => {
    const { service, events } = build([]);
    const error = await service
      .checkCredentials(wrong, meta)
      .catch((e: unknown) => e);
    expect((error as Error).message).toBe('Invalid credentials');
    expect(events).toEqual([
      expect.objectContaining({
        userId: 'user-1',
        actorId: null,
        category: 'SIGN_IN',
        type: 'SIGN_IN_FAILED',
        reason: 'WRONG_PASSWORD',
        attemptsLeft: 4,
        ip: '203.0.113.7',
        device: 'Chrome on Windows',
        userAgent: 'Mozilla/5.0',
      }),
    ]);
  });

  // covers: contract 0001 section 12 (403 ACCOUNT_LOCKED, isLocked kept for the portal)
  it('answers 403 ACCOUNT_LOCKED for an account already locked, and records it', async () => {
    const { service, events } = build(both, { lockedAt: new Date() });
    const error = await service
      .checkCredentials(right, meta)
      .catch((e: unknown) => e);
    expect((error as ForbiddenException).getStatus()).toBe(403);
    expect((error as ForbiddenException).getResponse()).toMatchObject({
      code: 'ACCOUNT_LOCKED',
      isLocked: true,
      remainingAttempts: 0,
      lockedUntil: expect.any(String),
    });
    expect(events).toEqual([
      expect.objectContaining({
        type: 'SIGN_IN_FAILED',
        reason: 'ACCOUNT_LOCKED',
      }),
    ]);
  });

  // covers: suite spec 0015 AC-4, AC-5 (deactivated: only the right password learns it)
  it('treats a wrong password on a deactivated account like any wrong password', async () => {
    const { service, events } = build(both, { isActive: false });
    await expect(service.checkCredentials(wrong, meta)).rejects.toThrow(
      'Invalid credentials',
    );
    expect(events).toEqual([
      expect.objectContaining({ reason: 'WRONG_PASSWORD', attemptsLeft: 4 }),
    ]);
  });

  it('tells a deactivated account so after its right password, and records it', async () => {
    const { service, events } = build(both, { isActive: false });
    const error = await service
      .checkCredentials(right, meta)
      .catch((e: unknown) => e);
    expect((error as ForbiddenException).getStatus()).toBe(403);
    expect((error as ForbiddenException).getResponse()).toMatchObject({
      code: 'ACCOUNT_INACTIVE',
    });
    expect(events).toEqual([
      expect.objectContaining({ reason: 'ACCOUNT_INACTIVE' }),
    ]);
  });

  // covers: suite spec 0015 AC-1, AC-2 (the lock runs out on its own)
  it('signs in once the lock ran out, and clears it', async () => {
    const ranOut = new Date(Date.now() - (LOCK_MINUTES + 1) * 60_000);
    const { service, update } = build(both, {
      lockedAt: ranOut,
      failedLoginAttempts: 5,
    });
    await expect(service.checkCredentials(right, meta)).resolves.toBeDefined();
    expect(update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: { failedLoginAttempts: 0, lockedAt: null },
      }),
    );
  });

  it('gives 4 to 1 tries left, then one LOCKED_OUT and no fifth SIGN_IN_FAILED (AC-1)', async () => {
    const { service, events } = build(both);
    for (let i = 0; i < 4; i++) {
      await service.checkCredentials(wrong, meta).catch(() => undefined);
    }
    const error = await service
      .checkCredentials(wrong, meta)
      .catch((e: unknown) => e);
    expect((error as ForbiddenException).getStatus()).toBe(403);
    expect((error as ForbiddenException).getResponse()).toMatchObject({
      code: 'ACCOUNT_LOCKED',
      isLocked: true,
    });
    expect(events.map((e) => [e.type, e.attemptsLeft])).toEqual([
      ['SIGN_IN_FAILED', 4],
      ['SIGN_IN_FAILED', 3],
      ['SIGN_IN_FAILED', 2],
      ['SIGN_IN_FAILED', 1],
      ['LOCKED_OUT', null],
    ]);
  });

  it('records ACCOUNT_LOCKED when a parallel try locked it first (AC-1b)', async () => {
    const { service, events, account } = build(both, {
      failedLoginAttempts: 4,
    });
    // Read before the lock, updated after it
    account.lockedAt = new Date();
    await service.checkCredentials(wrong, meta).catch(() => undefined);
    expect(events).toEqual([
      expect.objectContaining({
        type: 'SIGN_IN_FAILED',
        reason: 'ACCOUNT_LOCKED',
      }),
    ]);
  });

  it('writes no row for an unknown email, and logs only its domain (AC-2)', async () => {
    const { service, events } = build(both, {}, false);
    await expect(
      service.checkCredentials(
        { email: 'Someone@Gmail.com', password: 'x' },
        meta,
      ),
    ).rejects.toThrow('Invalid credentials');
    expect(events).toEqual([]);
    expect(emailDomain('Someone@Gmail.com')).toBe('gmail.com');
  });
});
