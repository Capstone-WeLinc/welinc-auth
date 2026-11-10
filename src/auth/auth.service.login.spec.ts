import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { fakeConfig } from '../config/fake-config.setup';
import type { ForbiddenException } from '@nestjs/common';
import { SystemType } from '@prisma/client';
import { FakeCatalogService } from './testing/catalog.fake';
import type { RoleCode } from './roles/catalog.types';
import * as argon2 from 'argon2';
import type { PrismaService } from '../shared/prisma.service';
import type { MailService } from '../shared/mail.service';
import { AuthService } from './auth.service';
import { SessionService } from './sessions/session.service';
import { testTokenService } from './testing/test-keys';
import type { TokenService } from './tokens/token.service';

// covers: spec 0003 AC-11 (no token in the answer); spec 0007 AC-3 (no system pick here)
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
  ) {
    const findFirst = jest.fn<(args: unknown) => Promise<unknown>>();
    findFirst.mockResolvedValue({
      id: 'user-1',
      name: 'Pedro',
      email: 'pedro@welinc.com',
      contact: null,
      profilePicture: null,
      passwordHash,
      isActive: true,
      failedLoginAttempts: 0,
      lockedAt: null,
      roles,
      ...row,
    });
    const update = jest.fn<(args: unknown) => Promise<unknown>>();
    update.mockResolvedValue({});
    const sessions = {
      endAllForUser: jest.fn(() => Promise.resolve(0)),
    } as unknown as SessionService;
    return new AuthService(
      { user: { findFirst, update } } as unknown as PrismaService,
      tokens,
      {} as MailService,
      fakeConfig(),
      sessions,
      new FakeCatalogService(),
    );
  }

  const both = [
    { role: 'MECHANIC', system: SystemType.VRMS },
    { role: 'OPERATIONS', system: SystemType.BMS },
  ];

  it('answers the user with no token and no system pick', async () => {
    const answer = await build(both).checkCredentials({
      email: 'pedro@welinc.com',
      password: 'secret123',
    });
    expect(answer).toEqual({
      user: {
        id: 'user-1',
        name: 'Pedro',
        email: 'pedro@welinc.com',
        profilePicture: null,
      },
    });
  });

  it('leaves the no system check to the caller (spec 0007, AC-3)', async () => {
    const answer = await build([]).checkCredentials({
      email: 'pedro@welinc.com',
      password: 'secret123',
    });
    expect(answer.user.id).toBe('user-1');
  });

  it('still refuses a wrong password before picking a system', async () => {
    await expect(
      build([]).checkCredentials({
        email: 'pedro@welinc.com',
        password: 'wrong',
      }),
    ).rejects.toThrow('Invalid credentials');
  });

  // covers: contract 0001 section 12 (403 ACCOUNT_LOCKED, isLocked kept for the portal)
  it('answers 403 ACCOUNT_LOCKED for an account already locked', async () => {
    const error = await build(both, { lockedAt: new Date() })
      .checkCredentials({ email: 'pedro@welinc.com', password: 'secret123' })
      .catch((e: unknown) => e);
    expect((error as ForbiddenException).getStatus()).toBe(403);
    expect((error as ForbiddenException).getResponse()).toMatchObject({
      code: 'ACCOUNT_LOCKED',
      isLocked: true,
      remainingAttempts: 0,
    });
  });

  it('answers 403 ACCOUNT_LOCKED on the fifth wrong password', async () => {
    const error = await build(both, { failedLoginAttempts: 4 })
      .checkCredentials({ email: 'pedro@welinc.com', password: 'wrong' })
      .catch((e: unknown) => e);
    expect((error as ForbiddenException).getStatus()).toBe(403);
    expect((error as ForbiddenException).getResponse()).toMatchObject({
      code: 'ACCOUNT_LOCKED',
      isLocked: true,
    });
  });
});
