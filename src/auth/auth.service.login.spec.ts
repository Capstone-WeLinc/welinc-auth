import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
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

// covers: spec 0002 AC-5 (system pick and NO_SYSTEM_ACCESS); spec 0003 AC-11 (no token in the answer)
describe('AuthService.checkCredentials', () => {
  let tokens: TokenService;
  let passwordHash: string;

  beforeAll(async () => {
    tokens = await testTokenService();
    passwordHash = await argon2.hash('secret123');
  });

  function build(roles: { role: RoleCode; system: SystemType }[]) {
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
      { get: () => undefined } as unknown as ConfigService,
      sessions,
      new FakeCatalogService(),
    );
  }

  const both = [
    { role: 'MECHANIC', system: SystemType.VRMS },
    { role: 'OPERATIONS', system: SystemType.BMS },
  ];

  it('picks VRMS by default and answers the user with no token', async () => {
    const answer = await build(both).checkCredentials({
      email: 'pedro@welinc.com',
      password: 'secret123',
    });
    expect(answer).toEqual({
      system: 'VRMS',
      user: { id: 'user-1', name: 'Pedro', email: 'pedro@welinc.com' },
    });
  });

  it('picks the requested system', async () => {
    const answer = await build(both).checkCredentials({
      email: 'pedro@welinc.com',
      password: 'secret123',
      system: SystemType.BMS,
    });
    expect(answer.system).toBe('BMS');
  });

  it('answers 403 NO_SYSTEM_ACCESS and no token for a system the user lacks, or no system at all', async () => {
    for (const [roles, system] of [
      [both, SystemType.VMMS],
      [[], undefined],
    ] as const) {
      const error = await build([...roles])
        .checkCredentials({
          email: 'pedro@welinc.com',
          password: 'secret123',
          system,
        })
        .catch((e: unknown) => e);
      expect(error).toBeInstanceOf(HttpException);
      expect((error as HttpException).getStatus()).toBe(403);
      expect((error as HttpException).getResponse()).toMatchObject({
        statusCode: 403,
        error: 'Forbidden',
        code: 'NO_SYSTEM_ACCESS',
      });
    }
  });

  it('still refuses a wrong password before picking a system', async () => {
    await expect(
      build([]).checkCredentials({
        email: 'pedro@welinc.com',
        password: 'wrong',
      }),
    ).rejects.toThrow('Invalid credentials');
  });
});
