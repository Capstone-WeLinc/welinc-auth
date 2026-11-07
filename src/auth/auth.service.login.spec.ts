import { describe, it, expect, beforeAll, jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { SystemType, UserRole } from '@prisma/client';
import * as argon2 from 'argon2';
import { decodeJwt } from 'jose';
import type { PrismaService } from '../shared/prisma.service';
import type { MailService } from '../shared/mail.service';
import { AuthService } from './auth.service';
import { testTokenService } from './testing/test-keys';
import type { TokenService } from './tokens/token.service';

// covers: spec 0002 AC-5 (system pick and NO_SYSTEM_ACCESS), AC-6 (answer and token claims)
describe('AuthService.login', () => {
  let tokens: TokenService;
  let passwordHash: string;

  beforeAll(async () => {
    tokens = await testTokenService();
    passwordHash = await argon2.hash('secret123');
  });

  function build(roles: { role: UserRole; system: SystemType }[]) {
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
    return new AuthService(
      { user: { findFirst, update } } as unknown as PrismaService,
      tokens,
      {} as MailService,
      { get: () => undefined } as unknown as ConfigService,
    );
  }

  const both = [
    { role: UserRole.MECHANIC, system: SystemType.VRMS },
    { role: UserRole.OPERATIONS, system: SystemType.BMS },
  ];

  it('signs for VRMS by default, with only VRMS roles in the token and every role in user', async () => {
    const answer = await build(both).login({
      email: 'pedro@welinc.com',
      password: 'secret123',
    });
    expect(answer.system).toBe('VRMS');
    expect(answer.user.roles).toEqual(both);
    expect(decodeJwt(answer.accessToken)).toMatchObject({
      aud: 'VRMS',
      roles: [{ role: 'MECHANIC', system: 'VRMS' }],
      client_id: 'portal',
      token_use: 'user',
    });
  });

  it('signs for the requested system', async () => {
    const answer = await build(both).login({
      email: 'pedro@welinc.com',
      password: 'secret123',
      system: SystemType.BMS,
    });
    expect(answer.system).toBe('BMS');
    expect(decodeJwt(answer.accessToken)).toMatchObject({
      aud: 'BMS',
      roles: [{ role: 'OPERATIONS', system: 'BMS' }],
    });
  });

  it('answers 403 NO_SYSTEM_ACCESS and no token for a system the user lacks, or no system at all', async () => {
    for (const [roles, system] of [
      [both, SystemType.VMMS],
      [[], undefined],
    ] as const) {
      const error = await build([...roles])
        .login({ email: 'pedro@welinc.com', password: 'secret123', system })
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
      build([]).login({ email: 'pedro@welinc.com', password: 'wrong' }),
    ).rejects.toThrow('Invalid credentials');
  });
});
