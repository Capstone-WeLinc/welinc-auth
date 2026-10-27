import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { ForbiddenException, UnauthorizedException } from '@nestjs/common';
import type { ConfigService } from '@nestjs/config';
import { SystemType, UserRole } from '@prisma/client';
import type { Request } from 'express';
import type { PrismaService } from '../../shared/prisma.service';
import { JwtStrategy } from './jwt.strategy';

type Row = {
  id: string;
  email: string;
  isActive: boolean;
  lockedAt: Date | null;
  roles: { role: UserRole; system: SystemType }[];
};

const USER_ID = '3f2b8c1e-5a4d-4e6f-9a7b-1c2d3e4f5a6b';

function userRow(overrides: Partial<Row> = {}): Row {
  return {
    id: USER_ID,
    email: 'pedro@welinc.com',
    isActive: true,
    lockedAt: null,
    roles: [
      { role: UserRole.MECHANIC, system: SystemType.VRMS },
      { role: UserRole.OPERATIONS, system: SystemType.BMS },
    ],
    ...overrides,
  };
}

describe('JwtStrategy.validate', () => {
  let findFirst: jest.Mock<(args: unknown) => Promise<Row | null>>;
  let strategy: JwtStrategy;

  const payload = (extra: { system?: string } = {}) => ({
    sub: USER_ID,
    email: 'pedro@welinc.com',
    roles: [],
    ...extra,
  });

  const req = (parts: {
    query?: Record<string, unknown>;
    headers?: Record<string, string>;
    path?: string;
  }) =>
    ({
      query: parts.query ?? {},
      headers: parts.headers ?? {},
      path: parts.path ?? '/auth/me',
      body: {},
    }) as unknown as Request;

  beforeEach(() => {
    findFirst = jest.fn<(args: unknown) => Promise<Row | null>>();
    findFirst.mockResolvedValue(userRow());
    const config = {
      getOrThrow: () => 'test-secret',
    } as unknown as ConfigService;
    const prisma = { user: { findFirst } } as unknown as PrismaService;
    strategy = new JwtStrategy(config, prisma);
  });

  describe('which system is checked (AC-24)', () => {
    it('uses a valid ?system= query over the system claim in the token', async () => {
      const result = await strategy.validate(
        req({ query: { system: 'VRMS' } }),
        payload({ system: 'BMS' }),
      );

      expect(result.system).toBe(SystemType.VRMS);
    });

    it('uses a valid ?system= query over the Origin header', async () => {
      const result = await strategy.validate(
        req({
          query: { system: 'VRMS' },
          headers: { origin: 'http://localhost:8003' },
        }),
        payload(),
      );

      expect(result.system).toBe(SystemType.VRMS);
    });

    it('uses a valid ?system= query over the path', async () => {
      const result = await strategy.validate(
        req({ query: { system: 'VRMS' }, path: '/bms/bookings' }),
        payload(),
      );

      expect(result.system).toBe(SystemType.VRMS);
    });

    it('reads the query value case insensitively', async () => {
      const result = await strategy.validate(
        req({ query: { system: 'vrms' } }),
        payload(),
      );

      expect(result.system).toBe(SystemType.VRMS);
    });

    it('takes the first value when ?system= is repeated', async () => {
      const result = await strategy.validate(
        req({ query: { system: ['VRMS', 'BMS'] } }),
        payload(),
      );

      expect(result.system).toBe(SystemType.VRMS);
    });

    it('falls back to the token claim when the query value is not a system', async () => {
      const result = await strategy.validate(
        req({ query: { system: 'NOPE' } }),
        payload({ system: 'BMS' }),
      );

      expect(result.system).toBe(SystemType.BMS);
    });

    it('still reads the Origin header when no query or claim is given', async () => {
      const result = await strategy.validate(
        req({ headers: { origin: 'http://localhost:8003' } }),
        payload(),
      );

      expect(result.system).toBe(SystemType.BMS);
    });
  });

  describe('who gets in', () => {
    it('returns the caller with all their roles and the resolved system', async () => {
      const result = await strategy.validate(
        req({ query: { system: 'VRMS' } }),
        payload(),
      );

      expect(result).toEqual({
        sub: USER_ID,
        email: 'pedro@welinc.com',
        roles: userRow().roles,
        system: SystemType.VRMS,
      });
    });

    it('looks the user up by token subject and ignores soft deleted accounts', async () => {
      await strategy.validate(req({ query: { system: 'VRMS' } }), payload());

      expect(findFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: USER_ID, deletedAt: null } }),
      );
    });

    it('rejects a user who no longer exists', async () => {
      findFirst.mockResolvedValue(null);

      await expect(
        strategy.validate(req({ query: { system: 'VRMS' } }), payload()),
      ).rejects.toThrow(new UnauthorizedException('Invalid session'));
    });

    it('rejects a deactivated user', async () => {
      findFirst.mockResolvedValue(userRow({ isActive: false }));

      await expect(
        strategy.validate(req({ query: { system: 'VRMS' } }), payload()),
      ).rejects.toThrow(new UnauthorizedException('Invalid session'));
    });

    it('answers 403 with the lock message for a locked user', async () => {
      findFirst.mockResolvedValue(userRow({ lockedAt: new Date() }));

      const run = strategy.validate(
        req({ query: { system: 'VRMS' } }),
        payload(),
      );

      await expect(run).rejects.toBeInstanceOf(ForbiddenException);
      await expect(run).rejects.toThrow(
        'Account is locked. Contact your Admin to unlock.',
      );
    });

    it('answers 401 when the user has no role in the asked system', async () => {
      findFirst.mockResolvedValue(
        userRow({
          roles: [{ role: UserRole.OPERATIONS, system: SystemType.BMS }],
        }),
      );

      const run = strategy.validate(
        req({ query: { system: 'VRMS' } }),
        payload(),
      );

      await expect(run).rejects.toBeInstanceOf(UnauthorizedException);
      await expect(run).rejects.toThrow(
        'User does not have access to this system',
      );
    });

    it('does not let a BMS Origin turn a BMS only user into a VRMS caller', async () => {
      findFirst.mockResolvedValue(
        userRow({
          roles: [{ role: UserRole.OPERATIONS, system: SystemType.BMS }],
        }),
      );

      await expect(
        strategy.validate(
          req({
            query: { system: 'VRMS' },
            headers: { origin: 'http://localhost:8003' },
          }),
          payload(),
        ),
      ).rejects.toThrow('User does not have access to this system');
    });

    it('falls back to the first role system when nothing names a system', async () => {
      const result = await strategy.validate(req({}), payload());

      expect(result.system).toBe(SystemType.VRMS);
    });
  });
});
