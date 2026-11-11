import { HttpException, type ExecutionContext } from '@nestjs/common';
import { ThrottlerStorageService } from '@nestjs/throttler';
import { randomUUID } from 'node:crypto';
import type { PrismaService } from '../../shared/prisma.service';
import { testTokenService } from '../testing/test-keys';
import type { TokenService } from '../tokens/token.service';
import {
  InvalidCursorError,
  decodeFeedCursor,
  decodePageCursor,
  encodeFeedCursor,
  encodePageCursor,
} from './directory-cursor';
import { parseLimit, parseLookup } from './directory.controller';
import {
  DIRECTORY_LIMIT,
  DirectoryGuard,
  type DirectoryRequest,
} from './directory.guard';
import { fromSnapshot, fromUserRow } from './directory-user';
import { comparePositions } from './directory.service';
import { AuthController } from '../auth.controller';
import { SERVICE_SCOPE_KEY } from '../decorators/service-scope.decorator';

// Spec 0005: the directory's cursors, inputs, mapping and guard, without a database.

const EPOCH = '8ff6b793-4ebd-41ce-a336-d0f5188a5fc5';

function codeOf(fn: () => unknown): { status: number; code: unknown } {
  try {
    fn();
  } catch (error) {
    if (!(error instanceof HttpException)) throw error;
    return {
      status: error.getStatus(),
      code: (error.getResponse() as { code?: unknown }).code,
    };
  }
  throw new Error('expected a throw');
}

describe('directory cursors', () => {
  // covers: AC-5
  it('round trips a feed position with its epoch', () => {
    const cursor = encodeFeedCursor(EPOCH, { txid: 12345n, seq: 67n });
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeFeedCursor(cursor, EPOCH)).toEqual({ txid: 12345n, seq: 67n });
  });

  it('refuses a cursor from another epoch (a restored database)', () => {
    const cursor = encodeFeedCursor(randomUUID(), { txid: 1n, seq: 1n });
    expect(() => decodeFeedCursor(cursor, EPOCH)).toThrow(InvalidCursorError);
  });

  it.each([
    'not base64!',
    Buffer.from('v2.x.1.1').toString('base64url'),
    Buffer.from(`v1.${EPOCH}.1`).toString('base64url'),
    Buffer.from(`v1.${EPOCH}.-1.1`).toString('base64url'),
    Buffer.from(`v1.${EPOCH}.1.1e3`).toString('base64url'),
    'a'.repeat(201),
  ])('refuses a cursor welinc-auth did not issue: %s', (raw) => {
    expect(() => decodeFeedCursor(raw, EPOCH)).toThrow(InvalidCursorError);
  });

  // covers: AC-4
  it('round trips a page cursor and refuses anything but a uuid', () => {
    const id = randomUUID();
    expect(decodePageCursor(encodePageCursor(id))).toBe(id);
    expect(() =>
      decodePageCursor(Buffer.from('v1.robert').toString('base64url')),
    ).toThrow(InvalidCursorError);
  });

  it('orders positions by txid, then seq', () => {
    expect(comparePositions({ txid: 2n, seq: 1n }, { txid: 1n, seq: 9n })).toBe(
      1,
    );
    expect(comparePositions({ txid: 1n, seq: 1n }, { txid: 1n, seq: 2n })).toBe(
      -1,
    );
    expect(comparePositions({ txid: 1n, seq: 1n }, { txid: 1n, seq: 1n })).toBe(
      0,
    );
  });
});

describe('directory inputs', () => {
  // covers: AC-5
  it('defaults limit to 100 and accepts 1 to 500', () => {
    expect(parseLimit(undefined)).toBe(100);
    expect(parseLimit('1')).toBe(1);
    expect(parseLimit('500')).toBe(500);
  });

  it.each(['0', '501', '-1', '2.5', 'ten', ''])(
    'answers 400 VALIDATION_FAILED for limit %p',
    (raw) => {
      expect(codeOf(() => parseLimit(raw))).toEqual({
        status: 400,
        code: 'VALIDATION_FAILED',
      });
    },
  );

  it('answers 400 VALIDATION_FAILED for a repeated limit', () => {
    expect(codeOf(() => parseLimit(['1', '2']))).toMatchObject({
      code: 'VALIDATION_FAILED',
    });
  });

  // covers: AC-6
  it('accepts 1 to 200 distinct uuids', () => {
    const ids = Array.from({ length: 200 }, () => randomUUID());
    expect(parseLookup({ ids })).toEqual(ids);
  });

  it.each([
    ['no body', null],
    ['an array', []],
    ['no ids', {}],
    ['an extra field', { ids: [randomUUID()], system: 'VMMS' }],
    ['an empty list', { ids: [] }],
    ['201 ids', { ids: Array.from({ length: 201 }, () => randomUUID()) }],
    ['a non uuid', { ids: ['abc'] }],
    [
      'a repeat in other case',
      (() => {
        const id = randomUUID();
        return { ids: [id, id.toUpperCase()] };
      })(),
    ],
  ])('answers 400 VALIDATION_FAILED for %s', (_name, body) => {
    expect(codeOf(() => parseLookup(body))).toEqual({
      status: 400,
      code: 'VALIDATION_FAILED',
    });
  });
});

describe('DirectoryUser mapping', () => {
  const row = {
    id: 'u1',
    name: 'Ana Cruz',
    email: 'ana@welinc.com',
    contact: '+639171234567',
    profilePicture: '/uploads/profiles/u1.jpg',
    isActive: true,
    deletedAt: null,
    erasedAt: null,
    updatedAt: new Date('2026-11-09T01:02:03.004Z'),
    roles: [
      { system: 'VRMS', role: 'MECHANIC' },
      { system: 'VMMS', role: 'ADMIN' },
      { system: 'VRMS', role: 'CHIEF_MECHANIC' },
    ],
  };

  // covers: AC-7
  it("gives only the caller's system roles, and the phone only with directory.contact", () => {
    expect(fromUserRow(row, { system: 'VRMS', canSeePhone: false })).toEqual({
      id: 'u1',
      name: 'Ana Cruz',
      email: 'ana@welinc.com',
      phone: null,
      picture: '/uploads/profiles/u1.jpg',
      isActive: true,
      deleted: false,
      erased: false,
      roles: ['CHIEF_MECHANIC', 'MECHANIC'],
      updatedAt: '2026-11-09T01:02:03.004Z',
    });
    expect(
      fromUserRow(row, { system: 'VMMS', canSeePhone: true }),
    ).toMatchObject({ phone: '+639171234567', roles: ['ADMIN'] });
  });

  it('maps a feed snapshot the same way, with deleted from deletedAt', () => {
    const user = fromSnapshot(
      {
        ...row,
        deletedAt: '2026-11-09T05:00:00+00:00',
        updatedAt: '2026-11-09T01:02:03.004+00:00',
      },
      { system: 'BMS', canSeePhone: false },
    );
    expect(user).toMatchObject({
      deleted: true,
      // A snapshot from before spec 0012 has no erasedAt: not erased
      erased: false,
      roles: [],
      phone: null,
      updatedAt: '2026-11-09T01:02:03.004Z',
    });
    expect(user).not.toHaveProperty('phoneVerified');
  });

  // covers: spec 0012 AC-17
  it('says erased when the snapshot carries erasedAt', () => {
    const { erasedAt: _unused, ...plain } = row;
    void _unused;
    const user = fromSnapshot(
      {
        ...plain,
        name: 'Deleted user',
        deletedAt: '2026-10-01T05:00:00+00:00',
        erasedAt: '2026-11-01T05:00:00+00:00',
        updatedAt: '2026-11-01T05:00:00.000+00:00',
      },
      { system: 'VRMS', canSeePhone: false },
    );
    expect(user).toMatchObject({
      erased: true,
      deleted: true,
      name: 'Deleted user',
    });
  });
});

describe('DirectoryGuard', () => {
  let tokens: TokenService;

  beforeAll(async () => {
    tokens = await testTokenService();
  });

  function contextFor(authorization?: string) {
    const request = {
      headers: authorization ? { authorization } : {},
      query: {},
    } as unknown as DirectoryRequest;
    const headers: Record<string, string> = {};
    const response = {
      setHeader: (name: string, value: string) => (headers[name] = value),
    };
    const context = {
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => response,
      }),
    } as unknown as ExecutionContext;
    return { context, request, headers };
  }

  function guardWith(
    client: { isActive: boolean; system: string | null } | null,
  ) {
    const prisma = {
      oAuthClient: { findUnique: jest.fn().mockResolvedValue(client) },
    } as unknown as PrismaService;
    return new DirectoryGuard(tokens, prisma, new ThrottlerStorageService());
  }

  const service = async (scopes: string[], clientId = 'vrms') =>
    (await tokens.signServiceToken({ clientId, aud: 'AUTH', scopes })).token;

  async function outcome(guard: DirectoryGuard, auth?: string) {
    const { context, request, headers } = contextFor(auth);
    try {
      await guard.canActivate(context);
      return { status: 200, view: request.directory, headers };
    } catch (error) {
      if (!(error instanceof HttpException)) throw error;
      return {
        status: error.getStatus(),
        code: (error.getResponse() as { code?: unknown }).code,
        headers,
      };
    }
  }

  // covers: AC-8
  it("lets a system's service token with directory.read in, as that client's system", async () => {
    const result = await outcome(
      guardWith({ isActive: true, system: 'VRMS' }),
      `Bearer ${await service(['directory.read'])}`,
    );
    expect(result).toMatchObject({
      status: 200,
      view: { system: 'VRMS', canSeePhone: false },
    });
  });

  // covers: AC-7
  it('lets a token holding directory.contact see phones', async () => {
    const result = await outcome(
      guardWith({ isActive: true, system: 'VMMS' }),
      `Bearer ${await service(['directory.read', 'directory.contact'], 'vmms')}`,
    );
    expect(result.view).toEqual({ system: 'VMMS', canSeePhone: true });
  });

  it('answers 401 with no token or a bad one', async () => {
    const guard = guardWith({ isActive: true, system: 'VRMS' });
    expect((await outcome(guard)).status).toBe(401);
    expect((await outcome(guard, 'Bearer not.a.token')).status).toBe(401);
  });

  it("answers 403 FORBIDDEN to a person's token, an admin's included", async () => {
    const token = await tokens.signUserToken({
      sub: randomUUID(),
      email: 'admin@welinc.com',
      aud: 'VRMS',
      roles: [{ role: 'ADMIN', system: 'VRMS' }],
      sid: randomUUID(),
      clientId: 'vrms',
    });
    expect(
      await outcome(
        guardWith({ isActive: true, system: 'VRMS' }),
        `Bearer ${token}`,
      ),
    ).toMatchObject({ status: 403, code: 'FORBIDDEN' });
  });

  it('answers 403 FORBIDDEN to a service token without directory.read', async () => {
    expect(
      await outcome(
        guardWith({ isActive: true, system: 'VRMS' }),
        `Bearer ${await service(['something.else'])}`,
      ),
    ).toMatchObject({ status: 403, code: 'FORBIDDEN' });
  });

  it('answers 403 FORBIDDEN to a client with no system', async () => {
    expect(
      await outcome(
        guardWith({ isActive: true, system: null }),
        `Bearer ${await service(['directory.read'], 'portal')}`,
      ),
    ).toMatchObject({ status: 403, code: 'FORBIDDEN' });
  });

  it('answers 401 to a switched off client', async () => {
    expect(
      (
        await outcome(
          guardWith({ isActive: false, system: 'VRMS' }),
          `Bearer ${await service(['directory.read'])}`,
        )
      ).status,
    ).toBe(401);
  });

  it('answers 429 RATE_LIMITED with Retry-After past 120 calls a minute per client', async () => {
    const guard = guardWith({ isActive: true, system: 'VRMS' });
    const auth = `Bearer ${await service(['directory.read'])}`;
    for (let i = 0; i < DIRECTORY_LIMIT.limit; i++) {
      expect((await outcome(guard, auth)).status).toBe(200);
    }
    const over = await outcome(guard, auth);
    expect(over).toMatchObject({ status: 429, code: 'RATE_LIMITED' });
    expect(Number(over.headers['Retry-After'])).toBeGreaterThan(0);
  });
});

describe('GET /auth/users (AC-9)', () => {
  // covers: AC-9. Without @ServiceScope(), JwtAuthGuard answers any service token 403
  // WRONG_TOKEN_USE (its own tests cover that rule), so only admins reach the route
  it('no longer lets a service token in', () => {
    const handler = Object.getOwnPropertyDescriptor(
      AuthController.prototype,
      'listUsers',
    )?.value as object;
    const scope: unknown = Reflect.getMetadata(SERVICE_SCOPE_KEY, handler);
    expect(handler).toBeDefined();
    expect(scope).toBeUndefined();
  });
});
