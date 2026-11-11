/* eslint-disable @typescript-eslint/require-await, @typescript-eslint/no-unused-vars -- test doubles */
import { describe, expect, it, jest } from '@jest/globals';
import { SessionEndReason, SessionKind } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import type { AccountEventsService } from '../events/account-events.service';
import { endActor, SessionService } from './session.service';
import type { SessionSettings } from './session-config';

const USER = '11111111-1111-4111-8111-111111111111';
const ADMIN = '22222222-2222-4222-8222-222222222222';
const SID = '33333333-3333-4333-8333-333333333333';
const CHROME =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const settings = {
  webIdleMinutes: 30,
  webMaxHours: 8,
  mobileIdleDays: 7,
  maxSessions: 10,
} as unknown as SessionSettings;

function setup(over: { count?: number } = {}) {
  const record = jest.fn(async (..._a: unknown[]) => undefined);
  const recordMany = jest.fn(async (..._a: unknown[]) => undefined);
  const events = { record, recordMany } as unknown as AccountEventsService;
  const sessionRow = {
    userId: USER,
    loginClientId: 'portal',
    kind: SessionKind.WEB,
    deviceName: null,
    userAgent: CHROME,
  };
  const tx = {
    session: {
      updateMany: jest.fn(async () => ({ count: over.count ?? 1 })),
      findUniqueOrThrow: jest.fn(async () => sessionRow),
      findMany: jest.fn(async () => []),
      create: jest.fn(async () => ({ id: SID })),
    },
    refreshToken: {
      updateMany: jest.fn(async () => ({ count: 0 })),
      create: jest.fn(async () => ({})),
    },
    $executeRaw: jest.fn(async () => over.count ?? 1),
  };
  const prisma = {
    $transaction: jest.fn(async (fn: (t: unknown) => unknown) => fn(tx)),
  } as unknown as PrismaService;
  const service = new SessionService(prisma, settings, events);
  return { service, tx, record, recordMany };
}

const lastEvent = (record: jest.Mock) =>
  record.mock.calls[0][1] as Record<string, unknown>;

// covers: AC-4, AC-6
describe('endActor', () => {
  it.each([
    [SessionEndReason.LOGOUT, USER],
    [SessionEndReason.USER_ENDED, USER],
    [SessionEndReason.PASSWORD_CHANGED, USER],
    [SessionEndReason.ADMIN_ENDED, ADMIN],
    [SessionEndReason.DEACTIVATED, ADMIN],
    [SessionEndReason.IDLE, null],
    [SessionEndReason.MAX_AGE, null],
    [SessionEndReason.REFRESH_REUSE, null],
  ])('names the right actor for %s', (reason, actor) => {
    expect(endActor(reason, USER, ADMIN)).toBe(actor);
  });

  it('has no actor for an admin end with no admin id', () => {
    expect(endActor(SessionEndReason.ADMIN_ENDED, USER, undefined)).toBeNull();
  });
});

// covers: AC-4 (exactly one ending event, only when the update changed the row)
describe('SessionService.end events', () => {
  it('writes one SIGNED_OUT for a LOGOUT, by the person, with the session device', async () => {
    const { service, tx, record } = setup();
    expect(
      await service.end(tx as never, SID, SessionEndReason.LOGOUT, {
        ip: '112.198.0.1',
      }),
    ).toBe(true);
    expect(record).toHaveBeenCalledTimes(1);
    expect(lastEvent(record)).toMatchObject({
      userId: USER,
      actorId: USER,
      type: 'SIGNED_OUT',
      reason: 'LOGOUT',
      system: null,
      sessionId: SID,
      clientId: 'portal',
      meta: { ip: '112.198.0.1', device: 'Chrome on Windows' },
    });
  });

  it('writes SESSION_ENDED with no actor and no address for an idle end', async () => {
    const { service, tx, record } = setup();
    await service.end(tx as never, SID, SessionEndReason.IDLE);
    expect(lastEvent(record)).toMatchObject({
      actorId: null,
      type: 'SESSION_ENDED',
      reason: 'IDLE',
      system: null,
      meta: { ip: null },
    });
  });

  it('tags an admin end with the admin system and names the admin', async () => {
    const { service, tx, record } = setup();
    await service.end(tx as never, SID, SessionEndReason.ADMIN_ENDED, {
      endedById: ADMIN,
      system: 'VRMS',
    });
    expect(lastEvent(record)).toMatchObject({
      actorId: ADMIN,
      type: 'SESSION_ENDED',
      system: 'VRMS',
    });
  });

  it('does not tag a self end with a system even if one is passed', async () => {
    const { service, tx, record } = setup();
    await service.end(tx as never, SID, SessionEndReason.USER_ENDED, {
      system: 'VRMS',
    });
    expect(lastEvent(record).system).toBeNull();
  });

  it('writes no event and answers false when the session was already ended', async () => {
    const { service, tx, record } = setup({ count: 0 });
    expect(await service.end(tx as never, SID, SessionEndReason.LOGOUT)).toBe(
      false,
    );
    expect(record).not.toHaveBeenCalled();
  });
});

// covers: AC-3, AC-4 (one SYSTEM_OPENED per system, the vouched address only)
describe('SessionService.addAudience', () => {
  const meta = { ip: '::ffff:112.198.0.1', clientId: 'vrms-backend' };

  it('writes one SYSTEM_OPENED the first time a system is added', async () => {
    const { service, tx, record } = setup({ count: 1 });
    expect(await service.addAudience(tx as never, SID, 'VRMS', meta)).toBe(1);
    expect(lastEvent(record)).toMatchObject({
      userId: USER,
      actorId: USER,
      type: 'SYSTEM_OPENED',
      system: 'VRMS',
      sessionId: SID,
      clientId: 'vrms-backend',
      meta: { ip: '112.198.0.1', device: 'Chrome on Windows' },
    });
  });

  it('writes nothing when the system was already there (a racing refresh)', async () => {
    const { service, tx, record } = setup({ count: 0 });
    expect(await service.addAudience(tx as never, SID, 'VRMS', meta)).toBe(0);
    expect(record).not.toHaveBeenCalled();
  });

  it('stores no address when the backend vouched for none', async () => {
    const { service, tx, record } = setup({ count: 1 });
    await service.addAudience(tx as never, SID, 'VRMS', {
      ip: null,
      clientId: 'vrms-backend',
    });
    expect(lastEvent(record)).toMatchObject({ meta: { ip: null } });
  });

  it('stores no address when the header is not an address', async () => {
    const { service, tx, record } = setup({ count: 1 });
    await service.addAudience(tx as never, SID, 'VRMS', {
      ip: 'not-an-ip',
      clientId: 'vrms-backend',
    });
    expect(lastEvent(record)).toMatchObject({ meta: { ip: null } });
  });
});

// covers: AC-1, AC-4
describe('SessionService.createMobile events', () => {
  it('writes SIGNED_IN and SYSTEM_OPENED together with the device the app named', async () => {
    const { service, recordMany } = setup();
    await service.createMobile({
      userId: USER,
      clientId: 'vmms-mobile',
      audience: 'VMMS',
      deviceName: 'Pixel 8',
      meta: { ip: '112.198.0.1', device: 'Pixel 8', userAgent: 'okhttp/4' },
    });
    expect(recordMany).toHaveBeenCalledTimes(1);
    const events = recordMany.mock.calls[0][1] as Record<string, unknown>[];
    expect(events.map((e) => e.type)).toEqual(['SIGNED_IN', 'SYSTEM_OPENED']);
    expect(events[0].system).toBeUndefined();
    expect(events[1].system).toBe('VMMS');
    for (const e of events) {
      expect(e).toMatchObject({
        userId: USER,
        actorId: USER,
        sessionId: SID,
        clientId: 'vmms-mobile',
        meta: { device: 'Pixel 8' },
      });
    }
  });
});
