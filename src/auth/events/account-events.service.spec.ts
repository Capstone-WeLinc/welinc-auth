/* eslint-disable @typescript-eslint/require-await, @typescript-eslint/no-unused-vars, @typescript-eslint/no-unnecessary-type-assertion -- test doubles */
import { describe, expect, it, jest } from '@jest/globals';
import { NotFoundException } from '@nestjs/common';
import { AccountEventType } from '@prisma/client';
import type { PrismaService } from '../../shared/prisma.service';
import {
  AccountEventsService,
  actorKind,
  adminView,
  keysetWhere,
  newestFirst,
  ownView,
  pageOf,
  type EventRow,
} from './account-events.service';
import { decodeEventCursor } from './event-cursor';
import type { GeoService } from './geo.service';

const USER = '11111111-1111-4111-8111-111111111111';
const ADMIN = '22222222-2222-4222-8222-222222222222';
const at = (iso: string) => new Date(iso);

function row(over: Partial<EventRow> = {}): EventRow {
  return {
    id: '0b6f7a52-3c1e-4a8e-9d3b-1f2a3b4c5d6e',
    userId: USER,
    actorId: USER,
    category: 'SIGN_IN',
    type: AccountEventType.SIGNED_IN,
    reason: null,
    system: null,
    sessionId: null,
    clientId: 'web-portal',
    field: null,
    oldValue: null,
    newValue: null,
    attemptsLeft: null,
    ip: '172.19.0.1',
    device: 'Chrome on Windows',
    userAgent: 'UA',
    country: null,
    network: null,
    createdAt: at('2026-11-12T01:00:00.123Z'),
    ...over,
  } as EventRow;
}

function service(geo = { country: 'PH', network: 'Globe', asn: 1 }) {
  const create = jest.fn(async (_a: unknown) => undefined);
  const createMany = jest.fn(async (_a: unknown) => undefined);
  const findMany = jest.fn(async (_a: unknown) => [] as unknown[]);
  const findFirst = jest.fn(async (_a: unknown) => null as unknown);
  const prisma = {
    accountEvent: { findMany },
    userRoleAssignment: { findFirst },
  } as unknown as PrismaService;
  const lookup = jest.fn((_ip: string | null) => geo);
  const svc = new AccountEventsService(prisma, {
    lookup,
  } as unknown as GeoService);
  const db = { accountEvent: { create, createMany } } as never;
  return { svc, db, create, createMany, findMany, findFirst, lookup };
}

describe('actorKind', () => {
  it('is SYSTEM when nobody acted, SELF for the person, ADMIN for someone else', () => {
    expect(actorKind({ userId: USER, actorId: null })).toBe('SYSTEM');
    expect(actorKind({ userId: USER, actorId: USER })).toBe('SELF');
    expect(actorKind({ userId: USER, actorId: ADMIN })).toBe('ADMIN');
  });
});

// covers: AC-11 (own view hides the admin's identity), AC-17, AC-19
describe('ownView', () => {
  it('shows only the actor kind for an admin action, never the admin', () => {
    const view = ownView(row({ actorId: ADMIN, type: 'ROLE_CHANGED' }));
    expect(view.actor).toEqual({ kind: 'ADMIN' });
    expect(JSON.stringify(view)).not.toContain(ADMIN);
  });

  it('marks a Docker bridge address as local network', () => {
    expect(ownView(row({ ip: '172.19.0.1' })).localNetwork).toBe(true);
    expect(ownView(row({ ip: '112.198.0.1' })).localNetwork).toBe(false);
    expect(ownView(row({ ip: null })).localNetwork).toBe(false);
  });

  it('writes createdAt as an ISO string', () => {
    expect(ownView(row()).createdAt).toBe('2026-11-12T01:00:00.123Z');
  });
});

// covers: AC-6, AC-12, AC-13 (admin sees the actor and only their own system's client)
describe('adminView', () => {
  const admin = { id: ADMIN, name: 'Ada Admin' };

  it('names the admin actor', () => {
    const view = adminView(
      { ...row({ actorId: ADMIN }), actor: admin } as never,
      'VRMS',
    );
    expect(view.actor).toEqual({ kind: 'ADMIN', id: ADMIN, name: 'Ada Admin' });
  });

  it('gives a system event no actor id or name', () => {
    const view = adminView(
      { ...row({ actorId: null }), actor: null } as never,
      'VRMS',
    );
    expect(view.actor).toEqual({ kind: 'SYSTEM' });
  });

  it('keeps the client on rows of the admin system only', () => {
    const own = adminView(
      { ...row({ system: 'VRMS' }), actor: null } as never,
      'VRMS',
    );
    const other = adminView(
      { ...row({ system: 'BMS' }), actor: null } as never,
      'VRMS',
    );
    const wide = adminView(
      { ...row({ system: null }), actor: null } as never,
      'VRMS',
    );
    expect(own.client).toBe('web-portal');
    expect(other.client).toBeNull();
    expect(wide.client).toBeNull();
  });
});

describe('paging helpers', () => {
  it('orders newest first and breaks ties by larger id first', () => {
    const a = { createdAt: at('2026-11-12T01:00:00.000Z'), id: 'a' };
    const b = { createdAt: at('2026-11-12T02:00:00.000Z'), id: 'b' };
    const c = { createdAt: at('2026-11-12T01:00:00.000Z'), id: 'c' };
    expect([a, b, c].sort(newestFirst).map((r) => r.id)).toEqual([
      'b',
      'c',
      'a',
    ]);
  });

  it('gives no cursor on a last page', () => {
    const rows = [row()];
    expect(pageOf(rows, 2, (r) => r.id).nextCursor).toBeNull();
  });

  it('cuts the extra row and points the cursor at the last kept one', () => {
    const rows = [
      row({
        id: '00000000-0000-4000-8000-000000000003',
        createdAt: at('2026-11-12T03:00:00.000Z'),
      }),
      row({
        id: '00000000-0000-4000-8000-000000000002',
        createdAt: at('2026-11-12T02:00:00.000Z'),
      }),
      row({
        id: '00000000-0000-4000-8000-000000000001',
        createdAt: at('2026-11-12T01:00:00.000Z'),
      }),
    ];
    const page = pageOf(rows, 2, (r) => r.id);
    expect(page.data).toHaveLength(2);
    const cursor = decodeEventCursor(page.nextCursor as string);
    expect(cursor.id).toBe('00000000-0000-4000-8000-000000000002');
    expect(cursor.createdAt.toISOString()).toBe('2026-11-12T02:00:00.000Z');
  });

  it('builds an empty filter when there is no cursor or date', () => {
    expect(keysetWhere({ cursor: null })).toEqual({});
  });

  it('builds the keyset, from and before conditions', () => {
    const cursor = { createdAt: at('2026-11-12T02:00:00.000Z'), id: 'x' };
    const where = keysetWhere({
      cursor,
      from: at('2026-11-01T00:00:00.000Z'),
      before: at('2026-11-13T00:00:00.000Z'),
    });
    expect(where).toEqual({
      AND: [
        {
          OR: [
            { createdAt: { lt: cursor.createdAt } },
            { createdAt: cursor.createdAt, id: { lt: 'x' } },
          ],
        },
        { createdAt: { gte: at('2026-11-01T00:00:00.000Z') } },
        { createdAt: { lt: at('2026-11-13T00:00:00.000Z') } },
      ],
    });
  });
});

// covers: AC-1, AC-3, AC-7, AC-17 (one writer, in the caller's transaction)
describe('AccountEventsService writes', () => {
  it('derives the category from the type and stores meta and place', () => {
    const { svc } = service();
    const data = svc.rowOf({
      userId: USER,
      type: 'SIGNED_IN',
      meta: { ip: '112.198.0.1', device: 'Pixel 8', userAgent: 'UA' },
    });
    expect(data).toMatchObject({
      userId: USER,
      actorId: null,
      category: 'SIGN_IN',
      type: 'SIGNED_IN',
      ip: '112.198.0.1',
      device: 'Pixel 8',
      country: 'PH',
      network: 'Globe',
    });
  });

  it('stores null for every optional field that was left out', () => {
    const { svc } = service({
      country: null,
      network: null,
      asn: null,
    } as never);
    const data = svc.rowOf({ userId: USER, type: 'SIGNED_OUT' });
    expect(data).toMatchObject({
      actorId: null,
      reason: null,
      system: null,
      sessionId: null,
      clientId: null,
      field: null,
      oldValue: null,
      newValue: null,
      attemptsLeft: null,
      ip: null,
      device: null,
      userAgent: null,
    });
  });

  it('looks the place up once, with the stored address', () => {
    const { svc, lookup } = service();
    svc.rowOf({
      userId: USER,
      type: 'SIGNED_IN',
      meta: { ip: '8.8.8.8', device: null, userAgent: null },
    });
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(lookup).toHaveBeenCalledWith('8.8.8.8');
  });

  it('writes through the transaction it was given', async () => {
    const { svc, db, create } = service();
    await svc.record(db, { userId: USER, type: 'SIGNED_OUT' });
    expect(create).toHaveBeenCalledTimes(1);
  });

  it('writes many in one createMany and nothing for an empty list', async () => {
    const { svc, db, createMany } = service();
    await svc.recordMany(db, []);
    expect(createMany).not.toHaveBeenCalled();
    await svc.recordMany(db, [
      { userId: USER, type: 'SIGNED_OUT' },
      { userId: USER, type: 'SIGNED_OUT' },
    ]);
    expect(createMany).toHaveBeenCalledTimes(1);
    expect(
      (createMany.mock.calls[0][0] as { data: unknown[] }).data,
    ).toHaveLength(2);
  });
});

describe('AccountEventsService reads', () => {
  const base = { cursor: null, limit: 2 };

  it('listOwn scopes to the caller and asks for one extra row', async () => {
    const { svc, findMany } = service();
    await svc.listOwn(USER, base);
    const args = findMany.mock.calls[0][0] as {
      where: { userId: string };
      take: number;
    };
    expect(args.where.userId).toBe(USER);
    expect(args.take).toBe(3);
  });

  // covers: AC-12
  it('listForUser answers 404 when the person holds no role in the system', async () => {
    const { svc, findMany } = service();
    await expect(svc.listForUser(USER, 'VRMS', base)).rejects.toBeInstanceOf(
      NotFoundException,
    );
    expect(findMany).not.toHaveBeenCalled();
  });

  it('listForUser reads only rows tagged with the system or account wide', async () => {
    const { svc, findMany, findFirst } = service();
    findFirst.mockResolvedValueOnce({ id: 'r' });
    await svc.listForUser(USER, 'VRMS', base);
    const args = findMany.mock.calls[0][0] as { where: { OR: unknown } };
    expect(args.where.OR).toEqual([{ system: 'VRMS' }, { system: null }]);
  });

  // covers: AC-13
  it('feed merges the tagged and account wide branches newest first and cuts to the limit', async () => {
    const { svc, findMany } = service();
    const mk = (id: string, iso: string) => ({
      ...row({ id, createdAt: at(iso), actorId: null }),
      actor: null,
      user: { id: USER, name: 'U', email: 'u@welinc.com' },
    });
    findMany
      .mockResolvedValueOnce([
        mk('00000000-0000-4000-8000-000000000004', '2026-11-12T04:00:00.000Z'),
        mk('00000000-0000-4000-8000-000000000002', '2026-11-12T02:00:00.000Z'),
      ])
      .mockResolvedValueOnce([
        mk('00000000-0000-4000-8000-000000000003', '2026-11-12T03:00:00.000Z'),
        mk('00000000-0000-4000-8000-000000000001', '2026-11-12T01:00:00.000Z'),
      ]);
    const page = await svc.feed('VRMS', { cursor: null, limit: 3 });
    expect(page.data.map((d) => d.id.slice(-1))).toEqual(['4', '3', '2']);
    expect(page.nextCursor).not.toBeNull();
    expect(page.data[0].user).toEqual({
      id: USER,
      name: 'U',
      email: 'u@welinc.com',
    });
  });

  it('feed reads the two branches with one scope each and the person filters', async () => {
    const { svc, findMany } = service();
    await svc.feed('VRMS', {
      cursor: null,
      limit: 5,
      q: 'multi',
      address: '8.8.8.8',
    });
    expect(findMany).toHaveBeenCalledTimes(2);
    const wheres = findMany.mock.calls.map((c) =>
      JSON.stringify((c[0] as { where: unknown }).where),
    );
    expect(wheres[0]).toContain('"system":"VRMS"');
    expect(wheres[1]).toContain('"system":null');
    expect(wheres[1]).toContain('"deletedAt":null');
    expect(wheres[0]).toContain('"ip":"8.8.8.8"');
    expect(wheres[0]).toContain('multi');
  });
});
