/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return -- the faked database is untyped on purpose */
import { describe, it, expect, jest } from '@jest/globals';
import { HttpException, NotFoundException } from '@nestjs/common';
import { AccountEventType, SystemType } from '@prisma/client';
import { fakeConfig } from '../config/fake-config.setup';
import type { MailService } from '../shared/mail.service';
import type { PrismaService } from '../shared/prisma.service';
import { AuthService } from './auth.service';
import { AccountEventsService } from './events/account-events.service';
import { PasswordCheckService } from './reauth/password-check.service';
import type { SessionService } from './sessions/session.service';
import { fakeAdminAlerts, fakeAdminStanding } from './testing/admin.fake';
import { FakeCatalogService } from './testing/catalog.fake';
import { fakeCodes } from './testing/codes.fake';
import { noGeo } from './testing/geo.fake';
import type { TokenService } from './tokens/token.service';
import type { ReadScope } from './user-scope';

// Suite spec 0017, AC-19 to AC-21: the People list and the person page read every system the
// admin holds when no system is named, with groups, sorts and the person page facts.

const USER_ID = '22222222-2222-4222-8222-222222222222';
const CREATOR_ID = '33333333-3333-4333-8333-333333333333';
const NOW = new Date('2026-11-23T08:00:00.000Z');
const LATER = new Date('2026-11-23T12:00:00.000Z');

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const SUITE: ReadScope = { systems: null, only: null, suite: true };
const MULTI: ReadScope = {
  systems: [SystemType.VRMS, SystemType.VMMS],
  only: null,
  suite: false,
};
const VRMS_ONLY: ReadScope = {
  systems: [SystemType.VRMS],
  only: SystemType.VRMS,
  suite: false,
};

function personRow(over: Record<string, unknown> = {}) {
  return {
    id: USER_ID,
    name: 'Pedro',
    email: 'pedro@welinc.com',
    emailVerified: true,
    passwordSet: true,
    contact: null,
    profilePicture: null,
    isActive: true,
    lockedAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    lastSignedInAt: NOW,
    roles: [
      {
        role: 'MECHANIC',
        system: SystemType.VRMS,
        createdAt: NOW,
        temporaryGrant: null,
      },
      {
        role: 'ADMIN',
        system: SystemType.VMMS,
        createdAt: NOW,
        temporaryGrant: { expiresAt: LATER },
      },
      {
        role: 'OPERATIONS',
        system: SystemType.BMS,
        createdAt: NOW,
        temporaryGrant: null,
      },
    ],
    deletionRequests: [],
    suiteAdmin: null,
    deletedAt: null,
    ...over,
  };
}

function build() {
  const db = {
    user: { findFirst: fn(), findMany: fn(), count: fn() },
    accountEvent: { findFirst: fn(), count: fn() },
    verificationCode: { findFirst: fn() },
  };
  db.user.findMany.mockResolvedValue([]);
  db.user.count.mockResolvedValue(0);
  db.accountEvent.findFirst.mockResolvedValue(null);
  db.accountEvent.count.mockResolvedValue(0);
  db.verificationCode.findFirst.mockResolvedValue(null);
  const countLive = fn();
  countLive.mockResolvedValue(2);
  const service = new AuthService(
    db as unknown as PrismaService,
    {} as TokenService,
    { sendMail: fn() } as unknown as MailService,
    fakeConfig({ ACCOUNT_ERASURE_GRACE_DAYS: '30' }),
    { countLive } as unknown as SessionService,
    new FakeCatalogService(),
    fakeCodes(),
    new AccountEventsService(db as unknown as PrismaService, noGeo),
    new PasswordCheckService(
      db as unknown as PrismaService,
      new AccountEventsService(db as unknown as PrismaService, noGeo),
    ),
    fakeAdminStanding(),
    fakeAdminAlerts(),
  );
  return { service, db, countLive };
}

const whereOf = (db: ReturnType<typeof build>['db']) =>
  db.user.findMany.mock.calls[0][0].where.AND as unknown[];

describe('listPeople for Add people (suite spec 0018, AC-14, AC-17)', () => {
  it('leaves out the holders of excludeRole in the named system', async () => {
    const { service, db } = build();
    await service.listPeople({ excludeRole: 'MECHANIC' }, VRMS_ONLY);
    expect(whereOf(db)).toContainEqual({
      NOT: {
        roles: { some: { system: SystemType.VRMS, role: 'MECHANIC' } },
      },
    });
  });

  it('refuses excludeRole without a system, and an unknown role', async () => {
    const { service } = build();
    await expect(
      service.listPeople({ excludeRole: 'MECHANIC' }, MULTI),
    ).rejects.toMatchObject({ response: { code: 'VALIDATION_FAILED' } });
    await expect(
      service.listPeople({ excludeRole: 'HELPER' }, VRMS_ONLY),
    ).rejects.toMatchObject({ response: { code: 'UNKNOWN_ROLE' } });
  });

  it('leaves out suite admins and the caller with assignable=true, nobody without it', async () => {
    const { service, db } = build();
    await service.listPeople({ assignable: 'true' }, VRMS_ONLY, CREATOR_ID);
    expect(whereOf(db)).toContainEqual({
      suiteAdmin: null,
      id: { not: CREATOR_ID },
    });

    const plain = build();
    await plain.service.listPeople(
      { assignable: 'false' },
      VRMS_ONLY,
      CREATOR_ID,
    );
    expect(whereOf(plain.db)).not.toContainEqual(
      expect.objectContaining({ suiteAdmin: null }),
    );
  });

  it('says since when each role is held', async () => {
    const { service, db } = build();
    db.user.findMany.mockResolvedValue([personRow()]);
    const { items } = await service.listPeople({}, VRMS_ONLY);
    expect(items[0].roles).toEqual([
      {
        role: 'MECHANIC',
        system: SystemType.VRMS,
        temporaryUntil: null,
        createdAt: NOW.toISOString(),
      },
    ]);
  });
});

describe('listPeople scope (AC-19)', () => {
  it('reads people with a role in any of the admin systems when no system is named', async () => {
    const { service, db } = build();
    await service.listPeople({}, MULTI);
    expect(whereOf(db)[1]).toEqual({
      roles: { some: { system: { in: [SystemType.VRMS, SystemType.VMMS] } } },
    });
  });

  it('keeps one named system as today', async () => {
    const { service, db } = build();
    await service.listPeople({}, VRMS_ONLY);
    expect(whereOf(db)[1]).toEqual({
      roles: { some: { system: SystemType.VRMS } },
    });
  });

  it('reads everyone for a suite admin', async () => {
    const { service, db } = build();
    await service.listPeople({}, SUITE);
    expect(whereOf(db)[1]).toEqual({});
  });

  it('answers every role with no system named, and only that system with one', async () => {
    const { service, db } = build();
    db.user.findMany.mockResolvedValue([personRow()]);
    const wide = await service.listPeople({}, MULTI);
    expect(wide.items[0].roles.map((r) => r.system)).toEqual([
      SystemType.VRMS,
      SystemType.VMMS,
      SystemType.BMS,
    ]);
    expect(wide.items[0].otherSystems).toEqual([]);
    const one = await service.listPeople({}, VRMS_ONLY);
    expect(one.items[0].roles).toEqual([
      {
        role: 'MECHANIC',
        system: SystemType.VRMS,
        temporaryUntil: null,
        createdAt: NOW.toISOString(),
      },
    ]);
    expect(one.items[0].otherSystems).toEqual([
      SystemType.BMS,
      SystemType.VMMS,
    ]);
  });

  it('a role filter still needs a system', async () => {
    const { service } = build();
    await expect(
      service.listPeople({ role: 'MECHANIC' }, MULTI),
    ).rejects.toMatchObject({ response: { code: 'VALIDATION_FAILED' } });
  });
});

describe('listPeople fields (AC-21)', () => {
  it('carries lastSignedInAt, createdAt and each role temporaryUntil', async () => {
    const { service, db } = build();
    db.user.findMany.mockResolvedValue([personRow()]);
    const { items } = await service.listPeople({}, SUITE);
    expect(items[0]).toMatchObject({
      lastSignedInAt: NOW.toISOString(),
      createdAt: NOW.toISOString(),
      temporaryUntil: LATER.toISOString(),
    });
    expect(items[0].roles[1]).toEqual({
      role: 'ADMIN',
      system: SystemType.VMMS,
      temporaryUntil: LATER.toISOString(),
      createdAt: NOW.toISOString(),
    });
    expect(items[0]).not.toHaveProperty('deletionRequests');
  });
});

describe('listPeople groups, sorts and search (AC-5, AC-20)', () => {
  it('adds the three counts only when a group is asked for', async () => {
    const { service, db } = build();
    db.user.count
      .mockResolvedValueOnce(2)
      .mockResolvedValueOnce(5)
      .mockResolvedValueOnce(1);
    const grouped = await service.listPeople({ group: 'active' }, MULTI);
    expect(grouped.counts).toEqual({ attention: 2, active: 5, inactive: 1 });
    const plain = await service.listPeople({}, MULTI);
    expect(plain).not.toHaveProperty('counts');
  });

  it('orders by each sort and ends on id', async () => {
    const { service, db } = build();
    await service.listPeople({ sort: 'lastSignedIn' }, SUITE);
    await service.listPeople({ sort: 'newest' }, SUITE);
    await service.listPeople({}, SUITE);
    expect(db.user.findMany.mock.calls.map((c) => c[0].orderBy)).toEqual([
      [{ lastSignedInAt: { sort: 'desc', nulls: 'last' } }, { id: 'asc' }],
      [{ createdAt: 'desc' }, { id: 'asc' }],
      [{ name: 'asc' }, { id: 'asc' }],
    ]);
  });

  it('hands out a cursor that only works for the same sort and filters', async () => {
    const { service, db } = build();
    db.user.findMany.mockResolvedValue([
      personRow(),
      personRow({ id: CREATOR_ID }),
    ]);
    const first = await service.listPeople(
      { sort: 'newest', limit: '1', group: 'active' },
      MULTI,
    );
    expect(first.next).not.toBeNull();
    db.user.findMany.mockResolvedValue([]);
    await expect(
      service.listPeople(
        { sort: 'newest', limit: '1', group: 'active', cursor: first.next! },
        MULTI,
      ),
    ).resolves.toMatchObject({ items: [] });
    for (const changed of [
      { sort: 'name' as const, group: 'active' as const },
      { sort: 'newest' as const, group: 'inactive' as const },
      { sort: 'newest' as const, group: 'active' as const, q: 'pe' },
    ]) {
      await expect(
        service.listPeople({ ...changed, cursor: first.next! }, MULTI),
      ).rejects.toMatchObject({ response: { code: 'INVALID_CURSOR' } });
    }
    await expect(
      service.listPeople(
        { sort: 'newest', group: 'active', cursor: first.next! },
        VRMS_ONLY,
      ),
    ).rejects.toBeInstanceOf(HttpException);
  });

  it('matches role display names in the systems in scope only', async () => {
    const { service, db } = build();
    await service.listPeople({ q: 'operations' }, MULTI);
    const search = whereOf(db)[2] as { OR: unknown[] };
    expect(search.OR).toEqual([
      { name: { contains: 'operations', mode: 'insensitive' } },
      { email: { contains: 'operations', mode: 'insensitive' } },
      {
        roles: {
          some: { system: SystemType.VMMS, role: { in: ['OPERATIONS'] } },
        },
      },
    ]);
  });

  it('reads a comma list of statuses as any of them', async () => {
    const { service, db } = build();
    await service.listPeople({ status: 'INACTIVE,LOCKED' }, SUITE);
    const status = whereOf(db)[3] as { OR: unknown[] };
    expect(status.OR).toHaveLength(2);
    expect(status.OR[1]).toEqual({ isActive: false });
  });
});

describe('getPerson (AC-19, AC-21)', () => {
  it('answers 404 for a soft deleted person to a system admin with no system named', async () => {
    const { service, db } = build();
    db.user.findFirst.mockResolvedValue(personRow({ deletedAt: NOW }));
    await expect(service.getPerson(USER_ID, MULTI)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('finds a soft deleted person for a suite admin, with when they can be restored', async () => {
    const { service, db } = build();
    db.user.findFirst.mockResolvedValue(personRow({ deletedAt: NOW }));
    const person = await service.getPerson(USER_ID, SUITE);
    expect(person.deletedAt).toBe(NOW.toISOString());
    expect(person.restorableUntil).toBe('2026-12-23T08:00:00.000Z');
  });

  it('answers 404 for someone whose only roles are elsewhere', async () => {
    const { service, db } = build();
    db.user.findFirst.mockResolvedValue(
      personRow({
        roles: [
          { role: 'ADMIN', system: SystemType.BMS, temporaryGrant: null },
        ],
      }),
    );
    await expect(service.getPerson(USER_ID, MULTI)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });

  it('carries the person page facts', async () => {
    const { service, db, countLive } = build();
    db.user.findFirst.mockResolvedValue(personRow({ passwordSet: false }));
    db.accountEvent.findFirst.mockResolvedValue({
      actor: { id: CREATOR_ID, name: 'Ada Admin', erasedAt: null },
    });
    db.accountEvent.count.mockResolvedValue(3);
    db.verificationCode.findFirst.mockResolvedValue({ expiresAt: LATER });
    const person = await service.getPerson(USER_ID, MULTI);
    expect(person).toMatchObject({
      addedBy: { id: CREATOR_ID, name: 'Ada Admin' },
      failedSignIns30d: 3,
      sessionCount: 2,
      setupCodeExpiresAt: LATER.toISOString(),
      restorableUntil: null,
      lastSignedInAt: NOW.toISOString(),
    });
    expect(countLive).toHaveBeenCalledWith(USER_ID, expect.any(Date));
    const failed = db.accountEvent.count.mock.calls[0][0].where;
    expect(failed.type).toEqual({
      in: [AccountEventType.SIGN_IN_FAILED, AccountEventType.LOCKED_OUT],
    });
    const since = failed.createdAt.gte as Date;
    expect(Date.now() - since.getTime()).toBeGreaterThanOrEqual(
      30 * 86_400_000 - 1_000,
    );
    expect(db.verificationCode.findFirst.mock.calls[0][0].where).toEqual({
      userId: USER_ID,
      purpose: 'PASSWORD_SETUP',
      usedAt: null,
    });
  });

  it.each([
    ['the person made it', { id: USER_ID, name: 'Pedro', erasedAt: null }],
    [
      'the creator is erased',
      { id: CREATOR_ID, name: 'Deleted user', erasedAt: NOW },
    ],
    ['nobody is known', null],
  ])('has no addedBy when %s', async (_case, actor) => {
    const { service, db } = build();
    db.user.findFirst.mockResolvedValue(personRow());
    db.accountEvent.findFirst.mockResolvedValue(actor ? { actor } : null);
    const person = await service.getPerson(USER_ID, MULTI);
    expect(person.addedBy).toBeNull();
  });
});

// covers: suite spec 0019 AC-21a (access on the list, its cursor key, access with role) and
// AC-21b (the facets: each facet ignores its own filter, scope, order and zeros)

describe('listPeople access filter (AC-21a)', () => {
  it('adds the access clause after the statuses', async () => {
    const { service, db } = build();
    await service.listPeople({ access: 'VMMS:MECHANIC' }, MULTI);
    expect(whereOf(db)[4]).toEqual({
      roles: { some: { system: SystemType.VMMS, role: { in: ['MECHANIC'] } } },
    });
  });

  it('refuses access together with role', async () => {
    const { service } = build();
    await expect(
      service.listPeople({ access: 'VRMS', role: 'MECHANIC' }, VRMS_ONLY),
    ).rejects.toMatchObject({ response: { code: 'VALIDATION_FAILED' } });
  });

  it('binds the cursor to the normalized picks', async () => {
    const { service, db } = build();
    db.user.findMany.mockResolvedValue([
      personRow(),
      personRow({ id: CREATOR_ID }),
    ]);
    const first = await service.listPeople(
      { limit: '1', access: 'VMMS' },
      MULTI,
    );
    db.user.findMany.mockResolvedValue([]);
    await expect(
      service.listPeople(
        { limit: '1', access: 'VMMS:MECHANIC,VMMS', cursor: first.next! },
        MULTI,
      ),
    ).resolves.toMatchObject({ items: [] });
    await expect(
      service.listPeople(
        { limit: '1', access: 'VRMS', cursor: first.next! },
        MULTI,
      ),
    ).rejects.toMatchObject({ response: { code: 'INVALID_CURSOR' } });
    await expect(
      service.listPeople({ limit: '1', cursor: first.next! }, MULTI),
    ).rejects.toMatchObject({ response: { code: 'INVALID_CURSOR' } });
  });

  it('refuses a system outside the read scope', async () => {
    const { service } = build();
    await expect(
      service.listPeople({ access: 'BMS' }, MULTI),
    ).rejects.toMatchObject({ response: { code: 'NOT_ADMIN_OF_SYSTEM' } });
  });
});

describe('facetPeople (AC-21b)', () => {
  type CountArgs = { where: { AND: unknown[] } };

  function facets() {
    const built = build();
    const groupBy = fn();
    groupBy.mockResolvedValue([]);
    (built.db as Record<string, unknown>).userRoleAssignment = { groupBy };
    return { ...built, groupBy };
  }

  it('answers every status, system and role in order, zeros included', async () => {
    const { service, db, groupBy } = facets();
    db.user.count.mockResolvedValue(0);
    groupBy.mockResolvedValue([
      { system: SystemType.VMMS, role: 'MECHANIC', _count: { _all: 4 } },
    ]);
    const answer = await service.facetPeople({}, MULTI);
    expect(Object.keys(answer.status)).toEqual([
      'ATTENTION',
      'LOCKED',
      'SETUP_PENDING',
      'ACTIVE_GROUP',
      'INACTIVE',
    ]);
    expect(answer.systems.map((s) => s.system)).toEqual([
      SystemType.VRMS,
      SystemType.VMMS,
    ]);
    expect(answer.systems[1].roles).toEqual([
      { code: 'ADMIN', count: 0 },
      { code: 'OPERATIONS', count: 0 },
      { code: 'CHIEF_MECHANIC', count: 0 },
      { code: 'MECHANIC', count: 4 },
    ]);
    expect(answer).not.toHaveProperty('items');
  });

  it('lists all three systems for a suite admin, only the named one with system', async () => {
    const { service } = facets();
    const suite = await service.facetPeople({}, SUITE);
    expect(suite.systems.map((s) => s.system)).toEqual([
      SystemType.VRMS,
      SystemType.VMMS,
      SystemType.BMS,
    ]);
    const one = await service.facetPeople({}, VRMS_ONLY);
    expect(one.systems.map((s) => s.system)).toEqual([SystemType.VRMS]);
  });

  it('counts each facet under every filter except its own', async () => {
    const { service, db, groupBy } = facets();
    await service.facetPeople(
      { status: 'LOCKED', access: 'VMMS:MECHANIC' },
      MULTI,
    );
    const calls = db.user.count.mock.calls.map(
      (c) => (c[0] as CountArgs).where.AND,
    );
    const lockedClause = { isActive: true, lockedAt: expect.anything() };
    const accessClause = {
      roles: { some: { system: SystemType.VMMS, role: { in: ['MECHANIC'] } } },
    };
    // total: every filter
    expect(calls[0]).toEqual(
      expect.arrayContaining([
        expect.objectContaining(lockedClause),
        accessClause,
      ]),
    );
    // status chips (1 to 5): access kept, the LOCKED pick gone, each chip's own rule added
    for (const where of calls.slice(1, 6)) {
      expect(where).toContainEqual(accessClause);
      expect(where).toHaveLength(calls[0].length);
    }
    expect(calls[5][calls[5].length - 1]).toEqual({ isActive: false });
    // systems (6, 7): status kept, access gone
    for (const where of calls.slice(6)) {
      expect(where).not.toContainEqual(accessClause);
    }
    expect(calls).toHaveLength(8);
    const roleWhere = groupBy.mock.calls[0][0].where;
    expect(roleWhere.system).toEqual({
      in: [SystemType.VRMS, SystemType.VMMS],
    });
    expect(roleWhere.user.AND).not.toContainEqual(accessClause);
  });

  it('uses the list search with the caller systems', async () => {
    const { service, db } = facets();
    await service.facetPeople({ q: 'driver' }, MULTI);
    const search = (db.user.count.mock.calls[0][0] as CountArgs).where
      .AND[2] as { OR: unknown[] };
    // BMS has the Driver role, but this admin has no BMS: names and emails only
    expect(search.OR).toHaveLength(2);
  });

  it('refuses the list filter errors', async () => {
    const { service } = facets();
    await expect(
      service.facetPeople({ access: 'BMS' }, MULTI),
    ).rejects.toMatchObject({ response: { code: 'NOT_ADMIN_OF_SYSTEM' } });
    await expect(
      service.facetPeople({ access: 'vrms' }, MULTI),
    ).rejects.toMatchObject({ response: { code: 'VALIDATION_FAILED' } });
  });
});
