/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return -- the faked database is untyped on purpose */
import { describe, it, expect, jest } from '@jest/globals';
import { AccountEventType, SystemType } from '@prisma/client';
import { fakeConfig } from '../config/fake-config.setup';
import type { MailService } from '../shared/mail.service';
import type { PrismaService } from '../shared/prisma.service';
import { AuthService } from './auth.service';
import type { CodeService } from './codes/code.service';
import { AccountEventsService } from './events/account-events.service';
import type { PasswordCheckService } from './reauth/password-check.service';
import type { SessionService } from './sessions/session.service';
import { fakeAdminAlerts, fakeAdminStanding } from './testing/admin.fake';
import { FakeCatalogService } from './testing/catalog.fake';
import { noGeo } from './testing/geo.fake';
import type { TokenService } from './tokens/token.service';

// Suite spec 0018, child 0001 AC-14 and AC-17: Add people (`moveToRole`). The database, the
// password check and the admin standing are faked; each rule has its own test.

const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
const SUITE_ID = '99999999-9999-4999-8999-999999999999';
const A = '22222222-2222-4222-8222-222222222222';
const B = '33333333-3333-4333-8333-333333333333';

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const systemAdmin = {
  id: ADMIN_ID,
  email: 'admin@welinc.com',
  system: SystemType.VRMS,
  sid: 'sid-admin',
};
const suiteActor = { ...systemAdmin, id: SUITE_ID, suite: true };

type Person = {
  id: string;
  name: string;
  isActive?: boolean;
  roles: { role: string; system: SystemType; temporaryGrantId?: string }[];
};

function build(opts: {
  people: Person[];
  role?: { is_system_admin: boolean; deleted_at: Date | null } | null;
  othersAdmins?: number;
  suiteAdmins?: string[];
}) {
  const roleRow =
    opts.role === undefined
      ? { is_system_admin: false, deleted_at: null }
      : opts.role;
  const db = {
    user: { findMany: fn(), count: fn() },
    userRoleAssignment: { deleteMany: fn(), create: fn() },
    accountEvent: { create: fn(), createMany: fn() },
    $queryRaw: fn(),
    $transaction: fn(),
  };
  db.$transaction.mockImplementation((arg: unknown) =>
    (arg as (tx: typeof db) => unknown)(db),
  );
  db.$queryRaw.mockImplementation((strings: TemplateStringsArray) =>
    Promise.resolve(
      strings.join('?').includes('FROM "system_roles"') && roleRow
        ? [roleRow]
        : [],
    ),
  );
  db.user.findMany.mockResolvedValue(
    opts.people.map((p) => ({
      isActive: true,
      ...p,
      roles: p.roles.map((r) => ({ temporaryGrantId: null, ...r })),
    })),
  );
  db.user.count.mockResolvedValue(opts.othersAdmins ?? 1);
  const consumeReauthToken = fn();
  consumeReauthToken.mockImplementation(
    (_tx: unknown, token: string | undefined) =>
      token
        ? Promise.resolve()
        : Promise.reject(
            Object.assign(new Error('REAUTH_REQUIRED'), {
              code: 'REAUTH_REQUIRED',
            }),
          ),
  );
  const alerts = fakeAdminAlerts();
  const service = new AuthService(
    db as unknown as PrismaService,
    {} as TokenService,
    {} as MailService,
    fakeConfig({}),
    {} as SessionService,
    new FakeCatalogService(),
    {} as CodeService,
    new AccountEventsService(db as unknown as PrismaService, noGeo),
    { consumeReauthToken } as unknown as PasswordCheckService,
    fakeAdminStanding(
      Object.fromEntries(
        (opts.suiteAdmins ?? []).map((id) => [
          id,
          { suiteAdmin: true, adminOf: [] },
        ]),
      ),
    ),
    alerts,
  );
  return { service, db, consumeReauthToken, alerts };
}

function written(db: ReturnType<typeof build>['db']) {
  return {
    creates: db.userRoleAssignment.create.mock.calls.map((c) => c[0].data),
    events: [
      ...db.accountEvent.create.mock.calls.map((c) => c[0].data),
      ...db.accountEvent.createMany.mock.calls.flatMap((c) => c[0].data),
    ],
  };
}

const mechanic = (id: string, name = 'Pedro'): Person => ({
  id,
  name,
  roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
});

async function codeOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    const e = error as {
      code?: string;
      getResponse?: () => { code?: string };
    };
    return e.getResponse?.().code ?? e.code;
  }
}

describe('AuthService.moveToRole (suite spec 0018, AC-14, AC-17)', () => {
  it('moves each person into the role, replacing only this system, and records ROLE_CHANGED', async () => {
    const shared: Person = {
      id: B,
      name: 'Rosa',
      roles: [
        { role: 'MECHANIC', system: SystemType.VRMS },
        { role: 'DRIVER', system: SystemType.VMMS },
      ],
    };
    const { service, db } = build({ people: [mechanic(A), shared] });

    const answer = await service.moveToRole(
      'CHIEF_MECHANIC',
      [A, B],
      undefined,
      systemAdmin,
    );

    expect(answer).toEqual({ moved: 2, skipped: 0 });
    for (const id of [A, B]) {
      expect(db.userRoleAssignment.deleteMany).toHaveBeenCalledWith({
        where: {
          userId: id,
          system: SystemType.VRMS,
          role: { not: 'CHIEF_MECHANIC' },
        },
      });
    }
    const { creates, events } = written(db);
    expect(creates).toEqual([
      { userId: A, system: SystemType.VRMS, role: 'CHIEF_MECHANIC' },
      { userId: B, system: SystemType.VRMS, role: 'CHIEF_MECHANIC' },
    ]);
    expect(events).toEqual([
      expect.objectContaining({
        userId: A,
        type: AccountEventType.ROLE_CHANGED,
        oldValue: 'MECHANIC@VRMS',
        newValue: 'CHIEF_MECHANIC@VRMS',
        system: SystemType.VRMS,
      }),
      expect.objectContaining({
        userId: B,
        type: AccountEventType.ROLE_CHANGED,
        oldValue: 'MECHANIC@VRMS',
        newValue: 'CHIEF_MECHANIC@VRMS',
      }),
    ]);
  });

  it('locks the role row before any account, so a Delete cannot race the move', async () => {
    const { service, db } = build({ people: [mechanic(A)] });
    await service.moveToRole('CHIEF_MECHANIC', [A], undefined, systemAdmin);
    const sql = db.$queryRaw.mock.calls.map((c) =>
      (c[0] as TemplateStringsArray).join('?'),
    );
    expect(sql[0]).toContain('FROM "system_roles"');
    expect(sql[0]).toContain('FOR UPDATE');
    expect(sql[1]).toContain('FROM users');
  });

  it('skips people who already hold the role and writes nothing for them', async () => {
    const chief: Person = {
      id: A,
      name: 'Ramon',
      roles: [{ role: 'CHIEF_MECHANIC', system: SystemType.VRMS }],
    };
    const { service, db } = build({ people: [chief] });
    await expect(
      service.moveToRole('CHIEF_MECHANIC', [A, A], undefined, systemAdmin),
    ).resolves.toEqual({ moved: 0, skipped: 1 });
    expect(db.userRoleAssignment.create).not.toHaveBeenCalled();
    expect(written(db).events).toEqual([]);
  });

  it('answers UNKNOWN_ROLE for a role that is missing or archived', async () => {
    for (const role of [
      null,
      { is_system_admin: false, deleted_at: new Date() },
    ]) {
      const { service, db } = build({ people: [mechanic(A)], role });
      expect(
        await codeOf(
          service.moveToRole('C_TIRE_SPECIALIST', [A], undefined, systemAdmin),
        ),
      ).toBe('UNKNOWN_ROLE');
      expect(db.userRoleAssignment.create).not.toHaveBeenCalled();
    }
  });

  it('answers SELF_ROLE when the caller is in the list, before any write', async () => {
    const { service, db } = build({ people: [mechanic(A)] });
    expect(
      await codeOf(
        service.moveToRole(
          'CHIEF_MECHANIC',
          [A, ADMIN_ID],
          undefined,
          systemAdmin,
        ),
      ),
    ).toBe('SELF_ROLE');
    expect(db.$transaction).not.toHaveBeenCalled();
  });

  it('answers NOT_IN_SYSTEM for someone with no role in the system, and nobody moves', async () => {
    const outsider: Person = {
      id: B,
      name: 'Alberto',
      roles: [{ role: 'DRIVER', system: SystemType.BMS }],
    };
    const { service, db } = build({ people: [mechanic(A), outsider] });
    expect(
      await codeOf(
        service.moveToRole('CHIEF_MECHANIC', [A, B], undefined, systemAdmin),
      ),
    ).toBe('NOT_IN_SYSTEM');
    expect(db.userRoleAssignment.create).not.toHaveBeenCalled();
  });

  it('answers TEMPORARY_ROLE for a temporary holder, and nobody moves', async () => {
    const temporary: Person = {
      id: B,
      name: 'Lito',
      roles: [
        {
          role: 'MECHANIC',
          system: SystemType.VRMS,
          temporaryGrantId: 'grant-1',
        },
      ],
    };
    const { service, db } = build({ people: [mechanic(A), temporary] });
    expect(
      await codeOf(
        service.moveToRole('CHIEF_MECHANIC', [A, B], undefined, systemAdmin),
      ),
    ).toBe('TEMPORARY_ROLE');
    expect(db.userRoleAssignment.create).not.toHaveBeenCalled();
  });

  it('answers SUITE_ADMIN_NO_ROLES for a suite admin', async () => {
    const { service } = build({ people: [mechanic(A)], suiteAdmins: [A] });
    expect(
      await codeOf(
        service.moveToRole('CHIEF_MECHANIC', [A], undefined, systemAdmin),
      ),
    ).toBe('SUITE_ADMIN_NO_ROLES');
  });

  it('judges LAST_ADMIN on the whole batch: every leaving admin is left out of the count', async () => {
    const admin = (id: string, name: string): Person => ({
      id,
      name,
      roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
    });
    const { service, db } = build({
      people: [admin(A, 'Victor'), admin(B, 'Liza')],
      othersAdmins: 0,
    });
    expect(
      await codeOf(
        service.moveToRole('MECHANIC', [A, B], undefined, systemAdmin),
      ),
    ).toBe('LAST_ADMIN');
    expect(db.user.count).toHaveBeenCalledWith({
      where: expect.objectContaining({ id: { notIn: [A, B] } }),
    });
    expect(db.userRoleAssignment.create).not.toHaveBeenCalled();
  });

  it('moves admins off the admin role while another admin stays', async () => {
    const { service } = build({
      people: [
        {
          id: A,
          name: 'Victor',
          roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
        },
      ],
      othersAdmins: 1,
    });
    await expect(
      service.moveToRole('MECHANIC', [A], undefined, systemAdmin),
    ).resolves.toEqual({ moved: 1, skipped: 0 });
  });

  it('asks for the password only when the target is the admin role', async () => {
    const toAdmin = build({
      people: [mechanic(A)],
      role: { is_system_admin: true, deleted_at: null },
    });
    expect(
      await codeOf(
        toAdmin.service.moveToRole('ADMIN', [A], undefined, systemAdmin),
      ),
    ).toBe('REAUTH_REQUIRED');
    expect(toAdmin.db.userRoleAssignment.create).not.toHaveBeenCalled();
    await expect(
      toAdmin.service.moveToRole('ADMIN', [A], 'token', systemAdmin),
    ).resolves.toEqual({ moved: 1, skipped: 0 });

    const toChief = build({ people: [mechanic(A)] });
    await toChief.service.moveToRole(
      'CHIEF_MECHANIC',
      [A],
      undefined,
      suiteActor,
    );
    expect(toChief.consumeReauthToken).not.toHaveBeenCalled();
  });

  it('alerts like Change role: the admin role added, and every role a suite admin gives', async () => {
    const toAdmin = build({
      people: [mechanic(A)],
      role: { is_system_admin: true, deleted_at: null },
    });
    await toAdmin.service.moveToRole('ADMIN', [A], 'token', systemAdmin);
    expect(toAdmin.alerts.sent[0][1]).toEqual([
      expect.objectContaining({ kind: 'ADMIN_ROLE_ADDED', targetId: A }),
    ]);

    const bySuite = build({ people: [mechanic(A)] });
    await bySuite.service.moveToRole(
      'CHIEF_MECHANIC',
      [A],
      undefined,
      suiteActor,
    );
    expect(bySuite.alerts.sent[0][1]).toEqual([
      expect.objectContaining({
        kind: 'SUITE_ROLE_GIVEN',
        targetId: A,
        role: 'CHIEF_MECHANIC',
      }),
    ]);
  });
});
