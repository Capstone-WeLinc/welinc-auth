import { fakeAdminAlerts, fakeAdminStanding } from './testing/admin.fake';
/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return -- the faked database is untyped on purpose */
import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  jest,
} from '@jest/globals';
import {
  BadRequestException,
  ConflictException,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { fakeConfig } from '../config/fake-config.setup';
import type { TokenService } from './tokens/token.service';
import {
  SystemType,
  AccountEventType,
  VerificationPurpose,
} from '@prisma/client';
import type { CodeService } from './codes/code.service';
import { CodeSendLimitError, MailFailedError } from './codes/code-errors';
import { FakeCatalogService } from './testing/catalog.fake';
import type { MailService } from '../shared/mail.service';
import type { PrismaService } from '../shared/prisma.service';
import { AuthService } from './auth.service';
import { AccountEventsService } from './events/account-events.service';
import { PasswordCheckService } from './reauth/password-check.service';
import { noGeo } from './testing/geo.fake';
import { SessionService } from './sessions/session.service';

// VRMS spec 0009: admin safety guards (AC-19), the change record (AC-20, AC-21).
// Suite spec 0009: setup and reset codes through the code service (AC-12 to AC-15), and an
// admin changing someone's email (AC-21). The database, the mail server, the config and the
// code service are faked; the code service's own rules are in codes/code.service.spec.ts.

const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
const USER_ID = '22222222-2222-4222-8222-222222222222';
const actor = {
  id: ADMIN_ID,
  email: 'admin@welinc.com',
  system: SystemType.VRMS,
  sid: 'sid-admin',
};

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const NOW = new Date('2026-10-27T08:00:00.000Z');
const VRMS_MECHANIC = [{ role: 'MECHANIC', system: SystemType.VRMS }];

function managedRow(overrides: Record<string, unknown> = {}) {
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
    roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
    ...overrides,
  };
}

function build(env: Record<string, string | undefined> = {}) {
  const db = {
    user: {
      findFirst: fn(),
      findUnique: fn(),
      findUniqueOrThrow: fn(),
      update: fn(),
      create: fn(),
      count: fn(),
    },
    accountEvent: { create: fn(), createMany: fn(), findMany: fn() },
    accountDeletionRequest: { updateMany: fn() },
    $queryRaw: fn(),
    $transaction: fn(),
  };
  db.accountDeletionRequest.updateMany.mockResolvedValue({ count: 0 });
  db.$transaction.mockImplementation((arg: unknown) =>
    typeof arg === 'function'
      ? (arg as (tx: typeof db) => unknown)(db)
      : Promise.all(arg as Promise<unknown>[]),
  );
  db.$queryRaw.mockResolvedValue([]);
  db.user.count.mockResolvedValue(1);
  const sendMail = fn();
  sendMail.mockResolvedValue(undefined);
  const config = fakeConfig(env);
  const endAllForUser = jest.fn<
    (
      tx: unknown,
      userId: string,
      reason: string,
      meta?: unknown,
    ) => Promise<number>
  >(() => Promise.resolve(0));
  const sessions = { endAllForUser } as unknown as SessionService;
  // The code service, faked: issue mails through sendMail (code 123456) like the real one, and
  // throws MailFailedError when the mail fails; check answers a right code and runs onRight
  const codes = {
    issue: fn(),
    check: fn(),
    retireAll: fn(),
    retire: fn(),
    liveCode: fn(),
  };
  codes.issue.mockImplementation(
    async (input: {
      mail: { to: string; build: (code: string) => object };
    }) => {
      try {
        await sendMail({ to: input.mail.to, ...input.mail.build('123456') });
      } catch {
        throw new MailFailedError();
      }
      return {
        kind: 'sent',
        id: 'code-1',
        expiresAt: new Date(NOW.getTime() + 600_000),
        resendAfter: 60,
      };
    },
  );
  const codeRow = {
    id: 'code-1',
    userId: USER_ID,
    newEmail: null as string | null,
  };
  codes.check.mockImplementation(
    async (input: { onRight?: (tx: unknown, row: unknown) => unknown }) => ({
      kind: 'right',
      row: codeRow,
      value: await input.onRight?.(db, codeRow),
    }),
  );
  codes.liveCode.mockResolvedValue(null);
  const service = new AuthService(
    db as unknown as PrismaService,
    {} as TokenService,
    { sendMail } as unknown as MailService,
    config,
    sessions,
    new FakeCatalogService(),
    codes as unknown as CodeService,
    new AccountEventsService(db as unknown as PrismaService, noGeo),
    new PasswordCheckService(
      db as unknown as PrismaService,
      new AccountEventsService(db as unknown as PrismaService, noGeo),
    ),
    fakeAdminStanding(),
    fakeAdminAlerts(),
  );
  return { service, db, sendMail, sessions, endAllForUser, codes, codeRow };
}

/**
 * The raw locks on admin role rows (`assertAnotherAdmin`), leaving out the account row lock every
 * role write takes first (spec 0004, AC-13).
 */
function adminLocks(db: ReturnType<typeof build>['db']) {
  return db.$queryRaw.mock.calls.filter((call) =>
    (call[0] as TemplateStringsArray).join('?').includes('user_roles'),
  );
}

/** The UserChange rows written, from either create or createMany. */
function changesWritten(db: ReturnType<typeof build>['db']) {
  return [
    ...db.accountEvent.create.mock.calls.map((c) => c[0].data),
    ...db.accountEvent.createMany.mock.calls.flatMap((c) => c[0].data),
  ];
}

describe('AuthService admin writes', () => {
  describe('updateUserStatus', () => {
    // covers: AC-19
    it('refuses to let an admin deactivate their own account', async () => {
      const { service, db } = build();

      await expect(
        service.updateUserStatus(ADMIN_ID, { isActive: false }, actor),
      ).rejects.toThrow(
        new ConflictException("You can't deactivate your own account."),
      );
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    it('answers 404 for an unknown or deleted user', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue(null);

      await expect(
        service.updateUserStatus(USER_ID, { isActive: false }, actor),
      ).rejects.toBeInstanceOf(NotFoundException);
    });

    // covers: AC-19
    it('refuses to deactivate the last admin of a system, and writes nothing', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
      });
      db.user.count.mockResolvedValue(0);

      await expect(
        service.updateUserStatus(USER_ID, { isActive: false }, actor),
      ).rejects.toThrow('This is the last VRMS admin.');
      expect(db.user.update).not.toHaveBeenCalled();
      expect(changesWritten(db)).toEqual([]);
    });

    it('lets an admin be deactivated when another admin remains', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
      });
      db.user.update.mockResolvedValue(managedRow({ isActive: false }));

      const result = await service.updateUserStatus(
        USER_ID,
        { isActive: false },
        actor,
      );

      expect(result.isActive).toBe(false);
    });

    // covers: AC-20
    it('records DEACTIVATED with the acting admin in the same transaction', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
      });
      db.user.update.mockResolvedValue(managedRow({ isActive: false }));

      await service.updateUserStatus(USER_ID, { isActive: false }, actor);

      expect(db.$transaction).toHaveBeenCalledTimes(1);
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          actorId: ADMIN_ID,
          type: AccountEventType.DEACTIVATED,
          field: null,
        }),
      ]);
    });

    it('records ACTIVATED when a user is switched back on, without an admin guard', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: false,
        roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
      });
      db.user.update.mockResolvedValue(managedRow());

      await service.updateUserStatus(USER_ID, { isActive: true }, actor);

      expect(adminLocks(db)).toHaveLength(0);
      expect(changesWritten(db)[0]).toMatchObject({
        type: AccountEventType.ACTIVATED,
      });
    });

    // covers: AC-20 (a save that changes nothing writes no row)
    it('writes no row and no update when the status is already what was asked', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: VRMS_MECHANIC,
      });
      db.user.findUniqueOrThrow.mockResolvedValue(managedRow());

      await service.updateUserStatus(USER_ID, { isActive: true }, actor);

      expect(db.user.update).not.toHaveBeenCalled();
      expect(changesWritten(db)).toEqual([]);
    });
  });

  describe('deleteUser', () => {
    // covers: AC-19
    it('refuses to let an admin delete their own account', async () => {
      const { service, db } = build();

      await expect(service.deleteUser(ADMIN_ID, actor)).rejects.toThrow(
        new ConflictException("You can't delete your own account."),
      );
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    it('answers 404 for an unknown user', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue(null);

      await expect(service.deleteUser(USER_ID, actor)).rejects.toBeInstanceOf(
        NotFoundException,
      );
    });

    // covers: AC-19
    it('refuses to delete the last active admin of a system', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
      });
      db.user.count.mockResolvedValue(0);

      await expect(service.deleteUser(USER_ID, actor)).rejects.toThrow(
        'This is the last VRMS admin.',
      );
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('skips the last admin check for an admin who is already inactive', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: false,
        roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
      });

      await expect(service.deleteUser(USER_ID, actor)).resolves.toEqual({
        id: USER_ID,
      });
      expect(adminLocks(db)).toHaveLength(0);
    });

    // covers: AC-20
    it('soft deletes the user and records DELETED', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
      });

      await service.deleteUser(USER_ID, actor);

      expect(db.user.update).toHaveBeenCalledWith({
        where: { id: USER_ID },
        data: {
          deletedAt: expect.any(Date),
          isActive: false,
          lockedAt: null,
        },
      });
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          type: AccountEventType.DELETED,
        }),
      ]);
    });
  });

  describe('unlockUser', () => {
    // covers: AC-20
    it('clears the lock and records UNLOCKED', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        lockedAt: NOW,
        roles: VRMS_MECHANIC,
      });
      db.user.update.mockResolvedValue(managedRow());

      await service.unlockUser(USER_ID, actor);

      expect(db.user.update).toHaveBeenCalledWith(
        expect.objectContaining({
          data: { lockedAt: null, failedLoginAttempts: 0 },
        }),
      );
      expect(changesWritten(db)[0]).toMatchObject({
        type: AccountEventType.UNLOCKED,
      });
    });

    it('writes no row when the user was not locked', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        lockedAt: null,
        roles: VRMS_MECHANIC,
      });
      db.user.findUniqueOrThrow.mockResolvedValue(managedRow());

      await service.unlockUser(USER_ID, actor);

      expect(db.user.update).not.toHaveBeenCalled();
      expect(changesWritten(db)).toEqual([]);
    });

    it('answers 404 for an unknown user', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue(null);

      await expect(service.unlockUser(USER_ID, actor)).rejects.toBeInstanceOf(
        NotFoundException,
      );
    });
  });

  describe('updateUser', () => {
    const existing = (overrides: Record<string, unknown> = {}) => ({
      id: USER_ID,
      name: 'Pedro',
      email: 'pedro@welinc.com',
      passwordSet: true,
      isActive: true,
      deletedAt: null,
      roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
      ...overrides,
    });

    function arrange(row = existing()) {
      const ctx = build();
      ctx.db.user.findUnique.mockResolvedValue(row);
      ctx.db.user.update.mockResolvedValue(managedRow());
      return ctx;
    }

    // covers: AC-19
    it('refuses to let an admin change their own roles', async () => {
      const { service, db } = arrange(
        existing({
          id: ADMIN_ID,
          roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
        }),
      );

      await expect(
        service.updateUser(
          ADMIN_ID,
          {
            roleAssignments: [{ role: 'MECHANIC', system: SystemType.VRMS }],
          },
          actor,
        ),
      ).rejects.toThrow(
        new ConflictException("You can't change your own role."),
      );
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('refuses to let an admin deactivate themselves through an edit', async () => {
      const { service } = arrange(existing({ id: ADMIN_ID }));

      await expect(
        service.updateUser(ADMIN_ID, { isActive: false }, actor),
      ).rejects.toThrow("You can't deactivate your own account.");
    });

    it('lets an admin edit their own name', async () => {
      const { service, db } = arrange(existing({ id: ADMIN_ID }));

      await service.updateUser(ADMIN_ID, { name: 'New Name' }, actor);

      expect(db.user.update).toHaveBeenCalled();
    });

    // covers: AC-19
    it('refuses to remove ADMIN from the last admin of a system', async () => {
      const { service, db } = arrange(
        existing({
          roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
        }),
      );
      db.user.count.mockResolvedValue(0);

      await expect(
        service.updateUser(
          USER_ID,
          {
            roleAssignments: [{ role: 'MECHANIC', system: SystemType.VRMS }],
          },
          actor,
        ),
      ).rejects.toThrow('This is the last VRMS admin.');
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('refuses to deactivate the last admin through an edit', async () => {
      const { service, db } = arrange(
        existing({
          roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
        }),
      );
      db.user.count.mockResolvedValue(0);

      await expect(
        service.updateUser(USER_ID, { isActive: false }, actor),
      ).rejects.toThrow('This is the last VRMS admin.');
    });

    it('does not run the admin check when the admin keeps the ADMIN role', async () => {
      const { service, db } = arrange(
        existing({
          roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
        }),
      );

      await service.updateUser(USER_ID, { name: 'Renamed' }, actor);

      expect(adminLocks(db)).toHaveLength(0);
    });

    // Follow up from the review: decisions come from a read inside the transaction
    it('decides from the read inside the transaction, not the one before it', async () => {
      const { service, db } = arrange(
        existing({
          roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
        }),
      );
      // Between the two reads, another admin made this user the last VRMS admin
      db.user.findUnique
        .mockResolvedValueOnce(
          existing({
            roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
          }),
        )
        .mockResolvedValueOnce(
          existing({
            roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
          }),
        );
      db.user.count.mockResolvedValue(0);

      await expect(
        service.updateUser(USER_ID, { isActive: false }, actor),
      ).rejects.toThrow('This is the last VRMS admin.');
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('writes the old value from the read inside the transaction', async () => {
      const { service, db } = arrange();
      db.user.findUnique
        .mockResolvedValueOnce(existing({ name: 'Pedro' }))
        .mockResolvedValueOnce(existing({ name: 'Pedro Santos' }));

      await service.updateUser(USER_ID, { name: 'Pedro Cruz' }, actor);

      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          field: 'name',
          oldValue: 'Pedro Santos',
          newValue: 'Pedro Cruz',
        }),
      ]);
    });

    it('answers 404 when the user is deleted between the two reads', async () => {
      const { service, db } = arrange();
      db.user.findUnique
        .mockResolvedValueOnce(existing())
        .mockResolvedValueOnce(existing({ deletedAt: NOW }));

      await expect(
        service.updateUser(USER_ID, { name: 'X' }, actor),
      ).rejects.toBeInstanceOf(NotFoundException);
      expect(db.user.update).not.toHaveBeenCalled();
    });

    // Follow up from the review: one lock order, so two multi system admins can't deadlock
    it("locks a multi system admin's systems in sorted order", async () => {
      const { service, db } = arrange(
        existing({
          roles: [
            { role: 'ADMIN', system: SystemType.VRMS },
            { role: 'ADMIN', system: SystemType.BMS },
          ],
        }),
      );

      await service.updateUser(USER_ID, { isActive: false }, actor);

      const locked = adminLocks(db).map((call) => call[1]);
      expect(locked).toEqual([SystemType.BMS, SystemType.VRMS]);
    });

    // covers: AC-20
    it('writes one UPDATED row per changed field with old and new values', async () => {
      const { service, db } = arrange();

      await service.updateUser(
        USER_ID,
        { name: '  Pedro Cruz  ', email: 'Pedro.Cruz@welinc.com' },
        actor,
      );

      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          type: AccountEventType.UPDATED,
          field: 'name',
          oldValue: 'Pedro',
          newValue: 'Pedro Cruz',
        }),
        expect.objectContaining({
          type: AccountEventType.UPDATED,
          field: 'email',
          oldValue: 'pedro@welinc.com',
          newValue: 'pedro.cruz@welinc.com',
        }),
      ]);
    });

    it('writes ROLE_CHANGED with sorted ROLE@SYSTEM lists', async () => {
      const { service, db } = arrange(
        existing({
          roles: [
            { role: 'OPERATIONS', system: SystemType.BMS },
            { role: 'MECHANIC', system: SystemType.VRMS },
          ],
        }),
      );

      await service.updateUser(
        USER_ID,
        {
          roleAssignments: [
            { role: 'CHIEF_MECHANIC', system: SystemType.VRMS },
          ],
        },
        actor,
      );

      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          type: AccountEventType.ROLE_CHANGED,
          field: 'roles',
          // Spec 0011, AC-6: only the system that changed
          system: SystemType.VRMS,
          oldValue: 'MECHANIC@VRMS',
          newValue: 'CHIEF_MECHANIC@VRMS',
        }),
      ]);
    });

    it('writes DEACTIVATED when an edit switches the user off', async () => {
      const { service, db } = arrange();

      await service.updateUser(USER_ID, { isActive: false }, actor);

      expect(changesWritten(db)).toEqual([
        expect.objectContaining({ type: AccountEventType.DEACTIVATED }),
      ]);
    });

    // covers: AC-20 (a save that changes nothing writes no row)
    it('writes no row when the save changes nothing', async () => {
      const { service, db } = arrange();

      await service.updateUser(
        USER_ID,
        {
          name: 'Pedro',
          email: 'PEDRO@welinc.com',
          isActive: true,
          roleAssignments: [{ role: 'MECHANIC', system: SystemType.VRMS }],
        },
        actor,
      );

      expect(db.accountEvent.createMany).not.toHaveBeenCalled();
      expect(db.accountEvent.create).not.toHaveBeenCalled();
    });

    // Suite spec 0009, AC-21: an admin changing someone else's email
    describe('email change', () => {
      const NEW = 'pedro.new@welinc.com';

      it('refuses your own email with 409 SELF_EMAIL', async () => {
        const { service, db } = arrange(existing({ id: ADMIN_ID }));

        await expect(
          service.updateUser(ADMIN_ID, { email: NEW }, actor),
        ).rejects.toMatchObject({ response: { code: 'SELF_EMAIL' } });
        expect(db.user.update).not.toHaveBeenCalled();
      });

      it('answers 409 EMAIL_TAKEN when another account holds the address', async () => {
        const { service, db } = arrange();
        db.user.findFirst.mockResolvedValue({ id: 'someone-else' });

        await expect(
          service.updateUser(USER_ID, { email: NEW }, actor),
        ).rejects.toMatchObject({ response: { code: 'EMAIL_TAKEN' } });
        expect(db.user.findFirst).toHaveBeenCalledWith(
          expect.objectContaining({
            where: {
              email: { equals: NEW, mode: 'insensitive' },
              id: { not: USER_ID },
            },
          }),
        );
        expect(db.user.update).not.toHaveBeenCalled();
      });

      it('answers 409 EMAIL_TAKEN from the unique index when a race wins', async () => {
        const { service, db } = arrange();
        db.user.update.mockRejectedValue({ code: 'P2002' });

        await expect(
          service.updateUser(USER_ID, { email: NEW }, actor),
        ).rejects.toMatchObject({ response: { code: 'EMAIL_TAKEN' } });
      });

      it('sets emailVerified false and retires every live code in the same transaction', async () => {
        const { service, db, codes } = arrange();

        await service.updateUser(USER_ID, { email: NEW }, actor);

        expect(db.user.update).toHaveBeenCalledWith(
          expect.objectContaining({
            data: expect.objectContaining({ email: NEW, emailVerified: false }),
          }),
        );
        expect(codes.retireAll).toHaveBeenCalledWith(db, USER_ID);
      });

      it('tells the old address after the commit, naming the new one, and sends no code there', async () => {
        const { service, db, sendMail, codes } = arrange();
        db.user.update.mockResolvedValue(managedRow({ email: NEW }));

        const result = await service.updateUser(USER_ID, { email: NEW }, actor);

        expect(sendMail).toHaveBeenCalledTimes(1);
        expect(sendMail.mock.calls[0][0]).toMatchObject({
          to: 'pedro@welinc.com',
          subject: expect.stringContaining('admin changed your email'),
        });
        expect(sendMail.mock.calls[0][0].text).toContain(NEW);
        expect(codes.issue).not.toHaveBeenCalled();
        expect(result).not.toHaveProperty('setupEmailSent');
      });

      it('sends a new setup code to the new address while setup is pending', async () => {
        const { service, db, codes } = arrange(
          existing({ passwordSet: false }),
        );
        db.user.update.mockResolvedValue(
          managedRow({ email: NEW, passwordSet: false }),
        );

        const result = await service.updateUser(USER_ID, { email: NEW }, actor);

        expect(codes.issue).toHaveBeenCalledWith(
          expect.objectContaining({
            userId: USER_ID,
            purpose: VerificationPurpose.PASSWORD_SETUP,
            mail: expect.objectContaining({ to: NEW }),
          }),
        );
        expect(result).toMatchObject({ setupEmailSent: true });
      });

      it('answers setupEmailSent false when that send fails, and a failed notice is only logged', async () => {
        const { service, db, sendMail } = arrange(
          existing({ passwordSet: false }),
        );
        db.user.update.mockResolvedValue(
          managedRow({ email: NEW, passwordSet: false }),
        );
        sendMail.mockRejectedValue(new Error('SMTP down'));
        const logged = jest
          .spyOn(Logger.prototype, 'error')
          .mockImplementation(() => {});

        const result = await service.updateUser(USER_ID, { email: NEW }, actor);

        expect(result).toMatchObject({ setupEmailSent: false });
        expect(JSON.stringify(logged.mock.calls)).not.toContain('pedro');
        logged.mockRestore();
      });

      it('ignores a change of letter case only', async () => {
        const { service, db, codes } = arrange();

        await service.updateUser(USER_ID, { email: 'PEDRO@WELINC.COM' }, actor);

        expect(db.user.update.mock.calls[0][0].data).not.toHaveProperty(
          'email',
        );
        expect(codes.retireAll).not.toHaveBeenCalled();
      });
    });

    it('answers 404 for a soft deleted user', async () => {
      const { service } = arrange(existing({ deletedAt: NOW }));

      await expect(
        service.updateUser(USER_ID, { name: 'X' }, actor),
      ).rejects.toBeInstanceOf(NotFoundException);
    });
  });

  describe('createUser', () => {
    const dto = {
      name: ' Pedro ',
      email: 'Pedro@welinc.com',
      roleAssignments: [{ role: 'MECHANIC', system: SystemType.VRMS }],
    };

    function arrange(env: Record<string, string | undefined> = {}) {
      const ctx = build(env);
      ctx.db.user.create.mockResolvedValue(managedRow());
      return ctx;
    }

    afterEach(() => {
      jest.restoreAllMocks();
    });

    // covers: VRMS AC-18, AC-20; suite AC-15
    it('saves the user, records CREATED and sends a setup code', async () => {
      const { service, db, codes } = arrange();

      const result = await service.createUser(dto, actor);

      expect(result).toMatchObject({ id: USER_ID, setupEmailSent: true });
      expect(codes.issue).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: USER_ID,
          purpose: VerificationPurpose.PASSWORD_SETUP,
          mail: expect.objectContaining({ to: 'pedro@welinc.com' }),
        }),
      );
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          type: AccountEventType.CREATED,
          field: null,
        }),
        // Spec 0011, AC-6: one ROLE_CHANGED per system granted
        expect.objectContaining({
          type: AccountEventType.ROLE_CHANGED,
          system: SystemType.VRMS,
          oldValue: null,
          newValue: 'MECHANIC@VRMS',
        }),
      ]);
    });

    // Suite AC-15: nobody knows the password; both flags start false
    it('starts with passwordSet and emailVerified false', async () => {
      const { service, db } = arrange();

      await service.createUser(dto, actor);

      expect(db.user.create.mock.calls[0][0].data).toMatchObject({
        passwordSet: false,
        emailVerified: false,
      });
    });

    it('trims the name and lowercases the email before saving', async () => {
      const { service, db } = arrange();

      await service.createUser(dto, actor);

      expect(db.user.create).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            name: 'Pedro',
            email: 'pedro@welinc.com',
          }),
        }),
      );
    });

    // covers: VRMS AC-18
    it('still answers with the saved user, setupEmailSent false, when the mail fails', async () => {
      const { service, sendMail } = arrange();
      sendMail.mockRejectedValue(new Error('SMTP down'));

      const result = await service.createUser(dto, actor);

      expect(result).toMatchObject({ id: USER_ID, setupEmailSent: false });
    });

    // Suite AC-5: a send the limits refuse is not an error here
    it('answers setupEmailSent false when the send limits refuse it', async () => {
      const { service, codes } = arrange();
      codes.issue.mockResolvedValue({ kind: 'limited', retryAfter: 30 });

      const result = await service.createUser(dto, actor);

      expect(result).toMatchObject({ setupEmailSent: false });
    });

    it('creates an inactive user with a setup code too', async () => {
      const { service, codes } = arrange();

      await service.createUser({ ...dto, isActive: false }, actor);

      expect(codes.issue).toHaveBeenCalledTimes(1);
    });

    it('answers 409 when the email already exists', async () => {
      const { service, db } = arrange();
      db.user.create.mockRejectedValue({ code: 'P2002' });

      await expect(service.createUser(dto, actor)).rejects.toThrow(
        new ConflictException('Email already exists'),
      );
    });

    it('rejects a duplicate role assignment before touching the database', async () => {
      const { service, db } = arrange();
      const role = { role: 'MECHANIC', system: SystemType.VRMS };

      await expect(
        service.createUser({ ...dto, roleAssignments: [role, role] }, actor),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(db.user.create).not.toHaveBeenCalled();
    });
  });
});

describe('AuthService password links and reset', () => {
  // covers: AC-16
  describe('PORTAL_URL', () => {
    const user = {
      id: USER_ID,
      name: 'Pedro',
      email: 'pedro@welinc.com',
      passwordSet: true,
      isActive: true,
      deletedAt: null,
      roles: [{ system: SystemType.VRMS }],
    };

    async function mailedText(env: Record<string, string | undefined>) {
      const { service, db, sendMail } = build(env);
      db.user.findUnique.mockResolvedValue(user);
      await service.forgotPassword('pedro@welinc.com');
      return sendMail.mock.calls[0][0].text as string;
    }

    it('links the reset email to the configured portal', async () => {
      const text = await mailedText({
        PORTAL_URL: 'https://portal.welinc.com',
      });

      expect(text).toContain('https://portal.welinc.com/forgot-password');
    });

    it('ignores trailing slashes on the portal address', async () => {
      const text = await mailedText({
        PORTAL_URL: 'https://portal.welinc.com//',
      });

      expect(text).toContain('https://portal.welinc.com/forgot-password');
      expect(text).not.toContain('com//forgot');
    });

    // PORTAL_URL being required (no localhost fallback) is the boot check's job: env.spec.ts
  });

  // Suite spec 0009, AC-13
  describe('forgotPassword', () => {
    const MESSAGE = 'If that email is registered, an OTP has been sent.';
    const target = (overrides: Record<string, unknown> = {}) => ({
      id: USER_ID,
      name: 'Pedro',
      email: 'pedro@welinc.com',
      passwordSet: true,
      isActive: true,
      deletedAt: null,
      roles: [{ system: SystemType.VRMS }],
      ...overrides,
    });
    const vrmsAdmin = {
      sub: ADMIN_ID,
      email: 'admin@welinc.com',
      sid: 'sid-admin',
      roles: [{ role: 'ADMIN', system: SystemType.VRMS }],
    };

    it.each([
      ['an unknown email', null],
      ['an inactive user', target({ isActive: false })],
      ['a deleted user', target({ deletedAt: NOW })],
    ])(
      'sends nothing and gives the same generic answer for %s',
      async (_l, row) => {
        const { service, db, codes } = build();
        db.user.findUnique.mockResolvedValue(row);

        const result = await service.forgotPassword('pedro@welinc.com');

        expect(result).toEqual({ message: MESSAGE });
        expect(codes.issue).not.toHaveBeenCalled();
      },
    );

    it('looks the address up lowercased', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(null);

      await service.forgotPassword(' Pedro@WeLinc.com ');

      expect(db.user.findUnique.mock.calls[0][0].where).toEqual({
        email: 'pedro@welinc.com',
      });
    });

    it('answers an active user with the very same message and a reset code', async () => {
      const { service, db, codes } = build();
      db.user.findUnique.mockResolvedValue(target());

      const result = await service.forgotPassword('pedro@welinc.com');

      expect(result).toEqual({ message: MESSAGE });
      expect(codes.issue).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: USER_ID,
          purpose: VerificationPurpose.PASSWORD_RESET,
        }),
      );
    });

    it('sends a setup code, with setup wording, while setup is pending', async () => {
      const { service, db, codes, sendMail } = build();
      db.user.findUnique.mockResolvedValue(target({ passwordSet: false }));

      await service.forgotPassword('pedro@welinc.com');

      expect(codes.issue.mock.calls[0][0]).toMatchObject({
        purpose: VerificationPurpose.PASSWORD_SETUP,
      });
      expect(sendMail.mock.calls[0][0].subject).toContain('Account Setup');
      expect(sendMail.mock.calls[0][0].text).toContain('1 hour');
    });

    // Spec 0011, AC-5: CODE_SENT (once RESET_SENT) is written by the code service, after the
    // mail, with the admin as actor
    it("sends the code as the admin of the user's system", async () => {
      const { service, db, codes } = build();
      db.user.findUnique.mockResolvedValue(target());

      await service.forgotPassword('pedro@welinc.com', vrmsAdmin);

      expect(codes.issue.mock.calls[0][0]).toMatchObject({
        userId: USER_ID,
        actorId: ADMIN_ID,
      });
      expect(changesWritten(db)).toEqual([]);
    });

    it.each([
      ['no token was sent (the portal)', null],
      [
        'the caller is only a mechanic',
        {
          ...vrmsAdmin,
          roles: [{ role: 'MECHANIC', system: SystemType.VRMS }],
        },
      ],
      [
        'the caller is an admin of a different system',
        {
          ...vrmsAdmin,
          roles: [{ role: 'ADMIN', system: SystemType.BMS }],
        },
      ],
    ])('records nothing when %s', async (_l, caller) => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(target());

      await service.forgotPassword('pedro@welinc.com', caller);

      expect(changesWritten(db)).toEqual([]);
    });

    it('gives the public the generic answer inside the wait', async () => {
      const { service, db, codes } = build();
      db.user.findUnique.mockResolvedValue(target());
      codes.issue.mockResolvedValue({ kind: 'limited', retryAfter: 42 });

      await expect(service.forgotPassword('pedro@welinc.com')).resolves.toEqual(
        { message: MESSAGE },
      );
    });

    it('answers an admin CODE_SEND_LIMIT inside the wait, and records nothing', async () => {
      const { service, db, codes } = build();
      db.user.findUnique.mockResolvedValue(target());
      codes.issue.mockResolvedValue({ kind: 'limited', retryAfter: 42 });

      await expect(
        service.forgotPassword('pedro@welinc.com', vrmsAdmin),
      ).rejects.toEqual(new CodeSendLimitError(42));
      expect(changesWritten(db)).toEqual([]);
    });

    it('does not fail a public request when the mail cannot be sent', async () => {
      const { service, db, sendMail } = build();
      db.user.findUnique.mockResolvedValue(target());
      sendMail.mockRejectedValue(new Error('SMTP down'));

      await expect(service.forgotPassword('pedro@welinc.com')).resolves.toEqual(
        { message: MESSAGE },
      );
    });

    it('tells an admin the mail failed, and records nothing', async () => {
      const { service, db, sendMail } = build();
      db.user.findUnique.mockResolvedValue(target());
      sendMail.mockRejectedValue(new Error('SMTP down'));

      await expect(
        service.forgotPassword('pedro@welinc.com', vrmsAdmin),
      ).rejects.toBeInstanceOf(MailFailedError);
      expect(changesWritten(db)).toEqual([]);
    });
  });

  // Suite spec 0009, AC-12, AC-14
  describe('verifyOtp and otpResetPassword', () => {
    it('checks the live setup or reset code without using it up', async () => {
      const { service, db, codes } = build();
      db.user.findFirst.mockResolvedValue({ id: USER_ID });

      await expect(
        service.verifyOtp('pedro@welinc.com', '123456'),
      ).resolves.toEqual({ message: 'OTP is valid' });
      expect(codes.check).toHaveBeenCalledWith(
        expect.objectContaining({
          target: {
            userId: USER_ID,
            purposes: [
              VerificationPurpose.PASSWORD_SETUP,
              VerificationPurpose.PASSWORD_RESET,
            ],
          },
          code: '123456',
          consume: false,
        }),
      );
    });

    it('acts only on an active, not deleted user', async () => {
      const { service, db, codes } = build();
      db.user.findFirst.mockResolvedValue(null);

      await expect(
        service.verifyOtp('pedro@welinc.com', '123456'),
      ).rejects.toThrow('Invalid or expired OTP');
      expect(db.user.findFirst.mock.calls[0][0].where).toEqual({
        email: 'pedro@welinc.com',
        isActive: true,
        deletedAt: null,
      });
      expect(codes.check).not.toHaveBeenCalled();
    });

    it.each([
      ['a wrong code', { kind: 'wrong', attemptsLeft: 3 }],
      ['a dead code', { kind: 'dead', reason: 'tries' }],
    ])('keeps the old message for %s', async (_l, answer) => {
      const { service, db, codes } = build();
      db.user.findFirst.mockResolvedValue({ id: USER_ID });
      codes.check.mockResolvedValue(answer);

      await expect(
        service.otpResetPassword('pedro@welinc.com', '000000', 'N3w-password!'),
      ).rejects.toThrow('Invalid or expired OTP');
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('sets the password, confirms the email, marks it set, unlocks and ends every session', async () => {
      const { service, db, codes, endAllForUser } = build();
      db.user.findFirst.mockResolvedValue({ id: USER_ID });

      await service.otpResetPassword(
        'pedro@welinc.com',
        '123456',
        'N3w-password-here!',
      );

      expect(codes.check.mock.calls[0][0]).toMatchObject({ consume: true });
      expect(db.user.update).toHaveBeenCalledWith({
        where: { id: USER_ID },
        data: expect.objectContaining({
          lockedAt: null,
          failedLoginAttempts: 0,
          emailVerified: true,
          passwordSet: true,
          passwordHash: expect.stringMatching(/^\$argon2/),
        }),
      });
      expect(endAllForUser).toHaveBeenCalledWith(
        expect.anything(),
        USER_ID,
        'PASSWORD_CHANGED',
        { ip: null },
      );
      // Spec 0011, AC-6
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          actorId: USER_ID,
          type: AccountEventType.PASSWORD_CHANGED,
        }),
      ]);
    });
  });
});

beforeEach(() => {
  jest.useRealTimers();
});
