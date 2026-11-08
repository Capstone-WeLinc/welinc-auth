/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-argument -- the faked database is untyped on purpose */
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
import type { ConfigService } from '@nestjs/config';
import type { TokenService } from './tokens/token.service';
import { SystemType, UserChangeAction, UserRole } from '@prisma/client';
import type { MailService } from '../shared/mail.service';
import type { PrismaService } from '../shared/prisma.service';
import { AuthService } from './auth.service';
import { SessionService } from './sessions/session.service';
import { encodeChangeCursor } from './user-changes';

// Spec 0009: admin safety guards (AC-19), the change record (AC-20, AC-21),
// reset and setup hardening (AC-16, AC-17, AC-18). The database, the mail
// server and the config are the only things faked.

const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
const USER_ID = '22222222-2222-4222-8222-222222222222';
const actor = {
  id: ADMIN_ID,
  email: 'admin@welinc.com',
  system: SystemType.VRMS,
};

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const NOW = new Date('2026-10-27T08:00:00.000Z');
const VRMS_MECHANIC = [{ role: UserRole.MECHANIC, system: SystemType.VRMS }];

function managedRow(overrides: Record<string, unknown> = {}) {
  return {
    id: USER_ID,
    name: 'Pedro',
    email: 'pedro@welinc.com',
    emailVerified: true,
    contact: null,
    profilePicture: null,
    isActive: true,
    lockedAt: null,
    createdAt: NOW,
    updatedAt: NOW,
    roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
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
    userChange: { create: fn(), createMany: fn(), findMany: fn() },
    passwordResetToken: {
      create: fn(),
      updateMany: fn(),
      findFirst: fn(),
      update: fn(),
    },
    $queryRaw: fn(),
    $transaction: fn(),
  };
  db.$transaction.mockImplementation((arg: unknown) =>
    typeof arg === 'function'
      ? (arg as (tx: typeof db) => unknown)(db)
      : Promise.all(arg as Promise<unknown>[]),
  );
  db.$queryRaw.mockResolvedValue([]);
  db.user.count.mockResolvedValue(1);
  const sendMail = fn();
  sendMail.mockResolvedValue(undefined);
  const config = {
    get: (key: string) => env[key],
  } as unknown as ConfigService;
  const sessions = {
    endAllForUser: jest.fn(() => Promise.resolve(0)),
  } as unknown as SessionService;
  const service = new AuthService(
    db as unknown as PrismaService,
    {} as TokenService,
    { sendMail } as unknown as MailService,
    config,
    sessions,
  );
  return { service, db, sendMail, sessions };
}

/** The UserChange rows written, from either create or createMany. */
function changesWritten(db: ReturnType<typeof build>['db']) {
  return [
    ...db.userChange.create.mock.calls.map((c) => c[0].data),
    ...db.userChange.createMany.mock.calls.flatMap((c) => c[0].data),
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
        roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
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
        roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
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
        roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
      });
      db.user.update.mockResolvedValue(managedRow({ isActive: false }));

      await service.updateUserStatus(USER_ID, { isActive: false }, actor);

      expect(db.$transaction).toHaveBeenCalledTimes(1);
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          actorId: ADMIN_ID,
          actorEmail: 'admin@welinc.com',
          action: UserChangeAction.DEACTIVATED,
          field: null,
        }),
      ]);
    });

    it('records ACTIVATED when a user is switched back on, without an admin guard', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: false,
        roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
      });
      db.user.update.mockResolvedValue(managedRow());

      await service.updateUserStatus(USER_ID, { isActive: true }, actor);

      expect(db.$queryRaw).not.toHaveBeenCalled();
      expect(changesWritten(db)[0]).toMatchObject({
        action: UserChangeAction.ACTIVATED,
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
        roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
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
        roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
      });

      await expect(service.deleteUser(USER_ID, actor)).resolves.toEqual({
        id: USER_ID,
      });
      expect(db.$queryRaw).not.toHaveBeenCalled();
    });

    // covers: AC-20
    it('soft deletes the user and records DELETED', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
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
          action: UserChangeAction.DELETED,
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
        action: UserChangeAction.UNLOCKED,
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
      isActive: true,
      deletedAt: null,
      roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
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
          roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
        }),
      );

      await expect(
        service.updateUser(
          ADMIN_ID,
          {
            roleAssignments: [
              { role: UserRole.MECHANIC, system: SystemType.VRMS },
            ],
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
          roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
        }),
      );
      db.user.count.mockResolvedValue(0);

      await expect(
        service.updateUser(
          USER_ID,
          {
            roleAssignments: [
              { role: UserRole.MECHANIC, system: SystemType.VRMS },
            ],
          },
          actor,
        ),
      ).rejects.toThrow('This is the last VRMS admin.');
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('refuses to deactivate the last admin through an edit', async () => {
      const { service, db } = arrange(
        existing({
          roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
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
          roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
        }),
      );

      await service.updateUser(USER_ID, { name: 'Renamed' }, actor);

      expect(db.$queryRaw).not.toHaveBeenCalled();
    });

    // Follow up from the review: decisions come from a read inside the transaction
    it('decides from the read inside the transaction, not the one before it', async () => {
      const { service, db } = arrange(
        existing({
          roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
        }),
      );
      // Between the two reads, another admin made this user the last VRMS admin
      db.user.findUnique
        .mockResolvedValueOnce(
          existing({
            roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
          }),
        )
        .mockResolvedValueOnce(
          existing({
            roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
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
            { role: UserRole.ADMIN, system: SystemType.VRMS },
            { role: UserRole.ADMIN, system: SystemType.BMS },
          ],
        }),
      );

      await service.updateUser(USER_ID, { isActive: false }, actor);

      const locked = db.$queryRaw.mock.calls.map((call) => call[1]);
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
          action: UserChangeAction.UPDATED,
          field: 'name',
          oldValue: 'Pedro',
          newValue: 'Pedro Cruz',
        }),
        expect.objectContaining({
          action: UserChangeAction.UPDATED,
          field: 'email',
          oldValue: 'pedro@welinc.com',
          newValue: 'pedro.cruz@welinc.com',
        }),
      ]);
    });

    it('writes ROLE_CHANGED with sorted ROLE@SYSTEM lists', async () => {
      const { service, db } = arrange();

      await service.updateUser(
        USER_ID,
        {
          roleAssignments: [
            { role: UserRole.MECHANIC, system: SystemType.VRMS },
            { role: UserRole.ADMIN, system: SystemType.VRMS },
          ],
        },
        actor,
      );

      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          action: UserChangeAction.ROLE_CHANGED,
          field: 'roles',
          oldValue: 'MECHANIC@VRMS',
          newValue: 'ADMIN@VRMS,MECHANIC@VRMS',
        }),
      ]);
    });

    it('writes DEACTIVATED when an edit switches the user off', async () => {
      const { service, db } = arrange();

      await service.updateUser(USER_ID, { isActive: false }, actor);

      expect(changesWritten(db)).toEqual([
        expect.objectContaining({ action: UserChangeAction.DEACTIVATED }),
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
          roleAssignments: [
            { role: UserRole.MECHANIC, system: SystemType.VRMS },
          ],
        },
        actor,
      );

      expect(db.userChange.createMany).not.toHaveBeenCalled();
      expect(db.userChange.create).not.toHaveBeenCalled();
    });

    // covers: AC-20 (no password, hash or code is ever stored)
    it('never copies a new password or its hash into a change row', async () => {
      const { service, db } = arrange();

      await service.updateUser(
        USER_ID,
        { name: 'Renamed', password: 'Sup3r-secret-pw!' },
        actor,
      );

      const stored = JSON.stringify(changesWritten(db));
      expect(stored).not.toContain('Sup3r-secret-pw!');
      expect(stored).not.toMatch(/argon2/i);
      expect(stored.toLowerCase()).not.toContain('password');
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
      roleAssignments: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
    };

    function arrange(env: Record<string, string | undefined> = {}) {
      const ctx = build(env);
      ctx.db.user.create.mockResolvedValue(managedRow());
      return ctx;
    }

    afterEach(() => jest.restoreAllMocks());

    // covers: AC-18, AC-20
    it('saves the user, records CREATED and reports the setup email as sent', async () => {
      const { service, db, sendMail } = arrange();

      const result = await service.createUser(dto, actor);

      expect(result).toMatchObject({ id: USER_ID, setupEmailSent: true });
      expect(sendMail).toHaveBeenCalledTimes(1);
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          action: UserChangeAction.CREATED,
          field: null,
        }),
      ]);
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

    // covers: AC-18
    it('still answers with the saved user, setupEmailSent false, when the mail fails', async () => {
      const { service, sendMail } = arrange();
      sendMail.mockRejectedValue(new Error('SMTP down'));
      jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});

      const result = await service.createUser(dto, actor);

      expect(result).toMatchObject({ id: USER_ID, setupEmailSent: false });
    });

    // covers: AC-16, AC-18
    it('logs a mail failure without the setup code', async () => {
      const { service, sendMail } = arrange();
      sendMail.mockRejectedValue(new Error('SMTP down'));
      const logged = jest
        .spyOn(Logger.prototype, 'error')
        .mockImplementation(() => {});

      await service.createUser(dto, actor);

      const mailed = sendMail.mock.calls[0][0].text as string;
      const code = /Setup Code: (\d{6})/.exec(mailed)![1];
      expect(logged).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(logged.mock.calls)).not.toContain(code);
    });

    it('does not report a sent email when an admin set the password directly', async () => {
      const { service, sendMail } = arrange();

      const result = await service.createUser(
        { ...dto, password: 'Str0ng-pass-phrase!' },
        actor,
      );

      expect(sendMail).not.toHaveBeenCalled();
      expect(result.setupEmailSent).toBe(false);
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
      const role = { role: UserRole.MECHANIC, system: SystemType.VRMS };

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

    it('falls back to localhost:8000 outside production', async () => {
      const text = await mailedText({});

      expect(text).toContain('http://localhost:8000/forgot-password');
    });

    it('refuses to start in production without PORTAL_URL', () => {
      expect(() => build({ NODE_ENV: 'production' })).toThrow(
        'PORTAL_URL is required in production',
      );
    });

    it('starts in production when PORTAL_URL is set', () => {
      expect(() =>
        build({
          NODE_ENV: 'production',
          PORTAL_URL: 'https://portal.welinc.com',
        }),
      ).not.toThrow();
    });
  });

  describe('forgotPassword', () => {
    const MESSAGE = 'If that email is registered, an OTP has been sent.';
    const target = (overrides: Record<string, unknown> = {}) => ({
      id: USER_ID,
      name: 'Pedro',
      email: 'pedro@welinc.com',
      isActive: true,
      deletedAt: null,
      roles: [{ system: SystemType.VRMS }],
      ...overrides,
    });
    const vrmsAdmin = {
      sub: ADMIN_ID,
      email: 'admin@welinc.com',
      roles: [{ role: UserRole.ADMIN, system: SystemType.VRMS }],
    };

    afterEach(() => jest.restoreAllMocks());

    // covers: AC-17
    it.each([
      ['an unknown email', null],
      ['an inactive user', target({ isActive: false })],
      ['a deleted user', target({ deletedAt: NOW })],
    ])(
      'sends nothing and gives the same generic answer for %s',
      async (_l, row) => {
        const { service, db, sendMail } = build();
        db.user.findUnique.mockResolvedValue(row);

        const result = await service.forgotPassword('pedro@welinc.com');

        expect(result).toEqual({ message: MESSAGE });
        expect(sendMail).not.toHaveBeenCalled();
        expect(db.passwordResetToken.create).not.toHaveBeenCalled();
      },
    );

    it('answers an active user with the very same message', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(target());

      const result = await service.forgotPassword('pedro@welinc.com');

      expect(result).toEqual({ message: MESSAGE });
    });

    // covers: AC-17
    it('retires the older unused codes before it issues the new one', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(target());
      const order: string[] = [];
      db.passwordResetToken.updateMany.mockImplementation(() => {
        order.push('retire');
        return Promise.resolve({ count: 1 });
      });
      db.passwordResetToken.create.mockImplementation(() => {
        order.push('create');
        return Promise.resolve({});
      });

      await service.forgotPassword('pedro@welinc.com');

      expect(db.passwordResetToken.updateMany).toHaveBeenCalledWith({
        where: { userId: USER_ID, usedAt: null },
        data: { usedAt: expect.any(Date) },
      });
      expect(order).toEqual(['retire', 'create']);
    });

    it('issues a six digit code that expires in about ten minutes', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(target());
      jest.useFakeTimers().setSystemTime(NOW);

      await service.forgotPassword('pedro@welinc.com');
      jest.useRealTimers();

      const { data } = db.passwordResetToken.create.mock.calls[0][0];
      expect(data.otp).toMatch(/^\d{6}$/);
      expect(data.expiresAt.getTime() - NOW.getTime()).toBe(10 * 60 * 1000);
    });

    // covers: AC-16
    it('never writes the code to the console or the logger', async () => {
      const { service, db, sendMail } = build();
      db.user.findUnique.mockResolvedValue(target());
      const log = jest.spyOn(console, 'log').mockImplementation(() => {});
      const info = jest.spyOn(console, 'info').mockImplementation(() => {});
      const loggerLog = jest
        .spyOn(Logger.prototype, 'log')
        .mockImplementation(() => {});

      await service.forgotPassword('pedro@welinc.com');

      const code = /Reset Code: (\d{6})/.exec(
        sendMail.mock.calls[0][0].text as string,
      )![1];
      const everything = JSON.stringify([
        log.mock.calls,
        info.mock.calls,
        loggerLog.mock.calls,
      ]);
      expect(everything).not.toContain(code);
    });

    // covers: AC-20
    it("records RESET_SENT when an admin of the user's system asked for it", async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(target());

      await service.forgotPassword('pedro@welinc.com', vrmsAdmin);

      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          actorId: ADMIN_ID,
          actorEmail: 'admin@welinc.com',
          action: UserChangeAction.RESET_SENT,
        }),
      ]);
    });

    it.each([
      ['no token was sent (the portal)', null],
      [
        'the caller is only a mechanic',
        {
          ...vrmsAdmin,
          roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
        },
      ],
      [
        'the caller is an admin of a different system',
        {
          ...vrmsAdmin,
          roles: [{ role: UserRole.ADMIN, system: SystemType.BMS }],
        },
      ],
    ])('records nothing when %s', async (_l, caller) => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(target());

      await service.forgotPassword('pedro@welinc.com', caller);

      expect(changesWritten(db)).toEqual([]);
    });

    it('does not fail the request when the mail cannot be sent', async () => {
      const { service, db, sendMail } = build();
      db.user.findUnique.mockResolvedValue(target());
      sendMail.mockRejectedValue(new Error('SMTP down'));
      jest.spyOn(Logger.prototype, 'error').mockImplementation(() => {});

      await expect(service.forgotPassword('pedro@welinc.com')).resolves.toEqual(
        { message: MESSAGE },
      );
    });
  });

  describe('otpResetPassword', () => {
    // covers: AC-17
    it('clears the lock and the failed attempts when the code is completed', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue({ id: USER_ID });
      db.passwordResetToken.findFirst.mockResolvedValue({
        id: 'token-1',
        otp: '123456',
      });

      await service.otpResetPassword(
        'pedro@welinc.com',
        '123456',
        'N3w-password-here!',
      );

      expect(db.user.update).toHaveBeenCalledWith({
        where: { id: USER_ID },
        data: expect.objectContaining({
          lockedAt: null,
          failedLoginAttempts: 0,
          emailVerified: true,
        }),
      });
      expect(db.passwordResetToken.update).toHaveBeenCalledWith({
        where: { id: 'token-1' },
        data: { usedAt: expect.any(Date) },
      });
    });

    it('rejects a wrong code and changes nothing', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue({ id: USER_ID });
      db.passwordResetToken.findFirst.mockResolvedValue({
        id: 'token-1',
        otp: '123456',
      });

      await expect(
        service.otpResetPassword('pedro@welinc.com', '000000', 'N3w-password!'),
      ).rejects.toThrow('Invalid or expired OTP');
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('only looks at unused, unexpired codes, newest first', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue({ id: USER_ID });
      db.passwordResetToken.findFirst.mockResolvedValue(null);

      await expect(
        service.otpResetPassword('pedro@welinc.com', '123456', 'N3w-password!'),
      ).rejects.toThrow('Invalid or expired OTP');
      expect(db.passwordResetToken.findFirst).toHaveBeenCalledWith({
        where: {
          userId: USER_ID,
          usedAt: null,
          expiresAt: { gt: expect.any(Date) },
        },
        orderBy: { createdAt: 'desc' },
      });
    });
  });
});

describe('AuthService.getUserChanges', () => {
  const row = (n: number) => ({
    id: `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`,
    action: UserChangeAction.UPDATED,
    field: 'name',
    oldValue: 'a',
    newValue: 'b',
    actorId: ADMIN_ID,
    actorEmail: 'admin@welinc.com',
    createdAt: new Date(NOW.getTime() - n * 1000),
  });

  function arrange(rows: ReturnType<typeof row>[] = []) {
    const ctx = build();
    ctx.db.user.findUnique.mockResolvedValue({
      id: USER_ID,
      roles: [{ role: UserRole.MECHANIC, system: SystemType.VRMS }],
    });
    ctx.db.userChange.findMany.mockResolvedValue(rows);
    return ctx;
  }

  // covers: AC-21
  it('answers 404 for an unknown user', async () => {
    const { service, db } = arrange();
    db.user.findUnique.mockResolvedValue(null);

    await expect(
      service.getUserChanges(USER_ID, {}, actor),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('returns rows with an ISO createdAt and no cursor when everything fits', async () => {
    const { service } = arrange([row(1), row(2)]);

    const result = await service.getUserChanges(USER_ID, {}, actor);

    expect(result.nextCursor).toBeNull();
    expect(result.data).toHaveLength(2);
    expect(result.data[0]).toEqual({
      ...row(1),
      createdAt: '2026-10-27T07:59:59.000Z',
    });
  });

  it('asks for newest first, one extra row, and a default page of 50', async () => {
    const { service, db } = arrange();

    await service.getUserChanges(USER_ID, {}, actor);

    expect(db.userChange.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
        take: 51,
        where: { userId: USER_ID },
      }),
    );
  });

  it('honours the limit and returns a cursor pointing at the last row on the page', async () => {
    const { service } = arrange([row(1), row(2), row(3)]);

    const result = await service.getUserChanges(USER_ID, { limit: 2 }, actor);

    expect(result.data.map((r) => r.id)).toEqual([row(1).id, row(2).id]);
    expect(result.nextCursor).toBe(
      encodeChangeCursor({ createdAt: row(2).createdAt, id: row(2).id }),
    );
  });

  it('pages on (createdAt, id) after the cursor', async () => {
    const { service, db } = arrange();
    const last = row(2);
    const cursor = encodeChangeCursor({
      createdAt: last.createdAt,
      id: last.id,
    });

    await service.getUserChanges(USER_ID, { cursor, limit: 2 }, actor);

    expect(db.userChange.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          userId: USER_ID,
          OR: [
            { createdAt: { lt: last.createdAt } },
            { createdAt: last.createdAt, id: { lt: last.id } },
          ],
        },
      }),
    );
  });

  it('answers 400 for a cursor that was tampered with', async () => {
    const { service, db } = arrange();

    await expect(
      service.getUserChanges(USER_ID, { cursor: 'garbage' }, actor),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(db.userChange.findMany).not.toHaveBeenCalled();
  });

  it('never selects anything beyond the documented fields', async () => {
    const { service, db } = arrange();

    await service.getUserChanges(USER_ID, {}, actor);

    const { select } = db.userChange.findMany.mock.calls[0][0];
    expect(Object.keys(select).sort()).toEqual(
      [
        'action',
        'actorEmail',
        'actorId',
        'createdAt',
        'field',
        'id',
        'newValue',
        'oldValue',
      ].sort(),
    );
  });
});

beforeEach(() => {
  jest.useRealTimers();
});
