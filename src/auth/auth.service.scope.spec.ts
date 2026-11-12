/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return -- the faked database is untyped on purpose */
import { describe, it, expect, jest } from '@jest/globals';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpStatus,
  NotFoundException,
} from '@nestjs/common';
import { fakeConfig } from '../config/fake-config.setup';
import type { TokenService } from './tokens/token.service';
import { SystemType, AccountEventType } from '@prisma/client';
import { FakeCatalogService } from './testing/catalog.fake';
import { fakeCodes } from './testing/codes.fake';
import type { RoleCode } from './roles/catalog.types';
import type { MailService } from '../shared/mail.service';
import type { PrismaService } from '../shared/prisma.service';
import { AuthService } from './auth.service';
import { AccountEventsService } from './events/account-events.service';
import { PasswordCheckService } from './reauth/password-check.service';
import { noGeo } from './testing/geo.fake';
import { SessionService } from './sessions/session.service';

// Spec 0011, AC-26 to AC-30: welinc-auth's admin user endpoints act only inside the
// caller's system. The database and the mail server are the only things faked.

const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
const USER_ID = '22222222-2222-4222-8222-222222222222';
const vrmsAdmin = {
  id: ADMIN_ID,
  email: 'admin@welinc.com',
  system: SystemType.VRMS,
};

const role = (r: RoleCode, system: SystemType) => ({ role: r, system });
const VRMS_MECHANIC = role('MECHANIC', SystemType.VRMS);
const BMS_ADMIN = role('ADMIN', SystemType.BMS);
const BMS_OPERATIONS = role('OPERATIONS', SystemType.BMS);
const VMMS_ADMIN = role('ADMIN', SystemType.VMMS);

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const NOW = new Date('2026-10-29T08:00:00.000Z');

function managedRow(roles = [VRMS_MECHANIC]) {
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
    roles,
  };
}

function build() {
  const db = {
    user: {
      findFirst: fn(),
      findUnique: fn(),
      findUniqueOrThrow: fn(),
      findMany: fn(),
      update: fn(),
      create: fn(),
      count: fn(),
    },
    userRoleAssignment: { createMany: fn() },
    accountEvent: { create: fn(), createMany: fn(), findMany: fn() },
    passwordResetToken: { create: fn() },
    $queryRaw: fn(),
    $transaction: fn(),
  };
  db.$transaction.mockImplementation((arg: unknown) =>
    (arg as (tx: typeof db) => unknown)(db),
  );
  db.$queryRaw.mockResolvedValue([]);
  db.user.count.mockResolvedValue(1);
  db.accountEvent.findMany.mockResolvedValue([]);
  const sendMail = fn();
  sendMail.mockResolvedValue(undefined);
  const sessions = {
    endAllForUser: jest.fn(() => Promise.resolve(0)),
  } as unknown as SessionService;
  const service = new AuthService(
    db as unknown as PrismaService,
    {} as TokenService,
    { sendMail } as unknown as MailService,
    fakeConfig(),
    sessions,
    new FakeCatalogService(),
    fakeCodes(),
    new AccountEventsService(db as unknown as PrismaService, noGeo),
    new PasswordCheckService(
      db as unknown as PrismaService,
      new AccountEventsService(db as unknown as PrismaService, noGeo),
    ),
  );
  return { service, db };
}

function changesWritten(db: ReturnType<typeof build>['db']) {
  return [
    ...db.accountEvent.create.mock.calls.map((c) => c[0].data),
    ...db.accountEvent.createMany.mock.calls.flatMap((c) => c[0].data),
  ];
}

describe('welinc-auth system scoping', () => {
  describe('listUsers', () => {
    // covers: AC-26
    it("asks only for users with a role in the caller's system, whatever the query says", async () => {
      const { service, db } = build();
      db.user.findMany.mockResolvedValue([]);

      await service.listUsers({ system: SystemType.BMS }, vrmsAdmin);

      expect(db.user.findMany.mock.calls[0][0].where).toEqual({
        deletedAt: null,
        roles: { some: { system: SystemType.VRMS } },
      });
    });

    it('returns only VRMS roles plus the other systems by name', async () => {
      const { service, db } = build();
      db.user.findMany.mockResolvedValue([
        {
          ...managedRow([VRMS_MECHANIC, BMS_OPERATIONS, BMS_ADMIN, VMMS_ADMIN]),
          deletionRequests: [{ id: 'request-1' }],
        },
        { ...managedRow([VRMS_MECHANIC]), deletionRequests: [] },
      ]);

      const [shared, own] = await service.listUsers({}, vrmsAdmin);

      // Spec 0012, AC-9: an EXISTS on a pending request, never the request itself
      expect(shared.pendingDeletion).toBe(true);
      expect(own.pendingDeletion).toBe(false);
      expect(shared).not.toHaveProperty('deletionRequests');

      expect(shared.roles).toEqual([VRMS_MECHANIC]);
      expect(shared.otherSystems).toEqual([SystemType.BMS, SystemType.VMMS]);
      expect(own.otherSystems).toEqual([]);
    });
  });

  // covers: AC-26
  describe('users outside the system answer 404', () => {
    const bmsOnly = { ...managedRow([BMS_ADMIN]), deletedAt: null };

    it('on edit, status, unlock, delete and set password', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue(bmsOnly);
      db.user.findFirst.mockResolvedValue(bmsOnly);

      for (const call of [
        () => service.updateUser(USER_ID, { name: 'X' }, vrmsAdmin),
        () => service.updateUserStatus(USER_ID, { isActive: false }, vrmsAdmin),
        () => service.unlockUser(USER_ID, vrmsAdmin),
        () => service.deleteUser(USER_ID, vrmsAdmin),
      ]) {
        await expect(call()).rejects.toBeInstanceOf(NotFoundException);
      }
      expect(db.user.update).not.toHaveBeenCalled();
      expect(changesWritten(db)).toEqual([]);
    });
  });

  describe('updateUser roles', () => {
    function arrange(roles: ReturnType<typeof role>[]) {
      const ctx = build();
      ctx.db.user.findUnique.mockResolvedValue({
        id: USER_ID,
        name: 'Pedro',
        email: 'pedro@welinc.com',
        isActive: true,
        deletedAt: null,
        roles,
      });
      ctx.db.user.update.mockResolvedValue(managedRow(roles));
      return ctx;
    }

    // covers: AC-27
    it("answers 403 when the edit sends another system's role, before any write", async () => {
      const { service, db } = arrange([VRMS_MECHANIC]);

      await expect(
        service.updateUser(
          USER_ID,
          { roleAssignments: [BMS_OPERATIONS] },
          vrmsAdmin,
        ),
      ).rejects.toThrow(
        new ForbiddenException('You can only change VRMS roles.'),
      );
      expect(db.$transaction).not.toHaveBeenCalled();
    });

    it("replaces the VRMS roles and keeps every other system's role", async () => {
      const { service, db } = arrange([VRMS_MECHANIC, BMS_OPERATIONS]);
      const chief = role('CHIEF_MECHANIC', SystemType.VRMS);

      await service.updateUser(
        USER_ID,
        { roleAssignments: [chief] },
        vrmsAdmin,
      );

      expect(db.user.update.mock.calls[0][0].data.roles.create).toEqual([
        BMS_OPERATIONS,
        chief,
      ]);
    });

    // covers: AC-28
    it('removes a shared account from VRMS with an empty role list', async () => {
      const { service, db } = arrange([VRMS_MECHANIC, BMS_OPERATIONS]);

      const result = await service.updateUser(
        USER_ID,
        { roleAssignments: [] },
        vrmsAdmin,
      );

      expect(db.user.update.mock.calls[0][0].data.roles.create).toEqual([
        BMS_OPERATIONS,
      ]);
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          type: AccountEventType.ROLE_CHANGED,
          system: SystemType.VRMS,
          oldValue: 'MECHANIC@VRMS',
          newValue: null,
        }),
      ]);
      expect(result).toBeDefined();
    });

    it('answers 400 for an empty role list on a VRMS only account', async () => {
      const { service, db } = arrange([VRMS_MECHANIC]);

      await expect(
        service.updateUser(USER_ID, { roleAssignments: [] }, vrmsAdmin),
      ).rejects.toBeInstanceOf(BadRequestException);
      expect(db.user.update).not.toHaveBeenCalled();
    });
  });

  // covers: AC-28
  describe('accounts that are an admin in another system', () => {
    const blocked =
      'This account is an admin in BMS, VMMS. Send a reset code instead.';

    function arrange() {
      const roles = [VRMS_MECHANIC, VMMS_ADMIN, BMS_ADMIN];
      const ctx = build();
      const row = {
        id: USER_ID,
        name: 'Pedro',
        email: 'pedro@welinc.com',
        isActive: true,
        deletedAt: null,
        roles,
      };
      ctx.db.user.findUnique.mockResolvedValue(row);
      // The "is this address free" lookup (suite spec 0009, AC-21) finds nobody else
      ctx.db.user.findFirst.mockImplementation((args: { where?: object }) =>
        Promise.resolve(args.where && 'email' in args.where ? null : row),
      );
      ctx.db.user.update.mockResolvedValue(managedRow(roles));
      return ctx;
    }

    it('blocks a new email', async () => {
      const { service, db } = arrange();

      await expect(
        service.updateUser(USER_ID, { email: 'new@welinc.com' }, vrmsAdmin),
      ).rejects.toThrow(new ForbiddenException(blocked));
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('still allows a name change and the same email', async () => {
      const { service, db } = arrange();

      await service.updateUser(
        USER_ID,
        { name: 'Pedro Cruz', email: 'PEDRO@welinc.com' },
        vrmsAdmin,
      );

      expect(db.user.update.mock.calls[0][0].data).toEqual({
        name: 'Pedro Cruz',
      });
    });
  });

  describe('deleteUser', () => {
    // covers: AC-28
    it('answers 403 for a shared account and deletes nothing', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [VRMS_MECHANIC, BMS_OPERATIONS],
      });

      await expect(service.deleteUser(USER_ID, vrmsAdmin)).rejects.toThrow(
        new ForbiddenException(
          'This account is shared with BMS. Remove its VRMS role instead.',
        ),
      );
      expect(db.user.update).not.toHaveBeenCalled();
    });
  });

  describe('updateUserStatus', () => {
    // covers: AC-28
    it('lets a VRMS admin deactivate a shared account', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [VRMS_MECHANIC, BMS_OPERATIONS],
      });
      db.user.update.mockResolvedValue(
        managedRow([VRMS_MECHANIC, BMS_OPERATIONS]),
      );

      const result = await service.updateUserStatus(
        USER_ID,
        { isActive: false },
        vrmsAdmin,
      );

      expect(db.user.update).toHaveBeenCalled();
      expect(result.otherSystems).toEqual([SystemType.BMS]);
    });
  });

  describe('lookupUsers', () => {
    // covers: AC-29
    it('searches active accounts outside VRMS by name or email, at most 10', async () => {
      const { service, db } = build();
      db.user.findMany.mockResolvedValue([
        {
          id: USER_ID,
          name: 'Pedro',
          email: 'pedro@welinc.com',
          roles: [{ system: SystemType.BMS }, { system: SystemType.BMS }],
        },
      ]);

      const result = await service.lookupUsers('ped', vrmsAdmin);

      const args = db.user.findMany.mock.calls[0][0];
      expect(args.where).toEqual({
        isActive: true,
        deletedAt: null,
        roles: { none: { system: SystemType.VRMS } },
        OR: [
          { name: { contains: 'ped', mode: 'insensitive' } },
          { email: { contains: 'ped', mode: 'insensitive' } },
        ],
      });
      expect(args.take).toBe(10);
      expect(result).toEqual([
        {
          id: USER_ID,
          name: 'Pedro',
          email: 'pedro@welinc.com',
          systems: [SystemType.BMS],
        },
      ]);
    });

    it('answers 429 on the 31st search in a minute', async () => {
      const { service, db } = build();
      db.user.findMany.mockResolvedValue([]);

      for (let i = 0; i < 30; i++) {
        await service.lookupUsers('ped', vrmsAdmin);
      }

      await expect(service.lookupUsers('ped', vrmsAdmin)).rejects.toMatchObject(
        { status: HttpStatus.TOO_MANY_REQUESTS },
      );
      expect(db.user.findMany).toHaveBeenCalledTimes(30);
    });
  });

  describe('createUser', () => {
    const dto = {
      name: 'Pedro',
      email: 'Pedro@welinc.com',
      roleAssignments: [VRMS_MECHANIC],
    };
    const account = (overrides: Record<string, unknown> = {}) => ({
      id: USER_ID,
      name: 'Pedro',
      isActive: true,
      deletedAt: null,
      roles: [BMS_OPERATIONS],
      ...overrides,
    });

    // covers: AC-27
    it("answers 403 for another system's role", async () => {
      const { service, db } = build();

      await expect(
        service.createUser({ ...dto, roleAssignments: [BMS_ADMIN] }, vrmsAdmin),
      ).rejects.toBeInstanceOf(ForbiddenException);
      expect(db.user.findFirst).not.toHaveBeenCalled();
    });

    // covers: AC-30
    it('answers ACCOUNT_EXISTS for an active account outside VRMS', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue(account());

      const error = await service
        .createUser(dto, vrmsAdmin)
        .catch((e: unknown) => e);

      expect(error).toBeInstanceOf(ConflictException);
      expect((error as ConflictException).getResponse()).toMatchObject({
        code: 'ACCOUNT_EXISTS',
        id: USER_ID,
        name: 'Pedro',
        systems: [SystemType.BMS],
      });
      expect(db.user.create).not.toHaveBeenCalled();
    });

    it('attaches only the VRMS roles with attachExisting and writes ROLE_CHANGED', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue(account());
      db.user.findUnique.mockResolvedValue(account());
      db.user.findUniqueOrThrow.mockResolvedValue(
        managedRow([BMS_OPERATIONS, VRMS_MECHANIC]),
      );

      const result = await service.createUser(
        { ...dto, attachExisting: true },
        vrmsAdmin,
      );

      expect(db.userRoleAssignment.createMany).toHaveBeenCalledWith({
        data: [{ userId: USER_ID, ...VRMS_MECHANIC }],
      });
      expect(db.user.create).not.toHaveBeenCalled();
      expect(db.user.update).not.toHaveBeenCalled();
      expect(changesWritten(db)).toEqual([
        expect.objectContaining({
          userId: USER_ID,
          type: AccountEventType.ROLE_CHANGED,
          system: SystemType.VRMS,
          oldValue: null,
          newValue: 'MECHANIC@VRMS',
        }),
      ]);
      expect(result).toMatchObject({
        roles: [VRMS_MECHANIC],
        otherSystems: [SystemType.BMS],
        setupEmailSent: false,
      });
    });

    it.each([
      ['deactivated', { isActive: false }],
      ['deleted', { deletedAt: NOW }],
      ['already in VRMS', { roles: [VRMS_MECHANIC] }],
    ])('answers the plain 409 for a %s account', async (_label, overrides) => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue(account(overrides));

      await expect(
        service.createUser({ ...dto, attachExisting: true }, vrmsAdmin),
      ).rejects.toThrow(new ConflictException('Email already exists'));
      expect(db.userRoleAssignment.createMany).not.toHaveBeenCalled();
    });

    it('answers the plain 409 when the account changes before the attach commits', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue(account());
      db.user.findUnique.mockResolvedValue(account({ isActive: false }));

      await expect(
        service.createUser({ ...dto, attachExisting: true }, vrmsAdmin),
      ).rejects.toThrow(new ConflictException('Email already exists'));
      expect(db.userRoleAssignment.createMany).not.toHaveBeenCalled();
    });
  });
});
