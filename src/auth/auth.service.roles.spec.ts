import { describe, it, expect, jest } from '@jest/globals';
import {
  ConflictException,
  ForbiddenException,
  HttpException,
} from '@nestjs/common';
import { fakeConfig } from '../config/fake-config.setup';
import { SystemType } from '@prisma/client';
import { FakeCatalogService } from './testing/catalog.fake';
import { fakeCodes } from './testing/codes.fake';
import type { MailService } from '../shared/mail.service';
import type { PrismaService } from '../shared/prisma.service';
import type { SessionService } from './sessions/session.service';
import type { TokenService } from './tokens/token.service';
import { AuthService } from './auth.service';

// Spec 0004: the role rules user admin enforces (AC-9 to AC-13, AC-17). Only the database is
// faked; the catalog is the real files through FakeCatalogService.

const ADMIN_ID = '11111111-1111-4111-8111-111111111111';
const USER_ID = '22222222-2222-4222-8222-222222222222';
const vrmsAdmin = {
  id: ADMIN_ID,
  email: 'admin@welinc.com',
  system: SystemType.VRMS,
};
const NOW = new Date('2026-11-08T08:00:00.000Z');

type Fn = jest.Mock<(...args: any[]) => any>;
const fn = (): Fn => jest.fn<(...args: any[]) => any>();

const role = (r: string, system: SystemType = SystemType.VRMS) => ({
  role: r,
  system,
});

function managedRow(roles = [role('MECHANIC')]) {
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
  const order: string[] = [];
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
    userChange: { create: fn(), createMany: fn() },
    passwordResetToken: { create: fn() },
    $queryRaw: fn(),
    $transaction: fn(),
  };
  db.$transaction.mockImplementation((arg: unknown) =>
    (arg as (tx: typeof db) => unknown)(db),
  );
  db.$queryRaw.mockImplementation((sql: TemplateStringsArray) => {
    order.push(sql.join('?').includes('FROM users') ? 'lock' : 'raw');
    return Promise.resolve([]);
  });
  db.user.findUnique.mockImplementation(() => {
    order.push('read');
    return Promise.resolve({
      id: USER_ID,
      name: 'Pedro',
      email: 'pedro@welinc.com',
      isActive: true,
      deletedAt: null,
      roles: [role('MECHANIC')],
    });
  });
  db.user.count.mockResolvedValue(1);
  db.user.update.mockResolvedValue(managedRow());
  db.user.findMany.mockResolvedValue([]);
  const service = new AuthService(
    db as unknown as PrismaService,
    {} as TokenService,
    { sendMail: fn() } as unknown as MailService,
    fakeConfig(),
    {
      endAllForUser: jest.fn(() => Promise.resolve(0)),
    } as unknown as SessionService,
    new FakeCatalogService(),
    fakeCodes(),
  );
  return { service, db, order };
}

const bodyOf = (error: unknown) =>
  (error as HttpException).getResponse() as {
    code?: string;
    message?: string;
  };

describe('spec 0004 role rules in user admin', () => {
  // covers: AC-9
  describe('UNKNOWN_ROLE', () => {
    it('refuses a role VRMS does not have, naming its roles', async () => {
      const { service, db } = build();

      const error = await service
        .createUser(
          {
            name: 'Pedro',
            email: 'pedro@welinc.com',
            roleAssignments: [role('DRIVER')],
          },
          vrmsAdmin,
        )
        .catch((e: unknown) => e);

      expect((error as HttpException).getStatus()).toBe(400);
      expect(bodyOf(error)).toMatchObject({
        code: 'UNKNOWN_ROLE',
        message:
          "VRMS has no role 'DRIVER'. Its roles are Admin, Chief Mechanic, Mechanic.",
      });
      expect(db.user.findFirst).not.toHaveBeenCalled();
    });

    it('names the BMS roles in file order for a BMS admin', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue({
        id: USER_ID,
        name: 'Pedro',
        email: 'pedro@welinc.com',
        isActive: true,
        deletedAt: null,
        roles: [role('OPERATIONS', SystemType.BMS)],
      });

      const error = await service
        .updateUser(
          USER_ID,
          { roleAssignments: [role('MECHANIC', SystemType.BMS)] },
          { ...vrmsAdmin, system: SystemType.BMS },
        )
        .catch((e: unknown) => e);

      expect(bodyOf(error)).toMatchObject({
        code: 'UNKNOWN_ROLE',
        message:
          "BMS has no role 'MECHANIC'. Its roles are Admin, Operations, Customer Support, Driver, Helper.",
      });
    });

    it('checks the list filter against the token system', async () => {
      const { service, db } = build();

      const error = await service
        .listUsers({ role: 'DRIVER' }, { system: SystemType.VRMS })
        .catch((e: unknown) => e);

      expect(bodyOf(error).code).toBe('UNKNOWN_ROLE');
      expect(db.user.findMany).not.toHaveBeenCalled();
    });

    it('filters by a known role inside the system', async () => {
      const { service, db } = build();

      await service.listUsers(
        { role: 'CHIEF_MECHANIC' },
        { system: SystemType.VRMS },
      );

      expect(db.user.findMany).toHaveBeenCalledWith(
        expect.objectContaining({
          where: {
            deletedAt: null,
            roles: {
              some: { system: SystemType.VRMS, role: 'CHIEF_MECHANIC' },
            },
          },
        }),
      );
    });
  });

  // covers: AC-10
  describe('ROLE_LIMIT', () => {
    it('refuses two VRMS roles in one request, never trimming', async () => {
      const { service, db } = build();

      const error = await service
        .updateUser(
          USER_ID,
          { roleAssignments: [role('ADMIN'), role('MECHANIC')] },
          vrmsAdmin,
        )
        .catch((e: unknown) => e);

      expect((error as HttpException).getStatus()).toBe(409);
      expect(bodyOf(error)).toMatchObject({
        code: 'ROLE_LIMIT',
        message: 'VRMS allows one role per person.',
      });
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it("answers 403 for another system's role before UNKNOWN_ROLE", async () => {
      const { service } = build();

      await expect(
        service.updateUser(
          USER_ID,
          { roleAssignments: [role('DRIVER', SystemType.BMS)] },
          vrmsAdmin,
        ),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('answers UNKNOWN_ROLE before ROLE_LIMIT', async () => {
      const { service } = build();

      const error = await service
        .updateUser(
          USER_ID,
          { roleAssignments: [role('ADMIN'), role('DRIVER')] },
          vrmsAdmin,
        )
        .catch((e: unknown) => e);

      expect(bodyOf(error).code).toBe('UNKNOWN_ROLE');
    });

    it('answers the duplicate 400 before anything else', async () => {
      const { service } = build();

      const error = await service
        .updateUser(
          USER_ID,
          { roleAssignments: [role('DRIVER'), role('DRIVER')] },
          vrmsAdmin,
        )
        .catch((e: unknown) => e);

      expect(bodyOf(error).message).toBe(
        'Duplicate role assignments are not allowed',
      );
    });
  });

  // covers: AC-11
  it('changes Mechanic to Chief Mechanic in one edit', async () => {
    const { service, db } = build();

    await service.updateUser(
      USER_ID,
      { roleAssignments: [role('CHIEF_MECHANIC')] },
      vrmsAdmin,
    );

    expect(db.user.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          roles: { deleteMany: {}, create: [role('CHIEF_MECHANIC')] },
        }),
      }),
    );
  });

  // covers: AC-13
  describe('the account row lock', () => {
    it('locks the account before reading its roles inside an edit', async () => {
      const { service, order } = build();

      await service.updateUser(
        USER_ID,
        { roleAssignments: [role('CHIEF_MECHANIC')] },
        vrmsAdmin,
      );

      // One read before the transaction (the early 404), then the lock, then the fresh read
      expect(order.slice(0, 3)).toEqual(['read', 'lock', 'read']);
    });

    it('locks the account first when attaching, and counts the limit from the fresh read', async () => {
      const { service, db, order } = build();
      const account = {
        id: USER_ID,
        name: 'Pedro',
        isActive: true,
        deletedAt: null,
        roles: [role('OPERATIONS', SystemType.BMS)],
      };
      db.user.findFirst.mockResolvedValue(account);
      db.user.findUnique.mockImplementation(() => {
        order.push('read');
        return Promise.resolve(account);
      });
      db.user.findUniqueOrThrow.mockResolvedValue(
        managedRow([role('OPERATIONS', SystemType.BMS), role('MECHANIC')]),
      );

      await service.createUser(
        {
          name: 'Pedro',
          email: 'pedro@welinc.com',
          roleAssignments: [role('MECHANIC')],
          attachExisting: true,
        },
        vrmsAdmin,
      );

      expect(order.slice(0, 2)).toEqual(['lock', 'read']);
      expect(db.userRoleAssignment.createMany).toHaveBeenCalled();
    });

    it('locks the account before the admin rows on a deactivation', async () => {
      const { service, db, order } = build();
      db.user.findFirst.mockResolvedValue({
        isActive: true,
        roles: [role('ADMIN')],
      });

      await service.updateUserStatus(USER_ID, { isActive: false }, vrmsAdmin);

      expect(order).toEqual(['lock', 'raw']);
    });
  });

  // covers: AC-12
  describe('own roles', () => {
    it('refuses an admin editing their own role', async () => {
      const { service, db } = build();
      db.user.findUnique.mockResolvedValue({
        id: ADMIN_ID,
        name: 'Admin',
        email: 'admin@welinc.com',
        isActive: true,
        deletedAt: null,
        roles: [role('ADMIN')],
      });

      await expect(
        service.updateUser(
          ADMIN_ID,
          { roleAssignments: [role('MECHANIC')] },
          vrmsAdmin,
        ),
      ).rejects.toThrow(
        new ConflictException("You can't change your own role."),
      );
      expect(db.user.update).not.toHaveBeenCalled();
    });

    it('refuses attaching a role to your own account, since you already hold one here', async () => {
      const { service, db } = build();
      db.user.findFirst.mockResolvedValue({
        id: ADMIN_ID,
        name: 'Admin',
        isActive: true,
        deletedAt: null,
        roles: [role('ADMIN')],
      });

      await expect(
        service.createUser(
          {
            name: 'Admin',
            email: 'admin@welinc.com',
            roleAssignments: [role('MECHANIC')],
            attachExisting: true,
          },
          vrmsAdmin,
        ),
      ).rejects.toThrow(new ConflictException('Email already exists'));
      expect(db.userRoleAssignment.createMany).not.toHaveBeenCalled();
    });
  });

  // covers: AC-15
  it('keeps the last admin rule through the flag', async () => {
    const { service, db } = build();
    db.user.findUnique.mockResolvedValue({
      id: USER_ID,
      name: 'Pedro',
      email: 'pedro@welinc.com',
      isActive: true,
      deletedAt: null,
      roles: [role('ADMIN')],
    });
    db.user.count.mockResolvedValue(0);

    await expect(
      service.updateUser(
        USER_ID,
        { roleAssignments: [role('MECHANIC')] },
        vrmsAdmin,
      ),
    ).rejects.toThrow('This is the last VRMS admin.');
  });

  // covers: AC-17
  it('/auth/me returns only the roles of the token system', async () => {
    const { service, db } = build();
    db.user.findFirst.mockResolvedValue(
      managedRow([role('MECHANIC'), role('MECHANIC', SystemType.VMMS)]),
    );

    const me = await service.getCurrentUser(USER_ID, SystemType.VRMS);

    expect(me.roles).toEqual([role('MECHANIC')]);
  });
});
