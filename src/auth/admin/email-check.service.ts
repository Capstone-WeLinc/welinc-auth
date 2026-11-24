import { Injectable } from '@nestjs/common';
import type { SystemType } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { liveRoleWhere } from '../roles/live-roles';
import { launcherOrder } from '../sessions/launcher';
import type { AdminStanding } from './admin-standing.service';

export type EmailCheckStatus =
  'inactive' | 'suite-admin' | 'in-system' | 'existing' | 'free';

/** The `GET /auth/admin/users/email-check` body (suite spec 0019, AC-23). */
export type EmailCheck = {
  status: EmailCheckStatus;
  /** `existing` and `in-system` only. */
  name?: string;
  picture?: string | null;
  /** `existing` and `in-system` only: the person's systems the caller administers. */
  systems?: SystemType[];
};

/**
 * Suite spec 0019, AC-22, AC-23: what Add a user can do with one exact email in `system`. It
 * finds the account the way create does (a case insensitive match over every account, deleted
 * ones included), so the answer never disagrees with what create then does.
 */
@Injectable()
export class EmailCheckService {
  constructor(private readonly prisma: PrismaService) {}

  async check(
    email: string,
    system: SystemType,
    caller: AdminStanding,
  ): Promise<EmailCheck> {
    const user = await this.prisma.user.findFirst({
      where: { email: { equals: email, mode: 'insensitive' } },
      select: {
        name: true,
        profilePicture: true,
        isActive: true,
        deletedAt: true,
        suiteAdmin: { select: { userId: true } },
        roles: { where: liveRoleWhere(), select: { system: true } },
      },
    });
    return emailCheckAnswer(user, system, caller);
  }
}

type CheckedUser = {
  name: string;
  profilePicture: string | null;
  isActive: boolean;
  deletedAt: Date | null;
  suiteAdmin: { userId: string } | null;
  roles: { system: SystemType }[];
};

/**
 * Pure: the first status that applies, in AC-23's order. Only a suite admin learns that an
 * address is a suite admin's; a system admin gets `existing` with no systems for it. Systems are
 * listed only where the caller is an admin.
 */
export function emailCheckAnswer(
  user: CheckedUser | null,
  system: SystemType,
  caller: AdminStanding,
): EmailCheck {
  if (!user) return { status: 'free' };
  if (!user.isActive || user.deletedAt) return { status: 'inactive' };
  const person = { name: user.name, picture: user.profilePicture };
  if (user.suiteAdmin) {
    return caller.suiteAdmin
      ? { status: 'suite-admin' }
      : { status: 'existing', ...person, systems: [] };
  }
  const systems = launcherOrder(user.roles).filter(
    (s) => caller.suiteAdmin || caller.adminOf.includes(s),
  );
  const inSystem = user.roles.some((r) => r.system === system);
  return { status: inSystem ? 'in-system' : 'existing', ...person, systems };
}
