import { ForbiddenException, Injectable } from '@nestjs/common';
import {
  AccountEventType,
  ReauthPurpose,
  SessionEndReason,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { AccountEventsService } from '../events/account-events.service';
import { PasswordCheckService } from '../reauth/password-check.service';
import { SessionService } from '../sessions/session.service';
import { change } from '../user-changes';
import { assertInSystem, type AdminCaller } from '../user-scope';
import { AdminAlertsService } from './admin-alerts.service';
import {
  AdminStandingService,
  alertSystemsOf,
  isAdmin,
} from './admin-standing.service';

/** Admins end their own sessions through logout or Signed in devices, not the admin route. */
export const SELF_END_ALL =
  "You can't end your own sessions here. Use Signed in devices on your profile.";

/**
 * An admin's view of a person's sessions (spec 0003, AC-32), one service for the bearer
 * `/auth/users/:id/sessions` and the portal's `/auth/admin/users/:id/sessions` (spec 0013,
 * AC-16). Spec 0011 scoping: 404 for anyone outside the admin's system.
 */
@Injectable()
export class AccountSessionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly sessions: SessionService,
    private readonly events: AccountEventsService,
    private readonly passwords: PasswordCheckService,
    private readonly admins: AdminStandingService,
    private readonly alerts: AdminAlertsService,
  ) {}

  async list(userId: string, actor: AdminCaller) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        deletedAt: true,
        roles: { select: { role: true, system: true } },
      },
    });
    assertInSystem(user?.deletedAt ? null : user, actor.system);
    return this.sessions.listLive(userId);
  }

  /**
   * Ends every live session (`ADMIN_ENDED`, the admin as `endedById`) and records one
   * `SESSIONS_ENDED` holding the count, in one transaction. On an admin account it needs the
   * actor's `ADMIN_ACTION` recheck and alerts (spec 0013, AC-14b).
   */
  async endAll(
    userId: string,
    actor: AdminCaller,
    reauthToken: unknown,
  ): Promise<number> {
    const { ended, target } = await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.findUnique({
        where: { id: userId },
        select: {
          deletedAt: true,
          roles: { select: { role: true, system: true } },
        },
      });
      assertInSystem(user?.deletedAt ? null : user, actor.system);
      if (userId === actor.id) throw new ForbiddenException(SELF_END_ALL);
      const standing = await this.admins.standing(userId, tx);
      if (isAdmin(standing)) {
        await this.passwords.consumeReauthToken(
          tx,
          typeof reauthToken === 'string' ? reauthToken : undefined,
          actor.id,
          actor.sid,
          ReauthPurpose.ADMIN_ACTION,
        );
      }
      const count = await this.sessions.endAllForUser(
        tx,
        userId,
        SessionEndReason.ADMIN_ENDED,
        { endedById: actor.id, system: actor.system, ip: actor.meta?.ip },
      );
      await this.events.record(
        tx,
        change(userId, actor, AccountEventType.SESSIONS_ENDED, {
          newValue: String(count),
        }),
      );
      return { ended: count, target: standing };
    });
    if (isAdmin(target)) {
      await this.alerts.send(actor.id, [
        {
          kind: 'ADMIN_SESSIONS_ENDED',
          targetId: userId,
          systems: alertSystemsOf(target),
        },
      ]);
    }
    return ended;
  }
}
