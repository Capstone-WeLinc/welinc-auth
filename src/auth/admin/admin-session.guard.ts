import {
  Inject,
  Injectable,
  SetMetadata,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { PrismaService } from '../../shared/prisma.service';
import { accountLocked, lockActive } from '../lockout';
import {
  SESSION_SETTINGS,
  type SessionSettings,
} from '../sessions/session-config';
import { SessionService } from '../sessions/session.service';
import { readSsoCookie } from '../sessions/sso-cookie';
import { adminCodeRequired, notAnAdmin, notSignedIn } from './admin-errors';
import {
  AdminStandingService,
  isAdmin,
  type AdminStanding,
} from './admin-standing.service';

/**
 * How much a `/auth/admin/*` route asks of the cookie session (spec 0013, AC-6, AC-15):
 * - `signed-in`: any live portal session (`GET /auth/admin/me`)
 * - `admin`: an admin, code or not (the step up routes)
 * - `admin-code` (the default): an admin whose session passed the code
 */
export type AdminRouteLevel = 'signed-in' | 'admin' | 'admin-code';

export const ADMIN_ROUTE_LEVEL = 'adminRouteLevel';

/** Lowers the default `admin-code` level for one route. */
export const AdminRoute = (level: AdminRouteLevel) =>
  SetMetadata(ADMIN_ROUTE_LEVEL, level);

/** The signed in portal caller of a `/auth/admin/*` route. */
export type PortalAdmin = {
  userId: string;
  sid: string;
  user: {
    id: string;
    name: string;
    email: string;
    profilePicture: string | null;
  };
  standing: AdminStanding;
  /** `ADMIN_SIGN_IN_CODE` at request time (AC-8). */
  codeRequired: boolean;
  /** The session's `sign_in_code_at` is set. */
  codePassed: boolean;
};

export type AdminRequest = Request & { portalAdmin?: PortalAdmin };

/**
 * Spec 0013, AC-14: `/auth/admin/*` is authenticated by the `welinc_sso` cookie (the live web
 * session it points to), never a bearer token. Writes also run `PortalCsrfGuard` at method level,
 * which Nest runs after this class level guard: a request with no live session answers 401 first.
 */
@Injectable()
export class AdminSessionGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly sessions: SessionService,
    private readonly prisma: PrismaService,
    private readonly admins: AdminStandingService,
    @Inject(SESSION_SETTINGS) private readonly settings: SessionSettings,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AdminRequest>();
    const session = await this.sessions.liveBySsoHandle(
      readSsoCookie(request, this.settings),
    );
    if (!session) throw notSignedIn();

    // Spec 0012: a locked account gets 403 ACCOUNT_LOCKED on every user route
    const account = await this.prisma.user.findUnique({
      where: { id: session.userId },
      select: { lockedAt: true },
    });
    if (account && lockActive(account.lockedAt)) {
      throw accountLocked(account.lockedAt);
    }

    const standing = await this.admins.standing(session.userId);
    const codeRequired = this.admins.codeRequired();
    request.portalAdmin = {
      userId: session.userId,
      sid: session.id,
      user: {
        id: session.user.id,
        name: session.user.name,
        email: session.user.email,
        profilePicture: session.user.profilePicture,
      },
      standing,
      codeRequired,
      codePassed: session.signInCodeAt !== null,
    };

    const level =
      this.reflector.getAllAndOverride<AdminRouteLevel | undefined>(
        ADMIN_ROUTE_LEVEL,
        [context.getHandler(), context.getClass()],
      ) ?? 'admin-code';
    if (level === 'signed-in') return true;
    if (!isAdmin(standing)) throw notAnAdmin();
    if (level === 'admin') return true;
    if (codeRequired && session.signInCodeAt === null) {
      throw adminCodeRequired();
    }
    return true;
  }
}

/** The caller the guard put on the request. */
export function portalAdmin(request: AdminRequest): PortalAdmin {
  if (!request.portalAdmin) throw notSignedIn();
  return request.portalAdmin;
}
