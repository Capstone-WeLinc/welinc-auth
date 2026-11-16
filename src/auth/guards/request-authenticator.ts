import { liveRoleWhere } from '../roles/live-roles';
import { HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { SystemType } from '@prisma/client';
import type { RoleAssignment } from '../roles/catalog.types';
import { PrismaService } from '../../shared/prisma.service';
import { SessionService } from '../sessions/session.service';
import { coded } from '../errors';
import { setSentryUser } from '../../monitoring/user-context';
import { accountLocked, lockActive } from '../lockout';
import {
  TokenRejectedError,
  TokenService,
  type VerifiedServiceToken,
  type VerifiedToken,
} from '../tokens/token.service';

/** A signed in person. `system` is the token's `aud` (spec 0002, AC-9). */
export type UserCaller = {
  kind: 'user';
  sub: string;
  email: string;
  /** Every role the account holds, read from the database on each request. */
  roles: RoleAssignment[];
  system: SystemType;
  /** The token's session (spec 0003): what a password change keeps, and `current` in lists. */
  sid: string;
  /** Spec 0013, AC-6: when the token's session passed an emailed code, read on each request. */
  signInCodeAt: Date | null;
};

/** A backend calling with its own service token (spec 0002, AC-19). */
export type ServiceCaller = {
  kind: 'service';
  clientId: string;
  scopes: string[];
  /** The client's own system, from the registry: what an admin of it would see. */
  system: SystemType;
  token: VerifiedServiceToken;
};

export type Caller = UserCaller | ServiceCaller;

export function bearerToken(request: Request): string | null {
  const header = request.headers.authorization;
  if (typeof header !== 'string') return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

function querySystem(request: Request): string | undefined {
  const raw: unknown = Array.isArray(request.query?.system)
    ? request.query.system[0]
    : request.query?.system;
  return typeof raw === 'string' && raw !== '' ? raw.toUpperCase() : undefined;
}

/**
 * Turns a bearer token into a caller: checks the token in memory (AC-8), then, for a person,
 * the account in the database (active, not locked, holds a role in the token's system).
 */
@Injectable()
export class RequestAuthenticator {
  constructor(
    private readonly tokens: TokenService,
    private readonly prisma: PrismaService,
    private readonly sessions: SessionService,
  ) {}

  async authenticate(request: Request): Promise<Caller> {
    const raw = bearerToken(request);
    if (!raw) throw new UnauthorizedException();

    let token: VerifiedToken;
    try {
      token = await this.tokens.verify(raw);
    } catch (error) {
      if (error instanceof TokenRejectedError && error.expired) {
        throw coded(
          HttpStatus.UNAUTHORIZED,
          'TOKEN_EXPIRED',
          'The access token has expired',
        );
      }
      if (error instanceof TokenRejectedError)
        throw new UnauthorizedException();
      throw error;
    }

    const asked = querySystem(request);

    if (token.tokenUse === 'service') {
      // A client switched off, or one with no system (the portal), can't act for any system
      const client = await this.prisma.oAuthClient.findUnique({
        where: { id: token.clientId },
        select: { isActive: true, system: true },
      });
      if (!client || !client.isActive || !client.system) {
        throw new UnauthorizedException('Invalid session');
      }
      if (asked !== undefined && asked !== client.system) {
        throw coded(
          HttpStatus.FORBIDDEN,
          'WRONG_AUDIENCE',
          `This client acts for ${client.system}, not ${asked}`,
        );
      }
      return {
        kind: 'service',
        clientId: token.clientId,
        scopes: token.scopes,
        system: client.system,
        token,
      };
    }

    const system = token.aud;
    if (asked !== undefined && asked !== system) {
      throw coded(
        HttpStatus.FORBIDDEN,
        'WRONG_AUDIENCE',
        `This token is for ${system}, not ${asked}`,
      );
    }

    // Spec 0003, AC-1: a user token works only while its session is live; the S2 interim
    // token (no sid) never does
    const session = token.sid ? await this.sessions.live(token.sid) : null;
    if (!session || session.userId !== token.sub) {
      throw coded(
        HttpStatus.UNAUTHORIZED,
        'SESSION_ENDED',
        'The session has ended',
      );
    }

    const user = await this.prisma.user.findFirst({
      where: { id: token.sub, deletedAt: null },
      select: {
        id: true,
        email: true,
        isActive: true,
        lockedAt: true,
        // Spec 0013, AC-10: an expired temporary role is gone even before the sweep ends it
        roles: {
          where: liveRoleWhere(),
          select: { role: true, system: true },
        },
      },
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid session');
    }
    if (lockActive(user.lockedAt)) throw accountLocked(user.lockedAt);
    if (!user.roles.some((assignment) => assignment.system === system)) {
      throw new UnauthorizedException(
        'User does not have access to this system',
      );
    }

    const caller: UserCaller = {
      kind: 'user',
      sub: user.id,
      email: user.email,
      roles: user.roles,
      system,
      sid: session.id,
      signInCodeAt: session.signInCodeAt,
    };
    // VRMS spec 0025, AC-1: the id and this system's role names on any event from this request
    setSentryUser(caller);
    return caller;
  }
}
