import {
  ForbiddenException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';
import { SystemType, UserRole } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
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
  roles: { role: UserRole; system: SystemType }[];
  system: SystemType;
};

/** A backend calling with its own service token (spec 0002, AC-19). */
export type ServiceCaller = {
  kind: 'service';
  clientId: string;
  scopes: string[];
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
  ) {}

  async authenticate(request: Request): Promise<Caller> {
    const raw = bearerToken(request);
    if (!raw) throw new UnauthorizedException();

    let token: VerifiedToken;
    try {
      token = await this.tokens.verify(raw);
    } catch (error) {
      if (error instanceof TokenRejectedError)
        throw new UnauthorizedException();
      throw error;
    }

    if (token.tokenUse === 'service') {
      return {
        kind: 'service',
        clientId: token.clientId,
        scopes: token.scopes,
        token,
      };
    }

    const system = token.aud;
    const asked = querySystem(request);
    if (asked !== undefined && asked !== system) {
      throw coded(
        HttpStatus.FORBIDDEN,
        'WRONG_AUDIENCE',
        `This token is for ${system}, not ${asked}`,
      );
    }

    const user = await this.prisma.user.findFirst({
      where: { id: token.sub, deletedAt: null },
      select: {
        id: true,
        email: true,
        isActive: true,
        lockedAt: true,
        roles: { select: { role: true, system: true } },
      },
    });

    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid session');
    }
    if (user.lockedAt !== null) {
      throw new ForbiddenException(
        'Account is locked. Contact your Admin to unlock.',
      );
    }
    if (!user.roles.some((assignment) => assignment.system === system)) {
      throw new UnauthorizedException(
        'User does not have access to this system',
      );
    }

    return {
      kind: 'user',
      sub: user.id,
      email: user.email,
      roles: user.roles,
      system,
    };
  }
}
