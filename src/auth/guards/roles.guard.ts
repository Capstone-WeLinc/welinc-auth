import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { UserRole } from '@prisma/client';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { SERVICE_SCOPE_KEY } from '../decorators/service-scope.decorator';
import type { Caller } from './request-authenticator';

/**
 * Checks `@Roles()` against the person's roles in the token's system (`aud`, spec 0002, AC-9).
 * A service token never counts as an admin: it passes only on a `@ServiceScope()` route, where
 * `JwtAuthGuard` already checked its scope (AC-19).
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const targets = [context.getHandler(), context.getClass()];
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      targets,
    );

    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const caller = context
      .switchToHttp()
      .getRequest<Request & { user?: Caller }>().user;

    if (!caller) {
      return false;
    }

    if (caller.kind === 'service') {
      return Boolean(
        this.reflector.getAllAndOverride<string | undefined>(
          SERVICE_SCOPE_KEY,
          targets,
        ),
      );
    }

    return requiredRoles.some((requiredRole) =>
      caller.roles.some(
        (assignment) =>
          assignment.role === requiredRole &&
          assignment.system === caller.system,
      ),
    );
  }
}
