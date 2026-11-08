import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { SERVICE_SCOPE_KEY } from '../decorators/service-scope.decorator';
import { CatalogService, holdsAdmin } from '../roles/catalog.service';
import type { Caller } from './request-authenticator';

/**
 * `@SystemAdmin()` (spec 0004, AC-14): the person holds their system's admin role, read from
 * the catalog on every request (no cache, so a sync that moves the flag applies at once). A
 * service token never counts as an admin: it passes only on a `@ServiceScope()` route, where
 * `JwtAuthGuard` already checked its scope (spec 0002, AC-19).
 */
@Injectable()
export class SystemAdminGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly catalog: CatalogService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const caller = context
      .switchToHttp()
      .getRequest<Request & { user?: Caller }>().user;
    if (!caller) return false;

    if (caller.kind === 'service') {
      return Boolean(
        this.reflector.getAllAndOverride<string | undefined>(
          SERVICE_SCOPE_KEY,
          [context.getHandler(), context.getClass()],
        ),
      );
    }

    return holdsAdmin(
      caller.roles,
      caller.system,
      await this.catalog.adminRoles(),
    );
  }
}
