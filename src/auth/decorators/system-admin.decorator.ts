import { UseGuards, applyDecorators } from '@nestjs/common';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { SystemAdminGuard } from '../guards/system-admin.guard';

/**
 * Spec 0004, AC-14: the caller holds the role marked `isSystemAdmin` in the token's system
 * (`aud`). Authenticates too, so a route needs nothing else; a controller wide `JwtAuthGuard`
 * doesn't authenticate twice (see `JwtAuthGuard`). A service token passes only where the route
 * also carries `@ServiceScope()`.
 */
export const SystemAdmin = () =>
  applyDecorators(UseGuards(JwtAuthGuard, SystemAdminGuard));
