import {
  HttpStatus,
  Inject,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import type { Request } from 'express';
import { coded } from '../errors';
import { SESSION_SETTINGS, type SessionSettings } from './session-config';

/**
 * The CSRF check for a cookie authenticated route (spec 0001 section 7, spec 0003 AC-17): POST,
 * `Content-Type: application/json`, `Origin` exactly the allowed web address, and
 * `Sec-Fetch-Site` `same-origin` or `same-site` when the browser sends it. Spec 0013, AC-14: the
 * admin routes also write with PATCH and DELETE, which pass `methods` (same header rules).
 */
export function passesCsrf(
  request: Request,
  allowedOrigin: string,
  methods: readonly string[] = ['POST'],
): boolean {
  if (!methods.includes(request.method)) return false;
  // Read the header itself: `req.is()` answers null for a POST with no body
  const type = request.headers['content-type'];
  if (
    typeof type !== 'string' ||
    type.split(';')[0].trim().toLowerCase() !== 'application/json'
  ) {
    return false;
  }
  if (request.headers.origin !== allowedOrigin) return false;
  const site = request.headers['sec-fetch-site'];
  if (site !== undefined && site !== 'same-origin' && site !== 'same-site') {
    return false;
  }
  return true;
}

export const csrfRejected = () =>
  coded(
    HttpStatus.FORBIDDEN,
    'CSRF_REJECTED',
    'This request did not come from the portal',
  );

/** Every write method a cookie route may use (spec 0013, AC-14: every non `GET`). */
export const COOKIE_WRITE_METHODS = ['POST', 'PATCH', 'DELETE'] as const;

/**
 * The CSRF guard on welinc-auth's cookie routes: the portal is the one allowed origin. It sits
 * only on write routes, so it takes any write method; each still needs the JSON content type.
 */
@Injectable()
export class PortalCsrfGuard implements CanActivate {
  constructor(
    @Inject(SESSION_SETTINGS) private readonly settings: SessionSettings,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();
    if (
      !passesCsrf(request, this.settings.portalOrigin, COOKIE_WRITE_METHODS)
    ) {
      throw csrfRejected();
    }
    return true;
  }
}
