import { isIP } from 'node:net';
import type { Request } from 'express';
import { browserLabel } from '../sessions/device-label';

/**
 * Where an event came from (spec 0011, AC-3): the client address, the device label and the raw
 * `User-Agent`. Display and audit only, never used for a security decision.
 */
export type RequestMeta = {
  ip: string | null;
  device: string | null;
  userAgent: string | null;
};

export const NO_META: RequestMeta = { ip: null, device: null, userAgent: null };

const USER_AGENT_MAX = 512;
const DEVICE_MAX = 100;

/**
 * A storable address: IPv4 mapped IPv6 (`::ffff:1.2.3.4`) as plain IPv4, an IPv6 zone dropped,
 * anything that isn't an address as null (the column is `inet`).
 */
export function normaliseIp(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let ip = raw.trim();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) ip = mapped[1];
  ip = ip.replace(/%.*$/, '');
  return isIP(ip) ? ip : null;
}

/**
 * The meta of a browser or app request. `req.ip` honours `TRUST_PROXY_HOPS`, so behind the
 * gateway it is the browser's address, never a container's. A mobile login passes the device
 * name the app reported; otherwise the label comes from the `User-Agent`.
 */
export function requestMeta(
  req: Pick<Request, 'ip' | 'headers'>,
  opts: { deviceName?: string | null } = {},
): RequestMeta {
  const header = req.headers['user-agent'];
  const userAgent =
    typeof header === 'string' && header.length > 0
      ? header.slice(0, USER_AGENT_MAX)
      : null;
  const device =
    opts.deviceName !== undefined
      ? (opts.deviceName ?? 'Unknown device')
      : browserLabel(userAgent);
  return {
    ip: normaliseIp(req.ip),
    device: device.slice(0, DEVICE_MAX),
    userAgent,
  };
}
