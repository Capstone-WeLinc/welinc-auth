import { describe, expect, it } from '@jest/globals';
import { createHash } from 'crypto';
import type { Request } from 'express';
import { userAddressOf } from '../clients/token-endpoint.service';
import { errorPage } from './authorize.service';
import { passesCsrf } from './csrf';
import {
  hashOpaque,
  isOpaqueShape,
  newOpaque,
  openGrace,
  pkceMatches,
  sealGrace,
} from './opaque';
import { cutoffReason, sessionExpiresAt } from './session.service';

// covers: spec 0003 AC-7 (opaque values hashed), AC-8 (grace cipher), AC-13 and AC-15 (PKCE,
// error page), AC-3 (cutoffs), AC-17 (CSRF check), AC-43 (user address header)
describe('spec 0003 helpers', () => {
  it('makes 256 bit base64url values and stores only their SHA-256', () => {
    const value = newOpaque();
    expect(isOpaqueShape(value)).toBe(true);
    expect(hashOpaque(value)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashOpaque(value)).not.toContain(value);
    expect(isOpaqueShape('short')).toBe(false);
    expect(isOpaqueShape(['a'])).toBe(false);
  });

  it('opens the grace cipher only with the old token and the same row', () => {
    const old = newOpaque();
    const child = newOpaque();
    const sealed = sealGrace(child, old, 'row-1');
    expect(sealed.toString('utf8')).not.toContain(child);
    expect(openGrace(sealed, old, 'row-1')).toBe(child);
    expect(openGrace(sealed, newOpaque(), 'row-1')).toBeNull();
    expect(openGrace(sealed, old, 'row-2')).toBeNull();
    expect(openGrace(Buffer.alloc(10), old, 'row-1')).toBeNull();
  });

  it('checks PKCE S256', () => {
    const verifier = newOpaque() + newOpaque();
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    expect(pkceMatches(verifier, challenge)).toBe(true);
    expect(pkceMatches(verifier + 'x', challenge)).toBe(false);
  });

  it('ends at the absolute cutoff first, then the idle one, and reports the earlier as expiry', () => {
    const at = (m: number) => new Date(Date.UTC(2026, 10, 9, 8, m));
    const session = {
      endedAt: null,
      idleExpiresAt: at(30),
      absoluteExpiresAt: at(20),
    };
    expect(sessionExpiresAt(session)).toEqual(at(20));
    expect(cutoffReason(session, at(10))).toBeNull();
    expect(cutoffReason(session, at(25))).toBe('MAX_AGE');
    expect(cutoffReason({ ...session, absoluteExpiresAt: null }, at(31))).toBe(
      'IDLE',
    );
    expect(cutoffReason({ ...session, endedAt: at(1) }, at(40))).toBeNull();
  });

  it('runs the CSRF check: POST, JSON, the exact origin, a same site fetch', () => {
    const origin = 'http://localhost:8000';
    const req = (over: {
      method?: string;
      json?: boolean;
      headers?: Record<string, string>;
    }) =>
      ({
        method: over.method ?? 'POST',
        headers: {
          origin,
          'sec-fetch-site': 'same-site',
          'content-type':
            (over.json ?? true)
              ? 'application/json; charset=utf-8'
              : 'text/plain',
          ...over.headers,
        },
      }) as unknown as Request;
    expect(passesCsrf(req({}), origin)).toBe(true);
    expect(
      passesCsrf(req({ headers: { 'sec-fetch-site': 'same-origin' } }), origin),
    ).toBe(true);
    expect(passesCsrf(req({ method: 'GET' }), origin)).toBe(false);
    expect(passesCsrf(req({ json: false }), origin)).toBe(false);
    // An empty JSON POST (logout, refresh) still carries the header
    expect(
      passesCsrf(
        req({ headers: { 'content-type': 'application/json' } }),
        origin,
      ),
    ).toBe(true);
    expect(
      passesCsrf(req({ headers: { origin: 'http://evil.test' } }), origin),
    ).toBe(false);
    expect(
      passesCsrf(req({ headers: { origin: `${origin}.evil.test` } }), origin),
    ).toBe(false);
    expect(
      passesCsrf(req({ headers: { 'sec-fetch-site': 'cross-site' } }), origin),
    ).toBe(false);
  });

  it('keeps X-WeLinc-User-Address only when it is a plain IP address', () => {
    expect(userAddressOf('203.0.113.7')).toBe('203.0.113.7');
    expect(userAddressOf(' 2001:db8::1 ')).toBe('2001:db8::1');
    expect(userAddressOf('203.0.113.7, 10.0.0.1')).toBeNull();
    expect(userAddressOf('<script>')).toBeNull();
    expect(userAddressOf(undefined)).toBeNull();
  });

  it('escapes everything the authorize error page shows', () => {
    const page = errorPage('<img src=x onerror="alert(1)">');
    expect(page).not.toContain('<img');
    expect(page).toContain('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
  });
});
