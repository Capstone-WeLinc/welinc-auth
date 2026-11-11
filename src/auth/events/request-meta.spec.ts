import { describe, expect, it } from '@jest/globals';
import { NO_META, normaliseIp, requestMeta } from './request-meta';

const CHROME =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// covers: AC-3 (the browser's address, a device label, never a container's)
describe('normaliseIp', () => {
  it('keeps a plain IPv4 and IPv6 address', () => {
    expect(normaliseIp('112.198.0.1')).toBe('112.198.0.1');
    expect(normaliseIp('2001:4860:4860::8888')).toBe('2001:4860:4860::8888');
  });

  it('unwraps an IPv4 mapped IPv6 address', () => {
    expect(normaliseIp('::ffff:1.2.3.4')).toBe('1.2.3.4');
  });

  it('drops an IPv6 zone', () => {
    expect(normaliseIp('fe80::1%eth0')).toBe('fe80::1');
  });

  it('trims whitespace', () => {
    expect(normaliseIp('  8.8.8.8 ')).toBe('8.8.8.8');
  });

  it.each([null, undefined, '', 'unknown', '999.1.1.1', '1.2.3', 'a, b'])(
    'returns null for %p',
    (raw) => {
      expect(normaliseIp(raw)).toBeNull();
    },
  );
});

describe('requestMeta', () => {
  it('reads the address and labels the device from the user agent', () => {
    const meta = requestMeta({
      ip: '::ffff:112.198.0.1',
      headers: { 'user-agent': CHROME },
    });
    expect(meta).toEqual({
      ip: '112.198.0.1',
      device: 'Chrome on Windows',
      userAgent: CHROME,
    });
  });

  it('truncates a very long user agent to 512 characters', () => {
    const meta = requestMeta({
      ip: '8.8.8.8',
      headers: { 'user-agent': 'x'.repeat(2000) },
    });
    expect(meta.userAgent).toHaveLength(512);
  });

  it('uses the app reported device name for a mobile login', () => {
    const meta = requestMeta(
      { ip: '8.8.8.8', headers: { 'user-agent': 'okhttp/4' } },
      { deviceName: 'Pixel 8' },
    );
    expect(meta.device).toBe('Pixel 8');
  });

  it('falls back to Unknown device when the app sent no name', () => {
    const meta = requestMeta(
      { ip: '8.8.8.8', headers: {} },
      { deviceName: null },
    );
    expect(meta.device).toBe('Unknown device');
  });

  it('caps the device label at 100 characters', () => {
    const meta = requestMeta(
      { ip: '8.8.8.8', headers: {} },
      { deviceName: 'd'.repeat(300) },
    );
    expect(meta.device).toHaveLength(100);
  });

  it('stores no address or agent when the request has neither', () => {
    const meta = requestMeta({ ip: undefined, headers: {} });
    expect(meta.ip).toBeNull();
    expect(meta.userAgent).toBeNull();
    expect(meta.device).toBe('Unknown browser on Unknown OS');
  });

  it('exposes an empty meta for events with no request', () => {
    expect(NO_META).toEqual({ ip: null, device: null, userAgent: null });
  });
});
