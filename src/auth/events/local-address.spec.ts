import { describe, expect, it } from '@jest/globals';
import { isLocalAddress } from './local-address';

// covers: AC-17, AC-19 (local rows read back as localNetwork)
describe('isLocalAddress', () => {
  it.each([
    '10.0.0.1',
    '127.0.0.1',
    '172.16.0.1',
    '172.19.0.1',
    '172.31.255.255',
    '192.168.1.20',
    '169.254.10.10',
    '100.64.0.1',
    '100.127.255.255',
    '::1',
    'fc00::1',
    'fd12:3456::1',
    'fe80::1',
    'FE80::ABCD',
  ])('treats %s as local', (ip) => {
    expect(isLocalAddress(ip)).toBe(true);
  });

  it.each([
    '8.8.8.8',
    '112.198.0.1',
    '172.15.0.1',
    '172.32.0.1',
    '100.63.0.1',
    '100.128.0.1',
    '192.169.0.1',
    '2001:4860:4860::8888',
  ])('treats %s as public', (ip) => {
    expect(isLocalAddress(ip)).toBe(false);
  });

  it('is false for no address', () => {
    expect(isLocalAddress(null)).toBe(false);
    expect(isLocalAddress('')).toBe(false);
  });
});
