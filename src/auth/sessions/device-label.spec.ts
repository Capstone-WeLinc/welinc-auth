import { browserLabel, deviceLabel } from './device-label';

// Covers AC-33: the label is `<browser> on <OS>`, display only.
describe('browserLabel (AC-33)', () => {
  it.each([
    [
      'Chrome on Windows',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    ],
    [
      'Firefox on macOS',
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
    ],
    [
      'Edge on Windows',
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0',
    ],
    [
      'Opera on Windows',
      'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36 OPR/105.0',
    ],
    [
      'Samsung Internet on Android',
      'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36 SamsungBrowser/23.0',
    ],
    [
      'Safari on iOS',
      'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    ],
    [
      'Chrome on ChromeOS',
      'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 Chrome/120 Safari/537.36',
    ],
    [
      'Chrome on Linux',
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
    ],
  ])('reads %s from its User-Agent', (label, userAgent) => {
    expect(browserLabel(userAgent)).toBe(label);
  });

  it('puts iPad ahead of macOS even though iPad says Mac OS X', () => {
    expect(
      browserLabel(
        'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) Version/17.0 Safari/604.1',
      ),
    ).toBe('Safari on iOS');
  });

  it('answers Unknown for an empty, missing or odd User-Agent', () => {
    expect(browserLabel('')).toBe('Unknown browser on Unknown OS');
    expect(browserLabel(null)).toBe('Unknown browser on Unknown OS');
    expect(browserLabel('curl/8.4.0')).toBe('Unknown browser on Unknown OS');
  });

  it('does not throw on a very long or unicode User-Agent', () => {
    expect(() => browserLabel('é'.repeat(5000))).not.toThrow();
  });
});

describe('deviceLabel (AC-33)', () => {
  it('uses the reported device name for a mobile session', () => {
    expect(
      deviceLabel({
        kind: 'MOBILE',
        userAgent: 'Chrome/1',
        deviceName: 'Pixel 8 (Android 15)',
      }),
    ).toBe('Pixel 8 (Android 15)');
  });

  it('says Unknown device for a mobile session with no name', () => {
    expect(
      deviceLabel({ kind: 'MOBILE', userAgent: null, deviceName: null }),
    ).toBe('Unknown device');
  });

  it('ignores a device name on a web session and parses the User-Agent', () => {
    expect(
      deviceLabel({
        kind: 'WEB',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/120 Safari/537.36',
        deviceName: 'Spoofed',
      }),
    ).toBe('Chrome on Windows');
  });
});
