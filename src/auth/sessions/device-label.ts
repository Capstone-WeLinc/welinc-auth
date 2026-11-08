/**
 * The device label a session list shows (spec 0003, AC-33): `<browser> on <OS>` from our own
 * parser over the `User-Agent`, or the device name a mobile app reported. Display only: never
 * used for a security decision.
 */

// Order matters: Edge, Opera and Samsung Internet also say "Chrome", and Chrome says "Safari"
const BROWSERS: [RegExp, string][] = [
  [/\bEdg(e|A|iOS)?\//, 'Edge'],
  [/\bOPR\/|\bOpera\b/, 'Opera'],
  [/\bSamsungBrowser\//, 'Samsung Internet'],
  [/\bFirefox\/|\bFxiOS\//, 'Firefox'],
  [/\bChrome\/|\bCriOS\//, 'Chrome'],
  [/\bVersion\/[\d.]+.*\bSafari\//, 'Safari'],
];

// iOS before macOS (iPad can say "Mac OS X"), Android and ChromeOS before Linux
const SYSTEMS: [RegExp, string][] = [
  [/\bWindows NT\b/, 'Windows'],
  [/\biPhone\b|\biPad\b|\biPod\b/, 'iOS'],
  [/\bAndroid\b/, 'Android'],
  [/\bCrOS\b/, 'ChromeOS'],
  [/\bMacintosh\b|\bMac OS X\b/, 'macOS'],
  [/\bLinux\b/, 'Linux'],
];

function match(table: [RegExp, string][], ua: string): string | null {
  return table.find(([pattern]) => pattern.test(ua))?.[1] ?? null;
}

export function browserLabel(userAgent: string | null): string {
  const ua = userAgent ?? '';
  const browser = match(BROWSERS, ua) ?? 'Unknown browser';
  const os = match(SYSTEMS, ua) ?? 'Unknown OS';
  return `${browser} on ${os}`;
}

export function deviceLabel(session: {
  kind: 'WEB' | 'MOBILE';
  userAgent: string | null;
  deviceName: string | null;
}): string {
  if (session.kind === 'MOBILE') return session.deviceName ?? 'Unknown device';
  return browserLabel(session.userAgent);
}
