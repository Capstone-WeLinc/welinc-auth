/**
 * Made up domains the seed accounts and local tests use (spec 0006). On a development machine an
 * address here skips the DNS check when an account is made, and its email is printed to the log
 * instead of sent, so seed accounts get their codes while real addresses still go through SMTP.
 */
export const DEV_EMAIL_DOMAINS = [
  'welinc.com',
  'localhost',
  'test.com',
  'example.com',
];

/** True for an address on one of the made up domains above. */
export function isDevAddress(email: string): boolean {
  const domain = email.split('@').pop()?.trim().toLowerCase() ?? '';
  return DEV_EMAIL_DOMAINS.includes(domain);
}
