/**
 * Made up domains the seed accounts and local tests use (spec 0006). On a development machine an
 * address here skips the DNS check when an account is made. Its email is printed to the log instead
 * of sent outside production, and on staging too (SEED_MAIL_TO_LOG, spec 0009 AC-32), or on staging
 * goes to the team inbox (SEED_MAIL_REDIRECT, AC-33), so seed accounts get their codes while real
 * addresses still go through SMTP.
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

/** The longest tag a seed address gets in the team inbox address (spec 0009, AC-33). */
const TAG_MAX = 40;

/**
 * The team inbox address for a seed address (spec 0009, AC-33): `{tag}` in the template becomes the
 * seed address's local part, lowercased, anything outside a to z, 0 to 9, `.`, `_` and `-` turned
 * into `-`, cut to 40 characters. `vrms.admin@welinc.com` with `team+{tag}@gmail.com` gives
 * `team+vrms.admin@gmail.com`.
 */
export function seedMailRecipient(to: string, template: string): string {
  const local = to.slice(0, Math.max(to.lastIndexOf('@'), 0));
  const tag = local
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '-')
    .slice(0, TAG_MAX);
  return template.replace('{tag}', tag);
}
