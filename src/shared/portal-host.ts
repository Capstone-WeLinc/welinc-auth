/**
 * Suite spec 0009 AC-34: the portal's host (with any port) to name in email text, never a full
 * URL, so no email holds a link Brevo would rewrite through its click tracking domain.
 */
export function portalHostOf(url: string): string {
  return new URL(url).host;
}
