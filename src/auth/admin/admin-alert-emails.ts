import type { SystemType } from '@prisma/client';
import { escapeHtml, type Email } from '../codes/code-emails';

// Spec 0013, AC-13: the admin change alert. One email per recipient per save, listing every
// change in it, with who, what, when (Asia/Manila), the actor and the reason, and a portal link.

const BRAND = 'WeLinc Logistics';

/** What happened, in the alert's words (every AC-13 row). */
export type AdminAlertKind =
  | 'ADMIN_ROLE_ADDED'
  | 'ADMIN_ROLE_REMOVED'
  | 'ADMIN_EMAIL_CHANGED'
  | 'ADMIN_CODE_SENT'
  | 'ADMIN_UNLOCKED'
  | 'ADMIN_SESSIONS_ENDED'
  | 'SUITE_ADMIN_ADDED'
  | 'SUITE_ADMIN_REMOVED'
  | 'ADMIN_RECOVERY'
  | 'TEMP_ACCESS_STARTED'
  | 'TEMP_ACCESS_ENDED_EARLY'
  | 'SUITE_ROLE_GIVEN'
  | 'SUITE_ACCOUNT_CREATED'
  | 'PERMISSIONS_CHANGED';

/** One line of an alert, already resolved to names. */
export type AlertLine = {
  kind: AdminAlertKind;
  targetName: string;
  targetEmail: string;
  /** The system name the line is about ("VRMS"), or null for an account wide line. */
  systemName: string | null;
  /** The role's display name in that system, for role and temporary access lines. */
  roleName: string | null;
  /** When temporary access ends, for `TEMP_ACCESS_STARTED`. */
  until?: Date | null;
  at: Date;
  reason: string | null;
  /** `PERMISSIONS_CHANGED`: how many cells the save changed. */
  cells?: number;
};

/** "November 12, 2026, 3:04 PM" in Asia/Manila, as people in the suite read times. */
export function manilaDateTime(at: Date): string {
  return new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Manila',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(at);
}

function what(line: AlertLine): string {
  const role = `${line.systemName ?? 'a system'} ${line.roleName ?? 'admin'}`;
  switch (line.kind) {
    case 'ADMIN_ROLE_ADDED':
      return `was made ${role}`;
    case 'ADMIN_ROLE_REMOVED':
      return `is no longer ${role}`;
    case 'ADMIN_EMAIL_CHANGED':
      return 'had their sign in email changed by an admin';
    case 'ADMIN_CODE_SENT':
      return 'was sent a password reset or setup code by an admin';
    case 'ADMIN_UNLOCKED':
      return 'was unlocked by an admin';
    case 'ADMIN_SESSIONS_ENDED':
      return 'had every session ended by an admin';
    case 'SUITE_ADMIN_ADDED':
      return 'was made a suite admin';
    case 'SUITE_ADMIN_REMOVED':
      return 'is no longer a suite admin';
    case 'ADMIN_RECOVERY':
      return 'was unlocked and made a suite admin by the recovery script on the server';
    case 'TEMP_ACCESS_STARTED':
      return `gave themselves temporary ${role} access${
        line.until ? ` until ${manilaDateTime(line.until)} (Manila time)` : ''
      }`;
    case 'TEMP_ACCESS_ENDED_EARLY':
      return `no longer has temporary ${role} access (ended early)`;
    case 'SUITE_ROLE_GIVEN':
      return `was given the ${role} role by a suite admin`;
    case 'SUITE_ACCOUNT_CREATED':
      return `had a new account made for ${line.systemName ?? 'a system'} by a suite admin`;
    case 'PERMISSIONS_CHANGED':
      // Worded whole in alertSentence: the line is about a system, not a person
      return 'changed permissions';
  }
}

/** The plain sentence for one line, also used in the log. */
export function alertSentence(line: AlertLine): string {
  if (line.kind === 'PERMISSIONS_CHANGED') {
    const cells = line.cells ?? 0;
    return `${cells} ${cells === 1 ? 'permission was' : 'permissions were'} changed in the ${line.systemName ?? 'system'} permission matrix.`;
  }
  return `${line.targetName} (${line.targetEmail}) ${what(line)}.`;
}

export function adminAlertEmail(input: {
  recipientName: string;
  actorName: string;
  lines: AlertLine[];
  link: string;
}): Email {
  const first = input.lines[0];
  const subject =
    input.lines.length === 1
      ? first.kind === 'PERMISSIONS_CHANGED'
        ? `${BRAND} - Permissions changed in ${first.systemName ?? 'a system'}`
        : `${BRAND} - Admin change: ${first.targetName}`
      : `${BRAND} - ${input.lines.length} admin changes`;
  const details = (line: AlertLine) =>
    [
      `When: ${manilaDateTime(line.at)} (Manila time)`,
      `By: ${input.actorName}`,
      ...(line.reason ? [`Reason: ${line.reason}`] : []),
    ].join('\n');

  const text = [
    `Hello, ${input.recipientName || 'there'}!`,
    'You are getting this because you are an admin who would want to know about this change.',
    ...input.lines.map((line) => `${alertSentence(line)}\n${details(line)}`),
    `See it in the portal: ${input.link}`,
    "If you didn't expect this, check the account right away.",
  ].join('\n\n');

  const html = [
    `<p>Hello, <strong>${escapeHtml(input.recipientName || 'there')}</strong>!</p>`,
    '<p>You are getting this because you are an admin who would want to know about this change.</p>',
    ...input.lines.map(
      (line) =>
        `<p><strong>${escapeHtml(alertSentence(line))}</strong><br>${details(
          line,
        )
          .split('\n')
          .map(escapeHtml)
          .join('<br>')}</p>`,
    ),
    `<p><a href="${escapeHtml(input.link)}">See it in the portal</a></p>`,
    "<p>If you didn't expect this, check the account right away.</p>",
  ].join('\n');

  return { subject, text, html };
}

/** Systems a line concerns, for the recipient filter; `ALL` reaches every system's admins. */
export type AlertSystems = SystemType[] | 'ALL';
