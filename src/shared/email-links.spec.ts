// Suite spec 0009, AC-34: no email holds a link or URL the builder adds. Brevo rewrites every
// link through its click tracking domain, which some networks can't reach, so emails name the
// portal by its host in plain text. Every builder is in BUILDERS; the guard below fails when a
// new exported function is neither there nor a known helper, so a new email can't skip this test.
import { VerificationPurpose } from '@prisma/client';
import * as codeEmails from '../auth/codes/code-emails';
import * as alertEmails from '../auth/admin/admin-alert-emails';
import type {
  AdminAlertKind,
  AlertLine,
} from '../auth/admin/admin-alert-emails';
import * as deletionEmails from '../auth/deletion/deletion-emails';
import type { Email } from '../auth/codes/code-emails';
import { portalHostOf } from './portal-host';

const HOST = 'portal.welinc.test';
const EVIL = '<b>Ana & "Bo"</b>';
const AT = new Date('2026-11-20T04:16:00.000Z');

const ALERT_KINDS: AdminAlertKind[] = [
  'ADMIN_ROLE_ADDED',
  'ADMIN_ROLE_REMOVED',
  'ADMIN_EMAIL_CHANGED',
  'ADMIN_CODE_SENT',
  'ADMIN_UNLOCKED',
  'ADMIN_SESSIONS_ENDED',
  'SUITE_ADMIN_ADDED',
  'SUITE_ADMIN_REMOVED',
  'ADMIN_RECOVERY',
  'TEMP_ACCESS_STARTED',
  'TEMP_ACCESS_ENDED_EARLY',
  'SUITE_ROLE_GIVEN',
  'SUITE_ACCOUNT_CREATED',
  'PERMISSIONS_CHANGED',
];

const line = (kind: AdminAlertKind): AlertLine => ({
  kind,
  targetName: EVIL,
  targetEmail: 'ana@welinc.com',
  systemName: 'VRMS',
  roleName: 'Admin',
  until: AT,
  at: AT,
  reason: EVIL,
  cells: 3,
});

/** Every email builder in the three files, each with sample inputs. */
const BUILDERS: Record<string, () => Email[]> = {
  passwordCodeEmail: () =>
    [
      VerificationPurpose.PASSWORD_SETUP,
      VerificationPurpose.PASSWORD_RESET,
    ].map((purpose) =>
      codeEmails.passwordCodeEmail({
        purpose,
        name: EVIL,
        code: '123456',
        portalHost: HOST,
      }),
    ),
  signInCodeEmail: () => [
    codeEmails.signInCodeEmail({ name: EVIL, code: '123456' }),
    codeEmails.signInCodeEmail({ name: EVIL, code: '123456', admin: true }),
  ],
  emailChangeCodeEmail: () => [
    codeEmails.emailChangeCodeEmail({ name: EVIL, code: '123456' }),
  ],
  emailChangeStartedEmail: () => [
    codeEmails.emailChangeStartedEmail({ name: EVIL, newEmail: 'n@a.com' }),
  ],
  emailChangedEmail: () => [
    codeEmails.emailChangedEmail({ name: EVIL, newEmail: 'n@a.com' }),
  ],
  adminChangedEmailEmail: () => [
    codeEmails.adminChangedEmailEmail({ name: EVIL, newEmail: 'n@a.com' }),
  ],
  adminAlertEmail: () => [
    ...ALERT_KINDS.map((kind) =>
      alertEmails.adminAlertEmail({
        recipientName: EVIL,
        actorName: EVIL,
        lines: [line(kind)],
        portalHost: HOST,
      }),
    ),
    alertEmails.adminAlertEmail({
      recipientName: '',
      actorName: 'WeLinc (automatic)',
      lines: ALERT_KINDS.map(line),
      portalHost: HOST,
    }),
  ],
  requestReceivedEmail: () => [
    deletionEmails.requestReceivedEmail({ name: EVIL }),
  ],
  requestForAdminsEmail: () => [
    deletionEmails.requestForAdminsEmail({
      adminName: EVIL,
      personName: EVIL,
      personEmail: 'ana@welinc.com',
      reason: EVIL,
    }),
    deletionEmails.requestForAdminsEmail({
      adminName: '',
      personName: 'Ana',
      personEmail: 'ana@welinc.com',
      reason: null,
    }),
  ],
  requestCancelledEmail: () => [
    deletionEmails.requestCancelledEmail({ name: EVIL }),
  ],
  requestRejectedEmail: () => [
    deletionEmails.requestRejectedEmail({ name: EVIL, note: EVIL }),
  ],
  accountClosedEmail: () => [
    deletionEmails.accountClosedEmail({ name: EVIL, eraseAfter: AT }),
  ],
  accountClosedForAdminsEmail: () => [
    deletionEmails.accountClosedForAdminsEmail({
      adminName: EVIL,
      personName: EVIL,
      personEmail: 'ana@welinc.com',
      deciderName: EVIL,
      eraseAfter: AT,
    }),
  ],
  accountRestoredEmail: () => [
    deletionEmails.accountRestoredEmail({ name: EVIL }),
  ],
  dataErasedEmail: () => [deletionEmails.dataErasedEmail()],
};

/** Exported functions that build no email. */
const HELPERS = ['escapeHtml', 'manilaDate', 'manilaDateTime', 'alertSentence'];

describe('emails hold no link (suite spec 0009, AC-34)', () => {
  it('lists every exported function as a builder or a known helper', () => {
    const exported = [codeEmails, alertEmails, deletionEmails].flatMap((m) =>
      Object.entries(m)
        .filter(([, value]) => typeof value === 'function')
        .map(([name]) => name),
    );
    const unknown = exported.filter(
      (name) => !(name in BUILDERS) && !HELPERS.includes(name),
    );
    expect(unknown).toEqual([]);
  });

  it.each(Object.keys(BUILDERS))(
    '%s adds no <a tag and no http URL in either part',
    (name) => {
      for (const mail of BUILDERS[name]()) {
        expect(mail.html).not.toContain('<a');
        for (const part of [mail.text, mail.html]) {
          expect(part).not.toMatch(/https?:\/\//);
        }
      }
    },
  );

  it('setup and reset name the portal host and Forgot password in both parts', () => {
    for (const mail of BUILDERS.passwordCodeEmail()) {
      for (const part of [mail.text, mail.html]) {
        expect(part).toContain(
          `Go to ${HOST}, choose Forgot password, enter your email, then type this code.`,
        );
      }
    }
  });

  it('the admin alert names the portal host and Admin in both parts', () => {
    const [mail] = BUILDERS.adminAlertEmail();
    for (const part of [mail.text, mail.html]) {
      expect(part).toContain(`See it in the portal at ${HOST}, under Admin.`);
    }
  });

  it('the deletion request to admins names the Users page', () => {
    const [mail] = BUILDERS.requestForAdminsEmail();
    for (const part of [mail.text, mail.html]) {
      expect(part).toContain('Review it on the Users page of your system.');
    }
  });
});

describe('portalHostOf (suite spec 0009, AC-34)', () => {
  it('keeps the port and drops the scheme and path', () => {
    expect(portalHostOf('http://localhost:8000')).toBe('localhost:8000');
    expect(portalHostOf('https://staging-portal.welinc.app/')).toBe(
      'staging-portal.welinc.app',
    );
  });
});
