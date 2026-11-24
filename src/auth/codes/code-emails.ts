import { VerificationPurpose } from '@prisma/client';
import { lifetimeText } from './code-config';
import {
  codeEmailHtml,
  logoAttachment,
  TEXT_FOOTER,
  type EmailAttachment,
} from './email-layout';

// Spec 0009, AC-24: every code and notice email, each with a text and an HTML part. Names and
// addresses are HTML escaped. The old address never receives a code. Suite spec 0009 AC-34: no
// email holds a link or URL; Brevo rewrites links through a tracking domain some networks can't
// reach, so the portal is named by its host in plain text.

export type Email = {
  subject: string;
  text: string;
  html: string;
  /** The code emails' inline logo (suite spec 0019, AC-27); notices send none. */
  attachments?: EmailAttachment[];
};

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const BRAND = 'WeLinc Logistics';
const NOT_YOU =
  "If this wasn't you, change your password and tell your admin right away.";

const greet = (name: string) => `Hello, ${name || 'there'}!`;
const greetHtml = (name: string) =>
  `<p>Hello, <strong>${escapeHtml(name || 'there')}</strong>!</p>`;
/** The greeting inside the branded layout, which styles its own paragraphs. */
const greetInner = (name: string) =>
  `Hello, <strong>${escapeHtml(name || 'there')}</strong>!`;

/** Suite spec 0019, AC-27: a code email in the branded layout, the logo attached by CID. */
function codeEmail(input: {
  subject: string;
  title: string;
  text: string;
  before: string[];
  code: string;
  after: string[];
}): Email {
  return {
    subject: input.subject,
    text: `${input.text}\n\n${TEXT_FOOTER}`,
    html: codeEmailHtml(input),
    attachments: [logoAttachment()],
  };
}

/** Setup (60 min) or reset (10 min) code, naming the portal host in plain text (AC-13, AC-34). */
export function passwordCodeEmail(input: {
  purpose:
    | typeof VerificationPurpose.PASSWORD_SETUP
    | typeof VerificationPurpose.PASSWORD_RESET;
  name: string;
  code: string;
  portalHost: string;
}): Email {
  const setup = input.purpose === VerificationPurpose.PASSWORD_SETUP;
  const lifetime = lifetimeText(input.purpose);
  const intro = setup
    ? `Welcome to ${BRAND}! An administrator created your account. Use this code to set your password.`
    : 'You asked to reset your password. Use this code to set a new one.';
  const where = `Go to ${input.portalHost}, choose Forgot password, enter your email, then type this code. If you already have the reset page open, type it there.`;
  const expires = `This code expires in ${lifetime}. If you didn't ask for it, you can ignore this email.`;
  return codeEmail({
    subject: setup
      ? `${BRAND} - Set up your account`
      : `${BRAND} - Reset your password`,
    title: setup ? 'Set up your account' : 'Reset your password',
    text: `${greet(input.name)}

${intro}

${setup ? 'Setup' : 'Reset'} code: ${input.code}

${where}

${expires}`,
    before: [greetInner(input.name), escapeHtml(intro)],
    code: input.code,
    after: [escapeHtml(where), escapeHtml(expires)],
  });
}

/**
 * AC-7: the code that finishes a sign in on an unverified email. `admin` (spec 0013, AC-5 and the
 * step up): the email is already verified, so the code only confirms it's them.
 */
export function signInCodeEmail(input: {
  name: string;
  code: string;
  admin?: boolean;
}): Email {
  const lifetime = lifetimeText(VerificationPurpose.SIGN_IN);
  const ask = input.admin
    ? "Type this code to confirm it's you:"
    : 'Type this code to confirm your email and finish signing in:';
  const after = input.admin
    ? `It expires in ${lifetime}. If you didn't just sign in or open Admin, change your password and tell another admin right away.`
    : `It expires in ${lifetime}. If you didn't just sign in, change your password.`;
  return codeEmail({
    subject: input.admin
      ? `${BRAND} - Confirm it's you`
      : `${BRAND} - Your sign in code`,
    title: input.admin ? "Confirm it's you" : 'Your sign in code',
    text: `${greet(input.name)}

${ask}

${input.code}

${after}`,
    before: [greetInner(input.name), escapeHtml(ask)],
    code: input.code,
    after: [escapeHtml(after)],
  });
}

/** AC-17: the code sent to the new address. */
export function emailChangeCodeEmail(input: {
  name: string;
  code: string;
}): Email {
  const lifetime = lifetimeText(VerificationPurpose.EMAIL_CHANGE);
  const ask = "Type this code in WeLinc to make this your account's email:";
  const after = `It expires in ${lifetime}. If you didn't ask for this, ignore this email; nothing changes.`;
  return codeEmail({
    subject: `${BRAND} - Confirm your new email`,
    title: 'Confirm your new email',
    text: `${greet(input.name)}

${ask}

${input.code}

${after}`,
    before: [greetInner(input.name), escapeHtml(ask)],
    code: input.code,
    after: [escapeHtml(after)],
  });
}

/** AC-17, AC-24: to the old address, when your own change starts. */
export function emailChangeStartedEmail(input: {
  name: string;
  newEmail: string;
}): Email {
  return {
    subject: `${BRAND} - An email change was started`,
    text: `${greet(input.name)}

Someone signed in to your account asked to change its email to ${input.newEmail}. Your email stays the same until that address is confirmed.

${NOT_YOU}`,
    html: `${greetHtml(input.name)}
<p>Someone signed in to your account asked to change its email to <strong>${escapeHtml(input.newEmail)}</strong>. Your email stays the same until that address is confirmed.</p>
<p>${escapeHtml(NOT_YOU)}</p>`,
  };
}

/** AC-18, AC-24: to the old address, when your own change is done. */
export function emailChangedEmail(input: {
  name: string;
  newEmail: string;
}): Email {
  return {
    subject: `${BRAND} - Your email was changed`,
    text: `${greet(input.name)}

Your account's email is now ${input.newEmail}. This address no longer signs in.

${NOT_YOU}`,
    html: `${greetHtml(input.name)}
<p>Your account's email is now <strong>${escapeHtml(input.newEmail)}</strong>. This address no longer signs in.</p>
<p>${escapeHtml(NOT_YOU)}</p>`,
  };
}

/** AC-21, AC-24: to the old address, when an admin changed it. */
export function adminChangedEmailEmail(input: {
  name: string;
  newEmail: string;
}): Email {
  return {
    subject: `${BRAND} - An admin changed your email`,
    text: `${greet(input.name)}

An administrator changed your account's email to ${input.newEmail}. You'll confirm the new address the next time you sign in.

${NOT_YOU}`,
    html: `${greetHtml(input.name)}
<p>An administrator changed your account's email to <strong>${escapeHtml(input.newEmail)}</strong>. You'll confirm the new address the next time you sign in.</p>
<p>${escapeHtml(NOT_YOU)}</p>`,
  };
}
