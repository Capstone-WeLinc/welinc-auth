import { VerificationPurpose } from '@prisma/client';
import { lifetimeText } from './code-config';

// Spec 0009, AC-24: every code and notice email, each with a text and an HTML part. Names and
// addresses are HTML escaped. The old address never receives a code.

export type Email = { subject: string; text: string; html: string };

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const BRAND = 'WeLinc Logistics';
const CODE_STYLE =
  'font-size: 24px; font-weight: bold; color: #1a1f6e; letter-spacing: 2px;';
const LINK_STYLE =
  'color: #1a1f6e; font-weight: bold; text-decoration: underline;';
const NOT_YOU =
  "If this wasn't you, change your password and tell your admin right away.";

const greet = (name: string) => `Hello, ${name || 'there'}!`;
const greetHtml = (name: string) =>
  `<p>Hello, <strong>${escapeHtml(name || 'there')}</strong>!</p>`;

/** Setup (60 min) or reset (10 min) code, with the portal link (AC-13). */
export function passwordCodeEmail(input: {
  purpose:
    | typeof VerificationPurpose.PASSWORD_SETUP
    | typeof VerificationPurpose.PASSWORD_RESET;
  name: string;
  code: string;
  link: string;
}): Email {
  const setup = input.purpose === VerificationPurpose.PASSWORD_SETUP;
  const lifetime = lifetimeText(input.purpose);
  const intro = setup
    ? `Welcome to ${BRAND}! An administrator created your account. Use this code to set your password.`
    : 'You asked to reset your password. Use this code to set a new one.';
  const action = setup ? 'Set up your password' : 'Reset your password';
  return {
    subject: setup
      ? `${BRAND} - Set up your account`
      : `${BRAND} - Reset your password`,
    text: `${greet(input.name)}

${intro}

${setup ? 'Setup' : 'Reset'} code: ${input.code}

${action} here:
${input.link}

This code expires in ${lifetime}. If you didn't ask for it, you can ignore this email.`,
    html: `${greetHtml(input.name)}
<p>${escapeHtml(intro)}</p>
<h2 style="${CODE_STYLE}">${input.code}</h2>
<p><a href="${escapeHtml(input.link)}" style="${LINK_STYLE}">${action}</a></p>
<p>This code expires in ${lifetime}. If you didn't ask for it, you can ignore this email.</p>`,
  };
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
  return {
    subject: input.admin
      ? `${BRAND} - Confirm it's you`
      : `${BRAND} - Your sign in code`,
    text: `${greet(input.name)}

${ask}

${input.code}

${after}`,
    html: `${greetHtml(input.name)}
<p>${escapeHtml(ask)}</p>
<h2 style="${CODE_STYLE}">${input.code}</h2>
<p>${escapeHtml(after)}</p>`,
  };
}

/** AC-17: the code sent to the new address. */
export function emailChangeCodeEmail(input: {
  name: string;
  code: string;
}): Email {
  const lifetime = lifetimeText(VerificationPurpose.EMAIL_CHANGE);
  return {
    subject: `${BRAND} - Confirm your new email`,
    text: `${greet(input.name)}

Type this code in WeLinc to make this your account's email:

${input.code}

It expires in ${lifetime}. If you didn't ask for this, ignore this email; nothing changes.`,
    html: `${greetHtml(input.name)}
<p>Type this code in WeLinc to make this your account's email:</p>
<h2 style="${CODE_STYLE}">${input.code}</h2>
<p>It expires in ${lifetime}. If you didn't ask for this, ignore this email; nothing changes.</p>`,
  };
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
