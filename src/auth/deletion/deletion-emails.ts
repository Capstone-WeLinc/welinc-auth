import { escapeHtml, type Email } from '../codes/code-emails';

// Spec 0012, Emails: every deletion notice, a text and an HTML part each, names and notes HTML
// escaped, dates in Asia/Manila like every suite email. Sent after commit; a failure is logged.

const BRAND = 'WeLinc Logistics';

const greet = (name: string) => `Hello, ${name || 'there'}!`;
const greetHtml = (name: string) =>
  `<p>Hello, <strong>${escapeHtml(name || 'there')}</strong>!</p>`;

/** A date as people in the suite read it: "November 12, 2026" in Asia/Manila. */
export function manilaDate(at: Date): string {
  return new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Manila',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  }).format(at);
}

const paragraphs = (name: string, lines: string[]): Email['text'] =>
  [greet(name), ...lines].join('\n\n');
const paragraphsHtml = (name: string, lines: string[]): Email['html'] =>
  [greetHtml(name), ...lines.map((line) => `<p>${line}</p>`)].join('\n');

/** To the person: the request was saved. */
export function requestReceivedEmail(input: { name: string }): Email {
  const lines = [
    'We received your request to delete your WeLinc account. An admin of your systems reviews it.',
    'Until then your account works as usual. You can cancel the request from your profile.',
    "If this wasn't you, change your password and tell your admin right away.",
  ];
  return {
    subject: `${BRAND} - We received your deletion request`,
    text: paragraphs(input.name, lines),
    html: paragraphsHtml(input.name, lines.map(escapeHtml)),
  };
}

/** To each admin of the person's systems: someone asked, with their reason quoted. */
export function requestForAdminsEmail(input: {
  adminName: string;
  personName: string;
  personEmail: string;
  reason: string | null;
  reviewLink: string;
}): Email {
  const who = `${input.personName} (${input.personEmail})`;
  const reason = input.reason ? `"${input.reason}"` : 'No reason given.';
  return {
    subject: `${BRAND} - ${input.personName} asked to delete their account`,
    text: paragraphs(input.adminName, [
      `${who} asked to delete their account.`,
      `Their reason: ${reason}`,
      `Review it on the Users page of your system: ${input.reviewLink}`,
    ]),
    html: paragraphsHtml(input.adminName, [
      `<strong>${escapeHtml(who)}</strong> asked to delete their account.`,
      `Their reason: ${escapeHtml(reason)}`,
      `Review it on the Users page of your system: <a href="${escapeHtml(input.reviewLink)}">${escapeHtml(input.reviewLink)}</a>`,
    ]),
  };
}

/** To the person: their pending request was cancelled. */
export function requestCancelledEmail(input: { name: string }): Email {
  const lines = [
    'Your request to delete your WeLinc account was cancelled. Your account stays as it is.',
  ];
  return {
    subject: `${BRAND} - Your deletion request was cancelled`,
    text: paragraphs(input.name, lines),
    html: paragraphsHtml(input.name, lines.map(escapeHtml)),
  };
}

/** To the person: an admin said no, with the note quoted. */
export function requestRejectedEmail(input: {
  name: string;
  note: string;
}): Email {
  const lines = [
    'Your request to delete your WeLinc account was not approved.',
    `The admin's note: "${input.note}"`,
    'You can ask again from your profile at any time.',
  ];
  return {
    subject: `${BRAND} - Your deletion request was not approved`,
    text: paragraphs(input.name, lines),
    html: paragraphsHtml(input.name, lines.map(escapeHtml)),
  };
}

/** To the person: the account is closed, and when the data goes. */
export function accountClosedEmail(input: {
  name: string;
  eraseAfter: Date;
}): Email {
  const lines = [
    'Your WeLinc account is closed. You can no longer sign in.',
    `Your personal data will be erased on ${manilaDate(input.eraseAfter)}.`,
    'If this is a mistake, contact an admin of your systems before then to restore it.',
  ];
  return {
    subject: `${BRAND} - Your account was deleted`,
    text: paragraphs(input.name, lines),
    html: paragraphsHtml(input.name, lines.map(escapeHtml)),
  };
}

/** To the other admins of the person's systems: who was deleted, by whom, and when it erases. */
export function accountClosedForAdminsEmail(input: {
  adminName: string;
  personName: string;
  personEmail: string;
  deciderName: string;
  eraseAfter: Date;
}): Email {
  const lines = [
    `${input.deciderName} deleted the account of ${input.personName} (${input.personEmail}).`,
    `Their personal data will be erased on ${manilaDate(input.eraseAfter)}. Until then an admin can restore the account from the Users page.`,
  ];
  return {
    subject: `${BRAND} - ${input.personName}'s account was deleted`,
    text: paragraphs(input.adminName, lines),
    html: paragraphsHtml(input.adminName, lines.map(escapeHtml)),
  };
}

/** To the person: restored, still off until an admin turns it on. */
export function accountRestoredEmail(input: { name: string }): Email {
  const lines = [
    'Your WeLinc account was restored. Your personal data will not be erased.',
    'It stays turned off until an admin of your systems turns it on again.',
  ];
  return {
    subject: `${BRAND} - Your account was restored`,
    text: paragraphs(input.name, lines),
    html: paragraphsHtml(input.name, lines.map(escapeHtml)),
  };
}

/** To the old address, after the erasure. Names nobody: the name is already gone. */
export function dataErasedEmail(): Email {
  const lines = [
    'The personal data of your former WeLinc account was erased: your name, email, phone and picture are gone, and records that mention you now say "Deleted user".',
    'You will get no more emails from us at this address.',
  ];
  return {
    subject: `${BRAND} - Your personal data was erased`,
    text: ['Hello,', ...lines].join('\n\n'),
    html: [
      '<p>Hello,</p>',
      ...lines.map((l) => `<p>${escapeHtml(l)}</p>`),
    ].join('\n'),
  };
}
