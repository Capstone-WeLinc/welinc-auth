import {
  accountClosedEmail,
  accountClosedForAdminsEmail,
  accountRestoredEmail,
  dataErasedEmail,
  manilaDate,
  requestCancelledEmail,
  requestForAdminsEmail,
  requestReceivedEmail,
  requestRejectedEmail,
} from './deletion-emails';

// covers: spec 0012 Emails (a text and an html part each, escaped, Manila dates)

const EVIL = '<script>alert("x")</script>';

describe('manilaDate', () => {
  it('uses the Manila day, not the UTC day', () => {
    // 20:00 UTC on the 12th is already the 13th in Manila (UTC+8)
    expect(manilaDate(new Date('2026-11-12T20:00:00.000Z'))).toBe(
      'November 13, 2026',
    );
  });
});

describe('deletion emails', () => {
  it('give every notice a subject, a text part and an html part', () => {
    const emails = [
      requestReceivedEmail({ name: 'Ana' }),
      requestCancelledEmail({ name: 'Ana' }),
      requestRejectedEmail({ name: 'Ana', note: 'Not now' }),
      accountRestoredEmail({ name: 'Ana' }),
      accountClosedEmail({ name: 'Ana', eraseAfter: new Date() }),
      dataErasedEmail(),
    ];
    for (const e of emails) {
      expect(e.subject).toContain('WeLinc Logistics');
      expect(e.text.length).toBeGreaterThan(0);
      expect(e.html).toContain('<p>');
    }
  });

  it('greets by name and falls back to there for a blank name', () => {
    expect(requestReceivedEmail({ name: 'Ana' }).text).toContain('Hello, Ana!');
    expect(requestReceivedEmail({ name: '' }).text).toContain('Hello, there!');
  });

  it('escapes names and reason for admins in the html part, and holds no link (0009 AC-34)', () => {
    const e = requestForAdminsEmail({
      adminName: EVIL,
      personName: EVIL,
      personEmail: 'a@welinc.com',
      reason: EVIL,
    });
    expect(e.html).not.toContain('<script>');
    expect(e.html).toContain('&lt;script&gt;');
    expect(e.html).not.toContain('<a');
    expect(e.text).toContain('Users page of your system.');
  });

  it('says no reason was given when there is none', () => {
    const e = requestForAdminsEmail({
      adminName: 'Bo',
      personName: 'Ana',
      personEmail: 'a@welinc.com',
      reason: null,
    });
    expect(e.text).toContain('No reason given.');
  });

  it('quotes the admin note on a rejection and escapes it in html', () => {
    const e = requestRejectedEmail({ name: 'Ana', note: EVIL });
    expect(e.text).toContain(`"${EVIL}"`);
    expect(e.html).not.toContain('<script>');
  });

  it('puts the erase date in Manila time in the closed notices', () => {
    const eraseAfter = new Date('2026-12-12T20:00:00.000Z');
    expect(accountClosedEmail({ name: 'Ana', eraseAfter }).text).toContain(
      'December 13, 2026',
    );
    expect(
      accountClosedForAdminsEmail({
        adminName: 'Bo',
        personName: 'Ana',
        personEmail: 'a@welinc.com',
        deciderName: 'Cy',
        eraseAfter,
      }).text,
    ).toContain('December 13, 2026');
  });

  it('names nobody in the erased notice', () => {
    const e = dataErasedEmail();
    expect(e.text.startsWith('Hello,\n')).toBe(true);
  });
});
