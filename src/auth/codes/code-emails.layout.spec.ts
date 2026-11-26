import { VerificationPurpose } from '@prisma/client';
import {
  emailChangeCodeEmail,
  passwordCodeEmail,
  signInCodeEmail,
  type Email,
} from './code-emails';
import { EMAIL_LOGO_CID, FOOTER_BRAND } from './email-layout';

// covers: suite spec 0019 AC-27 (one branded layout for every code email, logo by CID)

const HOST = 'portal.welinc.test';
const CODE = '482913';

const CODE_EMAILS: Record<string, () => Email> = {
  setup: () =>
    passwordCodeEmail({
      purpose: VerificationPurpose.PASSWORD_SETUP,
      name: 'Carla Santos',
      code: CODE,
      portalHost: HOST,
    }),
  reset: () =>
    passwordCodeEmail({
      purpose: VerificationPurpose.PASSWORD_RESET,
      name: 'Carla Santos',
      code: CODE,
      portalHost: HOST,
    }),
  'sign in': () => signInCodeEmail({ name: 'Carla Santos', code: CODE }),
  'admin sign in': () =>
    signInCodeEmail({ name: 'Carla Santos', code: CODE, admin: true }),
  'email change': () =>
    emailChangeCodeEmail({ name: 'Carla Santos', code: CODE }),
};

describe.each(Object.entries(CODE_EMAILS))('the %s code email', (_, build) => {
  it('matches its HTML and text snapshots', () => {
    const mail = build();
    expect(mail.html).toMatchSnapshot('html');
    expect(mail.text).toMatchSnapshot('text');
  });

  it('attaches the logo as a PNG by CID and names it in text', () => {
    const mail = build();
    expect(mail.attachments).toHaveLength(1);
    const [logo] = mail.attachments!;
    expect(logo.cid).toBe(EMAIL_LOGO_CID);
    expect(logo.contentType).toBe('image/png');
    // The PNG signature
    expect(logo.content.subarray(0, 4).toString('hex')).toBe('89504e47');
    expect(mail.html).toContain(`src="cid:${EMAIL_LOGO_CID}"`);
    expect(mail.html).toContain('alt="WeLinc Logistics"');
  });

  it('holds no SVG, no data URI and no remote image', () => {
    const mail = build();
    expect(mail.html).not.toMatch(/<svg/i);
    expect(mail.html).not.toMatch(/data:/i);
    expect(mail.html).not.toMatch(/src="https?:/i);
  });

  it('shows the code once in a monospace face, and the same content in text', () => {
    const mail = build();
    expect(mail.html).toMatch(new RegExp(`monospace[^>]*>${CODE}<`));
    expect(mail.text).toContain(CODE);
    expect(mail.text).toContain(FOOTER_BRAND);
    expect(mail.html).toContain(FOOTER_BRAND);
  });
});
