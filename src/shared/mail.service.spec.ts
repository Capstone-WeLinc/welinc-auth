import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { fakeConfig } from '../config/fake-config.setup';
import { isDevAddress } from './dev-email-domains';
import { MailService } from './mail.service';

// covers: spec 0009 AC-1 (the development log fallback); seed addresses never leave the machine

const SMTP = {
  SMTP_HOST: 'smtp.example.org',
  SMTP_PORT: '587',
  SMTP_USER: 'sender@example.org',
  SMTP_PASS: 'not-a-real-password',
};

/** A MailService whose SMTP transport is a spy, so nothing is sent. */
function build(overrides: Record<string, string | undefined>) {
  const service = new MailService(fakeConfig(overrides));
  const sendMail = jest.fn(() => Promise.resolve({}));
  (service as unknown as { transporter: unknown }).transporter = { sendMail };
  const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  return { service, sendMail, log };
}

const mail = (to: string) => ({
  to,
  subject: 'Your code',
  text: 'Code 123456',
  tag: 'user=u1 purpose=TEST',
});

afterEach(() => jest.restoreAllMocks());

describe('MailService', () => {
  it('logs mail to a seed address in development, even with SMTP on', async () => {
    const { service, sendMail, log } = build({
      ...SMTP,
      NODE_ENV: 'development',
    });
    await service.sendMail(mail('vrms.admin@WeLinc.com'));
    expect(sendMail).not.toHaveBeenCalled();
    expect(String(log.mock.calls[0]?.[0])).toContain('Code 123456');
  });

  it('sends mail to a real address through SMTP in development', async () => {
    const { service, sendMail } = build({ ...SMTP, NODE_ENV: 'development' });
    await service.sendMail(mail('someone@gmail.com'));
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({ to: 'someone@gmail.com' }),
    );
  });

  it('knows the made up seed domains and nothing else', () => {
    expect(isDevAddress('a@welinc.com')).toBe(true);
    expect(isDevAddress('a@example.com')).toBe(true);
    expect(isDevAddress('a@gmail.com')).toBe(false);
    expect(isDevAddress('a@welinc.com.ph')).toBe(false);
  });
});
