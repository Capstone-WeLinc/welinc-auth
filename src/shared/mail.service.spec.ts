import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { fakeConfig } from '../config/fake-config.setup';
import { isDevAddress, seedMailRecipient } from './dev-email-domains';
import { MailService } from './mail.service';

// covers: spec 0009 AC-1 (the development log fallback), AC-32 (seed mail logged on staging), AC-33
// (seed mail to the team inbox on staging); seed addresses never reach welinc.com

const SMTP = {
  SMTP_HOST: 'smtp.example.org',
  SMTP_PORT: '587',
  SMTP_USER: 'sender@example.org',
  SMTP_PASS: 'not-a-real-password',
};

/** A MailService whose SMTP transport is a spy, so nothing is sent. */
function build(overrides: Record<string, string | undefined>) {
  const service = new MailService(fakeConfig(overrides));
  const sendMail = jest.fn<(options: unknown) => Promise<unknown>>(() =>
    Promise.resolve({}),
  );
  (service as unknown as { transporter: unknown }).transporter = { sendMail };
  const log = jest.spyOn(console, 'log').mockImplementation(() => undefined);
  return { service, sendMail, log };
}

/** The production settings the boot check needs, as on staging and production. */
const HOSTED = {
  ...SMTP,
  NODE_ENV: 'production',
  TRUST_PROXY_HOPS: '2',
  SSO_COOKIE_SECURE: 'true',
  CORS_ORIGINS: 'https://portal.welinc.test',
  PORTAL_URL: 'https://portal.welinc.test',
  AUTH_ISSUER: 'https://api.welinc.test/auth',
};

const mail = (to: string) => ({
  to,
  subject: 'Your code',
  text: 'Code 123456',
  tag: 'user=u1 purpose=TEST',
});

afterEach(() => {
  jest.restoreAllMocks();
});

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

  it('logs mail to a seed address on staging (SEED_MAIL_TO_LOG), never sends it', async () => {
    const { service, sendMail, log } = build({
      ...HOSTED,
      SEED_MAIL_TO_LOG: 'true',
    });
    await service.sendMail(mail('vrms.admin@welinc.com'));
    expect(sendMail).not.toHaveBeenCalled();
    expect(String(log.mock.calls[0]?.[0])).toContain('Code 123456');
  });

  it('still sends mail to a real address on staging', async () => {
    const { service, sendMail } = build({
      ...HOSTED,
      SEED_MAIL_TO_LOG: 'true',
    });
    await service.sendMail(mail('someone@gmail.com'));
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({ to: 'someone@gmail.com' }),
    );
  });

  it('sends mail to a seed address in production without SEED_MAIL_TO_LOG', async () => {
    const { service, sendMail, log } = build(HOSTED);
    await service.sendMail(mail('vrms.admin@welinc.com'));
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({ to: 'vrms.admin@welinc.com' }),
    );
    expect(log).not.toHaveBeenCalled();
  });

  it('sends seed mail to the team inbox on staging (SEED_MAIL_REDIRECT), not the log', async () => {
    const { service, sendMail, log } = build({
      ...HOSTED,
      SEED_MAIL_TO_LOG: 'true',
      SEED_MAIL_REDIRECT: 'welinc.demo+{tag}@gmail.com',
    });
    await service.sendMail(mail('vrms.admin@welinc.com'));
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({
        to: 'welinc.demo+vrms.admin@gmail.com',
        subject: 'Your code',
        text: 'Code 123456',
      }),
    );
    expect(log).not.toHaveBeenCalled();
  });

  it('sends a real address as is while SEED_MAIL_REDIRECT is set', async () => {
    const { service, sendMail } = build({
      ...HOSTED,
      SEED_MAIL_REDIRECT: 'welinc.demo+{tag}@gmail.com',
    });
    await service.sendMail(mail('someone@gmail.com'));
    expect(sendMail).toHaveBeenCalledWith(
      expect.objectContaining({ to: 'someone@gmail.com' }),
    );
  });

  it('falls back to the log when SEED_MAIL_REDIRECT is set but SMTP is off', async () => {
    const { service, sendMail, log } = build({
      ...HOSTED,
      SEED_MAIL_TO_LOG: 'true',
      SEED_MAIL_REDIRECT: 'welinc.demo+{tag}@gmail.com',
    });
    (service as unknown as { transporter: unknown }).transporter = null;
    await service.sendMail(mail('vrms.admin@welinc.com'));
    expect(sendMail).not.toHaveBeenCalled();
    expect(String(log.mock.calls[0]?.[0])).toContain('Code 123456');
  });

  it('builds the team inbox tag from the seed name', () => {
    const t = 'team+{tag}@gmail.com';
    expect(seedMailRecipient('VRMS.Admin@welinc.com', t)).toBe(
      'team+vrms.admin@gmail.com',
    );
    expect(seedMailRecipient('a+b c@welinc.com', t)).toBe(
      'team+a-b-c@gmail.com',
    );
    expect(seedMailRecipient(`${'x'.repeat(60)}@welinc.com`, t)).toBe(
      `team+${'x'.repeat(40)}@gmail.com`,
    );
  });

  it('knows the made up seed domains and nothing else', () => {
    expect(isDevAddress('a@welinc.com')).toBe(true);
    expect(isDevAddress('a@example.com')).toBe(true);
    expect(isDevAddress('a@gmail.com')).toBe(false);
    expect(isDevAddress('a@welinc.com.ph')).toBe(false);
  });
});
