import { describe, expect, it } from '@jest/globals';
import { VerificationPurpose } from '@prisma/client';
import { CODE_LIFETIME_MS, familyOf, lifetimeText } from './code-config';
import {
  adminChangedEmailEmail,
  emailChangeStartedEmail,
  escapeHtml,
  passwordCodeEmail,
  signInCodeEmail,
} from './code-emails';
import { newOtp } from './code.service';
import { attemptsLeft, resendAfter, sendDecision } from './send-limit';

// covers: suite spec 0009 AC-1, AC-2, AC-3, AC-4, AC-5 (the pure rules), AC-24 (the emails)

const NOW = new Date('2026-11-11T08:00:00.000Z');
const ago = (seconds: number) => new Date(NOW.getTime() - seconds * 1000);

describe('code config', () => {
  it('gives setup an hour and the rest 10 minutes', () => {
    expect(CODE_LIFETIME_MS.PASSWORD_SETUP).toBe(3_600_000);
    expect(CODE_LIFETIME_MS.PASSWORD_RESET).toBe(600_000);
    expect(CODE_LIFETIME_MS.SIGN_IN).toBe(600_000);
    expect(CODE_LIFETIME_MS.EMAIL_CHANGE).toBe(600_000);
    expect(lifetimeText(VerificationPurpose.PASSWORD_SETUP)).toBe('1 hour');
    expect(lifetimeText(VerificationPurpose.SIGN_IN)).toBe('10 minutes');
  });

  it('puts setup and reset in one family and the others alone', () => {
    expect(familyOf(VerificationPurpose.PASSWORD_RESET)).toContain(
      VerificationPurpose.PASSWORD_SETUP,
    );
    expect(familyOf(VerificationPurpose.SIGN_IN)).toEqual([
      VerificationPurpose.SIGN_IN,
    ]);
    expect(familyOf(VerificationPurpose.EMAIL_CHANGE)).toEqual([
      VerificationPurpose.EMAIL_CHANGE,
    ]);
  });

  it('makes 6 digit codes', () => {
    for (let i = 0; i < 50; i++) expect(newOtp()).toMatch(/^\d{6}$/);
  });
});

describe('sendDecision', () => {
  it('allows the first send', () => {
    expect(sendDecision([], NOW)).toEqual({ allowed: true });
  });

  it('refuses inside 60 s with the seconds left', () => {
    expect(sendDecision([ago(20)], NOW)).toEqual({
      allowed: false,
      reason: 'wait',
      retryAfter: 40,
    });
  });

  it('allows a send once 60 s have passed', () => {
    expect(sendDecision([ago(60)], NOW)).toEqual({ allowed: true });
  });

  it('refuses a 6th send in the hour until the oldest of the last 5 is an hour old', () => {
    const five = [ago(3000), ago(2400), ago(1800), ago(1200), ago(600)];
    expect(sendDecision(five, NOW)).toEqual({
      allowed: false,
      reason: 'hourly',
      retryAfter: 600,
    });
  });

  it('ignores sends older than an hour', () => {
    const old = [ago(4000), ago(3700), ago(3650), ago(3610), ago(3601)];
    expect(sendDecision(old, NOW)).toEqual({ allowed: true });
  });

  it('never answers a Retry-After below 1', () => {
    const decision = sendDecision([new Date(NOW.getTime() - 59_999)], NOW);
    expect(decision).toMatchObject({ retryAfter: 1 });
  });
});

describe('resendAfter and attemptsLeft', () => {
  it('counts down from 60 and stops at 0', () => {
    expect(resendAfter(null, NOW)).toBe(0);
    expect(resendAfter(ago(15), NOW)).toBe(45);
    expect(resendAfter(ago(90), NOW)).toBe(0);
  });

  it('answers 5 minus the tries', () => {
    expect(attemptsLeft(1)).toBe(4);
    expect(attemptsLeft(5)).toBe(0);
    expect(attemptsLeft(7)).toBe(0);
  });
});

describe('code emails', () => {
  const sneaky = '<b>Pedro</b> & "co"';

  it('escapes names and addresses in the HTML part', () => {
    expect(escapeHtml(sneaky)).toBe(
      '&lt;b&gt;Pedro&lt;/b&gt; &amp; &quot;co&quot;',
    );
    const mail = emailChangeStartedEmail({
      name: sneaky,
      newEmail: 'x<script>@a.com',
    });
    expect(mail.html).not.toContain('<b>Pedro');
    expect(mail.html).not.toContain('<script>');
    expect(mail.text).toContain('x<script>@a.com');
  });

  it("words an admin's code as confirming it's them, not their email", () => {
    const admin = signInCodeEmail({ name: 'P', code: '123456', admin: true });
    expect(admin.subject).toContain("Confirm it's you");
    expect(admin.text).not.toContain('confirm your email');
    expect(admin.html).toContain('123456');
    const verify = signInCodeEmail({ name: 'P', code: '123456' });
    expect(verify.text).toContain('confirm your email');
  });

  it('states the lifetime in every code email', () => {
    expect(signInCodeEmail({ name: 'P', code: '123456' }).text).toContain(
      '10 minutes',
    );
    expect(
      passwordCodeEmail({
        purpose: VerificationPurpose.PASSWORD_SETUP,
        name: 'P',
        code: '123456',
        link: 'https://portal/forgot-password',
      }).text,
    ).toContain('1 hour');
  });

  it('never puts a code in a notice to the old address, and tells them what to do', () => {
    for (const mail of [
      emailChangeStartedEmail({ name: 'P', newEmail: 'n@a.com' }),
      adminChangedEmailEmail({ name: 'P', newEmail: 'n@a.com' }),
    ]) {
      expect(mail.text).not.toMatch(/\b\d{6}\b/);
      expect(mail.text).toContain('n@a.com');
    }
    expect(
      emailChangeStartedEmail({ name: 'P', newEmail: 'n@a.com' }).text,
    ).toContain("If this wasn't you, change your password and tell your admin");
  });
});
