import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type { Env } from '../config/env';
import { isDevAddress } from './dev-email-domains';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter | null = null;
  private readonly from: string;
  private readonly production: boolean;

  /** SMTP counts as on only when host, user and pass are all set; boot warns otherwise (spec 0010, AC-5). */
  constructor(config: ConfigService<Env, true>) {
    const host = config.get('SMTP_HOST', { infer: true });
    const port = config.get('SMTP_PORT', { infer: true });
    const user = config.get('SMTP_USER', { infer: true });
    const pass = config.get('SMTP_PASS', { infer: true });
    this.from = config.get('SMTP_FROM', { infer: true });
    this.production = config.get('NODE_ENV', { infer: true }) === 'production';

    if (host && user && pass) {
      this.transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: {
          user,
          pass,
        },
      });
      this.logger.log(`SMTP Mailer initialized on host ${host}:${port}`);
    }
  }

  /**
   * Sends the email, or throws when it can't be sent. In development it prints the whole email
   * instead when SMTP is off, or when the address is on a made up seed domain (`welinc.com` and the
   * rest of `DEV_EMAIL_DOMAINS`), so seed accounts get their codes while real addresses still go
   * through SMTP: the one log allowed to hold a code or an address (spec 0009, AC-1). The boot
   * check already requires SMTP in production; this throw is the second guard.
   */
  async sendMail(options: {
    to: string;
    subject: string;
    text: string;
    html?: string;
    /** What the log line names instead of the address: `user=<id> purpose=<kind>` (spec 0009, AC-1). */
    tag: string;
  }): Promise<void> {
    if (!this.production && isDevAddress(options.to)) {
      this.logFallback(options);
      return;
    }
    if (!this.transporter) {
      if (this.production) {
        throw new Error('SMTP is not configured');
      }
      this.logFallback(options);
      return;
    }

    await this.transporter.sendMail({
      from: this.from,
      to: options.to,
      subject: options.subject,
      text: options.text,
      html: options.html,
    });
    this.logger.log(`email sent ${options.tag}`);
  }

  private logFallback(options: { to: string; subject: string; text: string }) {
    const logMessage = `
==================================================
📬  [DEVELOPMENT MAIL FALLBACK]
Date:    ${new Date().toISOString()}
To:      ${options.to}
Subject: ${options.subject}
Content:
${options.text}
==================================================
`;
    console.log(logMessage);
  }
}
