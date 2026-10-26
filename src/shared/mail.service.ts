import { Injectable, Logger } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter | null = null;

  constructor() {
    const host = process.env.SMTP_HOST;
    const port = process.env.SMTP_PORT
      ? parseInt(process.env.SMTP_PORT, 10)
      : 587;
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;

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
    } else {
      this.logger.warn(
        'SMTP environment variables (SMTP_HOST, SMTP_USER, SMTP_PASS) not fully set. Mailer will log to console in development mode.',
      );
    }
  }

  /**
   * Sends the email, or throws when it can't be sent. Without SMTP it logs the email instead, in
   * development only: in production that would put codes in the logs (spec 0009, AC-16).
   */
  async sendMail(options: {
    to: string;
    subject: string;
    text: string;
    html?: string;
  }): Promise<void> {
    const from =
      process.env.SMTP_FROM || 'WeLinc Logistics <no-reply@welinc.com>';

    if (!this.transporter) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('SMTP is not configured');
      }
      this.logFallback(options);
      return;
    }

    await this.transporter.sendMail({
      from,
      to: options.to,
      subject: options.subject,
      text: options.text,
      html: options.html,
    });
    this.logger.log(`Email successfully sent to ${options.to}`);
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
