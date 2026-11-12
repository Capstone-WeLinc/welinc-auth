import { NO_META, type RequestMeta } from '../events/request-meta';
import { Injectable } from '@nestjs/common';
import { VerificationPurpose } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { hashOpaque, isOpaqueShape, newOpaque } from '../sessions/opaque';
import { signInCodeEmail } from './code-emails';
import { CodeSendLimitError, codeExpired, invalidCode } from './code-errors';
import { CodeService } from './code.service';

/**
 * Why a right password still needs a code: an unverified email (spec 0009), or an admin's
 * portal sign in (spec 0013, AC-5). The ticket is the same either way and carries no admin flag.
 */
export type SignInStepStatus =
  | 'EMAIL_VERIFICATION_REQUIRED'
  | 'SIGN_IN_CODE_REQUIRED';

/** The `/auth/login` and `/auth/mobile/login` answer when a code is needed (AC-7, AC-11). */
export type EmailVerificationStep = {
  status: SignInStepStatus;
  challengeId: string;
  email: string;
  resendAfter: number;
};

const SIGN_IN = [VerificationPurpose.SIGN_IN] as const;

/**
 * Spec 0009: the sign in step. A right password on an unverified email answers a ticket
 * (`challengeId`) instead of a session; the ticket plus the emailed code finish the sign in. Only
 * `hashOpaque(ticket)` is stored, on the live `SIGN_IN` row. The routes are thin: the portal and
 * the mobile app share all of this.
 */
@Injectable()
export class SignInStepService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly codes: CodeService,
  ) {}

  /**
   * AC-7, AC-8: a new ticket on every right password. A fresh code is sent when the limits allow;
   * otherwise the ticket moves onto the live code and nothing is sent. No live code and no send
   * allowed: 429 `CODE_SEND_LIMIT`. A failed send: 503 `MAIL_FAILED` (`MailFailedError`).
   */
  async start(
    user: {
      id: string;
      name: string;
      email: string;
    },
    meta: RequestMeta = NO_META,
    status: SignInStepStatus = 'EMAIL_VERIFICATION_REQUIRED',
  ): Promise<EmailVerificationStep> {
    const ticket = newOpaque();
    const challengeHash = hashOpaque(ticket);
    const result = await this.codes.issue({
      userId: user.id,
      purpose: VerificationPurpose.SIGN_IN,
      challengeHash,
      meta,
      mail: {
        to: user.email,
        build: (code) => signInCodeEmail({ name: user.name, code }),
      },
      // The previous ticket stops working: the live row now carries this one
      onLimited: async (tx, live) => {
        if (live) {
          await tx.verificationCode.update({
            where: { id: live.id },
            data: { challengeHash },
          });
        }
      },
    });
    if (result.kind === 'limited' && !result.live) {
      throw new CodeSendLimitError(result.retryAfter);
    }
    return {
      status,
      challengeId: ticket,
      email: user.email,
      resendAfter: result.resendAfter,
    };
  }

  /**
   * AC-9 steps (1) to (4): find the live row by ticket (else 400 `CODE_EXPIRED`), run `precheck`
   * on the user (the account and systems checks, which count no try), check the code, then mark
   * it used and set `email_verified` in one transaction. Answers the user id; the caller finishes
   * the login (step 5).
   */
  async verify(
    challengeId: string,
    code: string,
    precheck: (userId: string) => Promise<void>,
    meta: RequestMeta = NO_META,
  ): Promise<string> {
    if (!isOpaqueShape(challengeId)) throw codeExpired();
    const result = await this.codes.check({
      target: { challengeHash: hashOpaque(challengeId) },
      code,
      consume: true,
      meta,
      precheck: async (_tx, row) => {
        if (row.purpose !== VerificationPurpose.SIGN_IN) throw codeExpired();
        await precheck(row.userId);
      },
      onRight: async (tx, row) => {
        await tx.user.update({
          where: { id: row.userId },
          data: { emailVerified: true },
        });
      },
    });
    if (result.kind === 'wrong') throw invalidCode(result.attemptsLeft);
    if (result.kind === 'dead') throw codeExpired();
    return result.row.userId;
  }

  /**
   * AC-10: a new code on the same ticket. A dead ticket: 400 `CODE_EXPIRED`. Inside the wait or
   * over the limit: 429 `CODE_SEND_LIMIT`. A failed send: 503, and the old code stays live.
   */
  async resend(
    challengeId: string,
    meta: RequestMeta = NO_META,
  ): Promise<{ resendAfter: number }> {
    if (!isOpaqueShape(challengeId)) throw codeExpired();
    const challengeHash = hashOpaque(challengeId);
    const row = await this.prisma.verificationCode.findFirst({
      where: {
        challengeHash,
        purpose: { in: [...SIGN_IN] },
        usedAt: null,
        expiresAt: { gt: new Date() },
      },
      select: {
        user: {
          select: {
            id: true,
            name: true,
            email: true,
            isActive: true,
            deletedAt: true,
          },
        },
      },
    });
    if (!row || !row.user.isActive || row.user.deletedAt) throw codeExpired();
    const { user } = row;
    const result = await this.codes.issue({
      userId: user.id,
      purpose: VerificationPurpose.SIGN_IN,
      challengeHash,
      meta,
      mail: {
        to: user.email,
        build: (code) => signInCodeEmail({ name: user.name, code }),
      },
    });
    if (result.kind === 'limited') {
      throw new CodeSendLimitError(result.retryAfter);
    }
    return { resendAfter: result.resendAfter };
  }
}
