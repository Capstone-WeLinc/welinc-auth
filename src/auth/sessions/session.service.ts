import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  Prisma,
  SessionEndReason,
  SessionKind,
  SystemType,
  type Session,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { hashOpaque, isOpaqueShape, newOpaque } from './opaque';
import { SESSION_SETTINGS, type SessionSettings } from './session-config';

type Db = Prisma.TransactionClient | PrismaService;

/** The fields every cutoff check reads. */
type SessionTimes = Pick<
  Session,
  'endedAt' | 'idleExpiresAt' | 'absoluteExpiresAt'
>;

/** A live session plus the account fields a session check needs. */
export type LiveSession = Session & {
  user: {
    id: string;
    name: string;
    email: string;
    isActive: boolean;
    deletedAt: Date | null;
  };
};

const USER_FIELDS = {
  id: true,
  name: true,
  email: true,
  isActive: true,
  deletedAt: true,
} as const;

/** The session's expiry as answers report it: the earlier of the idle and absolute cutoffs. */
export function sessionExpiresAt(session: SessionTimes): Date {
  const idle = session.idleExpiresAt;
  const absolute = session.absoluteExpiresAt;
  return absolute && absolute < idle ? absolute : idle;
}

/**
 * Whether a session is past a cutoff it hasn't been ended for yet (spec 0003, AC-3). Absolute
 * first: a session past both ended because of its age.
 */
export function cutoffReason(
  session: SessionTimes,
  now: Date,
): SessionEndReason | null {
  if (session.endedAt) return null;
  if (session.absoluteExpiresAt && now >= session.absoluteExpiresAt) {
    return SessionEndReason.MAX_AGE;
  }
  if (now >= session.idleExpiresAt) return SessionEndReason.IDLE;
  return null;
}

/**
 * welinc-auth is the only writer of `sessions` (spec 0003, Key invariants). A session goes from
 * live to ended with one reason and never back.
 */
@Injectable()
export class SessionService {
  private readonly logger = new Logger('Sessions');

  constructor(
    private readonly prisma: PrismaService,
    @Inject(SESSION_SETTINGS) readonly settings: SessionSettings,
  ) {}

  /** `last_activity_at` + the idle limit for the session's kind. */
  idleCutoff(kind: SessionKind, from: Date): Date {
    const ms =
      kind === SessionKind.WEB
        ? this.settings.webIdleMinutes * 60_000
        : this.settings.mobileIdleDays * 86_400_000;
    return new Date(from.getTime() + ms);
  }

  /**
   * Ends a live session with a reason: kills its SSO handle and marks every unused refresh token
   * under it used, with no grace (AC-5). Ending an ended session changes nothing.
   */
  async end(
    db: Db,
    sessionId: string,
    reason: SessionEndReason,
    meta: { endedById?: string; clientId?: string } = {},
  ): Promise<boolean> {
    const now = new Date();
    const { count } = await db.session.updateMany({
      where: { id: sessionId, endedAt: null },
      data: {
        endedAt: now,
        endReason: reason,
        endedById: meta.endedById ?? null,
        ssoHandleHash: null,
      },
    });
    if (count === 0) return false;
    await db.refreshToken.updateMany({
      where: { sessionId, usedAt: null },
      data: { usedAt: now },
    });
    // AC-39: sid, user, reason and client only
    const row = await db.session.findUnique({
      where: { id: sessionId },
      select: { userId: true, loginClientId: true },
    });
    this.logger.log(
      `session ended sid=${sessionId} user=${row?.userId ?? '-'} reason=${reason} client=${meta.clientId ?? row?.loginClientId ?? '-'}`,
    );
    return true;
  }

  /** `end` outside a caller's transaction. */
  endNow(
    sessionId: string,
    reason: SessionEndReason,
    meta: { endedById?: string; clientId?: string } = {},
  ): Promise<boolean> {
    return this.prisma.$transaction((tx) =>
      this.end(tx, sessionId, reason, meta),
    );
  }

  /**
   * Loads a session and enforces its cutoffs on the spot (AC-3): a live row past a cutoff is
   * ended now. Answers the session only when it is live and its account is active.
   */
  async live(sessionId: string, now = new Date()): Promise<LiveSession | null> {
    const session = await this.prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: { select: USER_FIELDS } },
    });
    return this.checkLive(session, now);
  }

  /** The live session behind a `welinc_sso` handle, if any (AC-12). */
  async liveBySsoHandle(
    handle: unknown,
    now = new Date(),
  ): Promise<LiveSession | null> {
    if (!isOpaqueShape(handle)) return null;
    const session = await this.prisma.session.findUnique({
      where: { ssoHandleHash: hashOpaque(handle) },
      include: { user: { select: USER_FIELDS } },
    });
    return this.checkLive(session, now);
  }

  private async checkLive(
    session: LiveSession | null,
    now: Date,
  ): Promise<LiveSession | null> {
    if (!session || session.endedAt) return null;
    const reason = cutoffReason(session, now);
    if (reason) {
      await this.end(this.prisma, session.id, reason);
      return null;
    }
    // A deactivated or deleted account has no live session, even before M2 ends its rows
    if (!session.user.isActive || session.user.deletedAt) return null;
    return session;
  }

  /**
   * Creates a web session at login (AC-1, AC-6, AC-11). One transaction: a transaction scoped
   * advisory lock on the user, so two logins at once can't both pass the cap; the browser's
   * previous SSO session ends (`LOGOUT`); sessions already past a cutoff are ended; an 11th live
   * session ends the one with the oldest `last_activity_at` (`MAX_SESSIONS`). The SSO handle and
   * the session id are always new (session fixation).
   */
  async createWeb(input: {
    userId: string;
    userAgent: string | null;
    ip: string | null;
    previousHandle: unknown;
  }): Promise<{ session: Session; handle: string }> {
    const handle = newOpaque();
    const now = new Date();
    const session = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${input.userId}, 0))`;

      if (isOpaqueShape(input.previousHandle)) {
        const previous = await tx.session.findUnique({
          where: { ssoHandleHash: hashOpaque(input.previousHandle) },
          select: { id: true },
        });
        if (previous) {
          await this.end(tx, previous.id, SessionEndReason.LOGOUT);
        }
      }

      const open = await tx.session.findMany({
        where: { userId: input.userId, endedAt: null },
        orderBy: { lastActivityAt: 'asc' },
      });
      const live: Session[] = [];
      for (const row of open) {
        const reason = cutoffReason(row, now);
        if (reason) await this.end(tx, row.id, reason);
        else live.push(row);
      }
      const excess = live.length - (this.settings.maxSessionsPerUser - 1);
      for (const row of live.slice(0, Math.max(0, excess))) {
        await this.end(tx, row.id, SessionEndReason.MAX_SESSIONS);
      }

      return tx.session.create({
        data: {
          userId: input.userId,
          kind: SessionKind.WEB,
          loginClientId: 'portal',
          userAgent: input.userAgent?.slice(0, 512) ?? null,
          createdIp: input.ip,
          lastSeenIp: input.ip,
          ssoHandleHash: hashOpaque(handle),
          createdAt: now,
          lastActivityAt: now,
          idleExpiresAt: this.idleCutoff(SessionKind.WEB, now),
          absoluteExpiresAt: new Date(
            now.getTime() + this.settings.webMaxHours * 3_600_000,
          ),
        },
      });
    });
    this.logger.log(
      `session created sid=${session.id} user=${input.userId} kind=WEB client=portal`,
    );
    return { session, handle };
  }

  /**
   * Ends every live session of a user (AC-4): deactivation, deletion, an OTP reset, an admin
   * password set, or a password change that keeps the caller's own session (`exceptSid`).
   * Answers how many it ended.
   */
  async endAllForUser(
    db: Db,
    userId: string,
    reason: SessionEndReason,
    meta: { exceptSid?: string; endedById?: string } = {},
  ): Promise<number> {
    const rows = await db.session.findMany({
      where: {
        userId,
        endedAt: null,
        ...(meta.exceptSid ? { id: { not: meta.exceptSid } } : {}),
      },
      select: { id: true },
    });
    let ended = 0;
    for (const row of rows) {
      if (await this.end(db, row.id, reason, { endedById: meta.endedById })) {
        ended++;
      }
    }
    return ended;
  }

  /**
   * The session behind any refresh token row of `clientId`, used or not (AC-42). Logout and
   * activity use it and never run reuse detection; `inGrace` says whether a used token is still
   * inside its grace window.
   */
  async byRefreshToken(
    clientId: string,
    token: unknown,
    now = new Date(),
  ): Promise<{ sessionId: string; used: boolean; inGrace: boolean } | null> {
    if (!isOpaqueShape(token)) return null;
    const row = await this.prisma.refreshToken.findUnique({
      where: { tokenHash: hashOpaque(token) },
      select: {
        sessionId: true,
        clientId: true,
        usedAt: true,
        graceUntil: true,
      },
    });
    if (!row || row.clientId !== clientId) return null;
    return {
      sessionId: row.sessionId,
      used: row.usedAt !== null,
      inGrace:
        row.usedAt !== null && row.graceUntil !== null && now <= row.graceUntil,
    };
  }

  /** Whether `clientId` has ever held a refresh token in `sessionId` (logout by `sid`, AC-42). */
  async clientHoldsSession(
    clientId: string,
    sessionId: string,
  ): Promise<boolean> {
    const row = await this.prisma.refreshToken.findFirst({
      where: { sessionId, clientId },
      select: { id: true },
    });
    return row !== null;
  }

  /**
   * An activity ping (AC-2, AC-3): a live session moves its idle cutoff; a session past a cutoff
   * is ended by `live` first. Answers false when there is no live session to touch.
   */
  async recordActivity(
    sessionId: string,
    lastSeenIp: string | null,
    now = new Date(),
  ): Promise<boolean> {
    const session = await this.live(sessionId, now);
    if (!session) return false;
    await this.touch(this.prisma, session, now, lastSeenIp);
    return true;
  }

  /** Counts as activity: moves `last_activity_at` and the idle cutoff (never past the absolute). */
  async touch(
    db: Db,
    session: Session,
    now = new Date(),
    lastSeenIp: string | null = null,
  ): Promise<void> {
    await db.session.update({
      where: { id: session.id },
      data: {
        lastActivityAt: now,
        idleExpiresAt: this.idleCutoff(session.kind, now),
        ...(lastSeenIp ? { lastSeenIp } : {}),
      },
    });
  }

  /** Records each system an access token was signed for (`sessions.audiences`). */
  async addAudience(db: Db, sessionId: string, aud: SystemType): Promise<void> {
    await db.$executeRaw`UPDATE "sessions" SET "audiences" = array_append("audiences", ${aud}::"SystemType") WHERE "id" = ${sessionId}::uuid AND NOT (${aud}::"SystemType" = ANY("audiences"))`;
  }
}
