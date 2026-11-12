import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  AccountEventType,
  Prisma,
  SessionEndReason,
  SessionKind,
  SystemType,
  type Session,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { hashOpaque, isOpaqueShape, newOpaque } from './opaque';
import { SESSION_SETTINGS, type SessionSettings } from './session-config';
import { deviceLabel } from './device-label';
import { AccountEventsService } from '../events/account-events.service';
import { normaliseIp, type RequestMeta } from '../events/request-meta';

/** Who and what ended a session, for its event (spec 0011, AC-4, Field visibility). */
export type SessionEndMeta = {
  endedById?: string;
  clientId?: string;
  /** The admin's system (`aud`), tagged on ADMIN_ENDED, DEACTIVATED and DELETED ends. */
  system?: SystemType;
  /** The address of the person whose request ended it; null for backends and the sweeper. */
  ip?: string | null;
};

/** Ends an admin causes: tagged with the admin's system. */
const ADMIN_REASONS = new Set<SessionEndReason>([
  SessionEndReason.ADMIN_ENDED,
  SessionEndReason.DEACTIVATED,
  SessionEndReason.DELETED,
]);

/** Ends the person causes. */
const SELF_REASONS = new Set<SessionEndReason>([
  SessionEndReason.LOGOUT,
  SessionEndReason.USER_ENDED,
  SessionEndReason.PASSWORD_CHANGED,
]);

/**
 * The actor of a session end (spec 0011): the user for LOGOUT, USER_ENDED and PASSWORD_CHANGED,
 * the admin for ADMIN_ENDED, DEACTIVATED and DELETED, nobody for IDLE, MAX_AGE, MAX_SESSIONS,
 * REFRESH_REUSE and CODE_REUSE.
 */
export function endActor(
  reason: SessionEndReason,
  userId: string,
  endedById: string | undefined,
): string | null {
  if (SELF_REASONS.has(reason)) return userId;
  if (ADMIN_REASONS.has(reason)) return endedById ?? null;
  return null;
}

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
    profilePicture: string | null;
    isActive: boolean;
    deletedAt: Date | null;
  };
};

const USER_FIELDS = {
  id: true,
  name: true,
  email: true,
  profilePicture: true,
  isActive: true,
  deletedAt: true,
} as const;

/** One session in a sessions list (spec 0003, AC-31, AC-34, AC-35). */
export type SessionView = {
  sid: string;
  kind: 'web' | 'mobile';
  device: string;
  client: string;
  systems: SystemType[];
  createdAt: string;
  lastActiveAt: string;
  current?: boolean;
};

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
    private readonly events: AccountEventsService,
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
   * under it used, with no grace (AC-5). Ending an ended session changes nothing. Spec 0011,
   * AC-4: writes exactly one `SIGNED_OUT` (for `LOGOUT`) or `SESSION_ENDED` in the same
   * transaction, only when its update changed the row; handed the bare client, it opens its own.
   */
  async end(
    db: Db,
    sessionId: string,
    reason: SessionEndReason,
    meta: SessionEndMeta = {},
  ): Promise<boolean> {
    if (db instanceof PrismaService) {
      return db.$transaction((tx) => this.end(tx, sessionId, reason, meta));
    }
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
    const row = await db.session.findUniqueOrThrow({
      where: { id: sessionId },
      select: {
        userId: true,
        loginClientId: true,
        kind: true,
        deviceName: true,
        userAgent: true,
      },
    });
    await this.events.record(db, {
      userId: row.userId,
      actorId: endActor(reason, row.userId, meta.endedById),
      type:
        reason === SessionEndReason.LOGOUT
          ? AccountEventType.SIGNED_OUT
          : AccountEventType.SESSION_ENDED,
      reason,
      system: ADMIN_REASONS.has(reason) ? (meta.system ?? null) : null,
      sessionId,
      clientId: meta.clientId ?? row.loginClientId,
      // The session's own device; the address only when a person's request ended it
      meta: {
        ip: meta.ip ?? null,
        device: deviceLabel(row),
        userAgent: row.userAgent,
      },
    });
    this.logger.log(
      `session ended sid=${sessionId} user=${row.userId} reason=${reason} client=${meta.clientId ?? row.loginClientId}`,
    );
    return true;
  }

  /** `end` outside a caller's transaction. */
  endNow(
    sessionId: string,
    reason: SessionEndReason,
    meta: SessionEndMeta = {},
  ): Promise<boolean> {
    return this.end(this.prisma, sessionId, reason, meta);
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
   * the session id are always new (session fixation). Spec 0011, AC-1: `SIGNED_IN` in the same
   * transaction.
   */
  async createWeb(input: {
    userId: string;
    meta: RequestMeta;
    previousHandle: unknown;
    /**
     * Spec 0013, AC-5, AC-7: the login finished through the code step, so the session starts
     * with `sign_in_code_at`; `admin` also writes `ADMIN_CODE_PASSED`.
     */
    codePassed?: { admin: boolean };
  }): Promise<{ session: Session; handle: string }> {
    const { meta } = input;
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

      await this.makeRoom(tx, input.userId, now);

      const created = await tx.session.create({
        data: {
          userId: input.userId,
          kind: SessionKind.WEB,
          loginClientId: 'portal',
          userAgent: meta.userAgent,
          createdIp: meta.ip,
          lastSeenIp: meta.ip,
          ssoHandleHash: hashOpaque(handle),
          createdAt: now,
          lastActivityAt: now,
          idleExpiresAt: this.idleCutoff(SessionKind.WEB, now),
          absoluteExpiresAt: new Date(
            now.getTime() + this.settings.webMaxHours * 3_600_000,
          ),
          signInCodeAt: input.codePassed ? now : null,
        },
      });
      await this.events.record(tx, {
        userId: input.userId,
        actorId: input.userId,
        type: AccountEventType.SIGNED_IN,
        sessionId: created.id,
        clientId: 'portal',
        meta,
      });
      if (input.codePassed?.admin) {
        await this.events.record(tx, {
          userId: input.userId,
          actorId: input.userId,
          type: AccountEventType.ADMIN_CODE_PASSED,
          sessionId: created.id,
          clientId: 'portal',
          meta,
        });
      }
      return created;
    });
    this.logger.log(
      `session created sid=${session.id} user=${input.userId} kind=WEB client=portal`,
    );
    return { session, handle };
  }

  /**
   * Spec 0013, AC-7: the step up. Sets `sign_in_code_at` on a live session that has none and
   * writes `ADMIN_CODE_PASSED`, in one transaction. Answers false when nothing changed (already
   * passed, or the session ended meanwhile). Never cleared afterwards.
   */
  async markCodePassed(
    sessionId: string,
    userId: string,
    meta: RequestMeta,
  ): Promise<boolean> {
    return this.prisma.$transaction(async (tx) => {
      const { count } = await tx.session.updateMany({
        where: { id: sessionId, userId, endedAt: null, signInCodeAt: null },
        data: { signInCodeAt: new Date() },
      });
      if (count === 0) return false;
      await this.events.record(tx, {
        userId,
        actorId: userId,
        type: AccountEventType.ADMIN_CODE_PASSED,
        sessionId,
        clientId: 'portal',
        meta,
      });
      return true;
    });
  }

  /**
   * Creates a mobile session at a native login (spec 0003, AC-28, AC-6), with its first refresh
   * token for `clientId`, in one transaction under the same per user lock and cap as a web
   * login. A mobile session has no SSO handle and no absolute limit; it rolls 7 days on each
   * refresh (AC-2). Spec 0011, AC-1, AC-4: `SIGNED_IN` and the first `SYSTEM_OPENED` in the same
   * transaction.
   */
  async createMobile(input: {
    userId: string;
    clientId: string;
    /** The system the first access token is signed for (`sessions.audiences`). */
    audience: SystemType;
    deviceName: string | null;
    meta: RequestMeta;
  }): Promise<{ session: Session; refreshToken: string }> {
    const { meta } = input;
    const refreshToken = newOpaque();
    const now = new Date();
    const session = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${input.userId}, 0))`;
      await this.makeRoom(tx, input.userId, now);
      const created = await tx.session.create({
        data: {
          userId: input.userId,
          kind: SessionKind.MOBILE,
          loginClientId: input.clientId,
          deviceName: input.deviceName,
          audiences: [input.audience],
          userAgent: meta.userAgent,
          createdIp: meta.ip,
          lastSeenIp: meta.ip,
          createdAt: now,
          lastActivityAt: now,
          idleExpiresAt: this.idleCutoff(SessionKind.MOBILE, now),
          absoluteExpiresAt: null,
        },
      });
      await tx.refreshToken.create({
        data: {
          sessionId: created.id,
          clientId: input.clientId,
          tokenHash: hashOpaque(refreshToken),
        },
      });
      const opened = {
        userId: input.userId,
        actorId: input.userId,
        sessionId: created.id,
        clientId: input.clientId,
        meta,
      };
      await this.events.recordMany(tx, [
        { ...opened, type: AccountEventType.SIGNED_IN },
        {
          ...opened,
          type: AccountEventType.SYSTEM_OPENED,
          system: input.audience,
        },
      ]);
      return created;
    });
    this.logger.log(
      `session created sid=${session.id} user=${input.userId} kind=MOBILE client=${input.clientId}`,
    );
    return { session, refreshToken };
  }

  /**
   * Inside a login transaction holding the user's lock: ends sessions already past a cutoff,
   * then, when the user is at the cap, the live ones with the oldest `last_activity_at`
   * (`MAX_SESSIONS`, AC-6), so the new session makes at most the cap.
   */
  private async makeRoom(
    tx: Prisma.TransactionClient,
    userId: string,
    now: Date,
  ): Promise<void> {
    const open = await tx.session.findMany({
      where: { userId, endedAt: null },
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
    meta: SessionEndMeta & { exceptSid?: string } = {},
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
      if (
        await this.end(db, row.id, reason, {
          endedById: meta.endedById,
          system: meta.system,
          ip: meta.ip,
        })
      ) {
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

  /**
   * A user's live sessions, newest activity first (AC-31). Rows past a cutoff are left out
   * here; the next call that touches them, or the hourly sweep, writes them as ended. With
   * `currentSid`, the caller's own row is marked `current`.
   */
  async listLive(
    userId: string,
    currentSid?: string,
    now = new Date(),
  ): Promise<SessionView[]> {
    const rows = await this.prisma.session.findMany({
      where: {
        userId,
        endedAt: null,
        idleExpiresAt: { gt: now },
        OR: [{ absoluteExpiresAt: null }, { absoluteExpiresAt: { gt: now } }],
      },
      orderBy: [{ lastActivityAt: 'desc' }, { createdAt: 'desc' }],
    });
    return rows.map((row) => ({
      sid: row.id,
      kind: row.kind === SessionKind.WEB ? 'web' : 'mobile',
      device: deviceLabel(row),
      client: row.loginClientId,
      systems: row.audiences,
      createdAt: row.createdAt.toISOString(),
      lastActiveAt: row.lastActivityAt.toISOString(),
      ...(currentSid !== undefined ? { current: row.id === currentSid } : {}),
    }));
  }

  /**
   * Records each system an access token was signed for (`sessions.audiences`). Spec 0011, AC-4:
   * the first time per system writes one `SYSTEM_OPENED`, only when the update changed the row,
   * so two refreshes racing write one. `ip` is the user's address a backend vouched for
   * (`X-WeLinc-User-Address` after a valid assertion), else null, never the backend's own.
   */
  async addAudience(
    db: Db,
    sessionId: string,
    aud: SystemType,
    meta: { ip: string | null; clientId: string },
  ): Promise<number> {
    const count =
      await db.$executeRaw`UPDATE "sessions" SET "audiences" = array_append("audiences", ${aud}::"SystemType") WHERE "id" = ${sessionId}::uuid AND NOT (${aud}::"SystemType" = ANY("audiences"))`;
    if (count !== 1) return count;
    const row = await db.session.findUniqueOrThrow({
      where: { id: sessionId },
      select: { userId: true, kind: true, deviceName: true, userAgent: true },
    });
    await this.events.record(db, {
      userId: row.userId,
      actorId: row.userId,
      type: AccountEventType.SYSTEM_OPENED,
      system: aud,
      sessionId,
      clientId: meta.clientId,
      meta: {
        ip: normaliseIp(meta.ip),
        device: deviceLabel(row),
        userAgent: row.userAgent,
      },
    });
    return count;
  }
}
