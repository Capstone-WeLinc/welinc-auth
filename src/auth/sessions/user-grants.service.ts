import type { RequestMeta } from '../events/request-meta';
import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import {
  Prisma,
  SessionEndReason,
  SessionKind,
  SystemType,
  type OAuthClient,
  type Session,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import { coded } from '../errors';
import { oauthError } from '../clients/oauth-error';
import { TokenService, type TokenRole } from '../tokens/token.service';
import {
  allowedCodes,
  appNotAllowedMessage,
  filterAllowed,
} from '../roles/allowed-roles';
import {
  hashOpaque,
  isOpaqueShape,
  isPkceVerifier,
  newOpaque,
  openGrace,
  pkceMatches,
  sealGrace,
} from './opaque';
import {
  SessionService,
  cutoffReason,
  sessionExpiresAt,
} from './session.service';
import { launcherOrder } from './launcher';

/** The user grants answer (spec 0001 section 5), plus the absolute end a web cookie lives to. */
export type UserTokenAnswer = {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  sid: string;
  /** The earlier of the idle and absolute cutoffs. */
  session_expires_at: string;
  /** Web sessions only: login + WEB_SESSION_MAX_HOURS, for the refresh cookie's max age. */
  session_absolute_expires_at?: string;
  user: {
    id: string;
    name: string;
    email: string;
    roles: TokenRole[];
    /** Every system the user holds a role in, launcher order (spec 0007, AC-6). Never in a JWT. */
    systems: SystemType[];
  };
};

type Tx = Prisma.TransactionClient;

/** What a grant transaction decided. Ending writes commit; the error is raised after. */
type Outcome =
  | {
      kind: 'issue';
      session: Session;
      refreshToken: string;
      user: { id: string; name: string; email: string };
      roles: TokenRole[];
      systems: SystemType[];
      aud: SystemType;
    }
  | { kind: 'invalid'; reason: string }
  | { kind: 'no_access'; aud: SystemType }
  | { kind: 'not_allowed'; message: string };

/** A mobile login that passed `checkMobileGrant`: what `startMobile` signs for. */
export type MobileGrant = {
  client: OAuthClient;
  aud: SystemType;
  roles: TokenRole[];
  systems: SystemType[];
};

/** What `rolesFor` found: the roles held in the audience, then the ones this client allows. */
type GrantRoles =
  | { kind: 'ok'; roles: TokenRole[]; systems: SystemType[] }
  | { kind: 'no_access'; aud: SystemType }
  | { kind: 'not_allowed'; message: string };

type CodeRow = {
  client_id: string;
  session_id: string;
  redirect_uri: string;
  code_challenge: string;
  expires_at: Date;
  used_at: Date | null;
};

type TokenRow = {
  id: string;
  session_id: string;
  client_id: string;
  used_at: Date | null;
  grace_cipher: Uint8Array | null;
  grace_until: Date | null;
};

const invalidGrant = () =>
  oauthError(
    HttpStatus.BAD_REQUEST,
    'invalid_grant',
    'The grant is invalid, expired or already used',
  );

/**
 * The `authorization_code` and `refresh_token` grants of `/auth/token` (spec 0003, AC-7 to
 * AC-10, AC-15, AC-41, AC-43). The caller has already proved it is `client`.
 */
@Injectable()
export class UserGrantsService {
  private readonly logger = new Logger('UserGrants');

  constructor(
    private readonly prisma: PrismaService,
    private readonly tokens: TokenService,
    private readonly sessions: SessionService,
  ) {}

  /** The code exchange, one transaction (spec 0003, Code exchange). */
  async exchangeCode(
    client: OAuthClient,
    input: { code: string; redirectUri: string; verifier: string },
    userAddress: string | null,
  ): Promise<UserTokenAnswer> {
    if (!isOpaqueShape(input.code) || !isPkceVerifier(input.verifier)) {
      return this.refuse(client.id, 'malformed');
    }
    const aud = client.system;
    if (!aud) return this.refuse(client.id, 'client_without_system');
    const now = new Date();

    const outcome = await this.prisma.$transaction(
      async (tx): Promise<Outcome> => {
        const [code] = await tx.$queryRaw<CodeRow[]>`
          SELECT "client_id", "session_id", "redirect_uri", "code_challenge", "expires_at", "used_at"
          FROM "authorization_codes" WHERE "code_hash" = ${hashOpaque(input.code)} FOR UPDATE`;
        if (!code) return { kind: 'invalid', reason: 'unknown_code' };
        if (code.used_at) {
          // AC-15: a second use of a code ends that session
          await this.sessions.end(
            tx,
            code.session_id,
            SessionEndReason.CODE_REUSE,
            { clientId: client.id },
          );
          return { kind: 'invalid', reason: 'code_reused' };
        }
        if (now >= code.expires_at)
          return { kind: 'invalid', reason: 'code_expired' };
        if (code.client_id !== client.id)
          return { kind: 'invalid', reason: 'client_mismatch' };
        if (code.redirect_uri !== input.redirectUri)
          return { kind: 'invalid', reason: 'redirect_mismatch' };
        if (!pkceMatches(input.verifier, code.code_challenge))
          return { kind: 'invalid', reason: 'pkce_mismatch' };

        const live = await this.liveSession(tx, code.session_id, now);
        if (live.kind !== 'live') return live;
        const granted = await this.rolesFor(
          tx,
          live.session.userId,
          aud,
          client,
        );
        if (granted.kind !== 'ok') return granted;
        const { roles, systems } = granted;

        await tx.authorizationCode.update({
          where: { codeHash: hashOpaque(input.code) },
          data: { usedAt: now },
        });
        // AC-7: a lost cookie on a live session; the old token goes with no grace
        await tx.refreshToken.updateMany({
          where: {
            sessionId: live.session.id,
            clientId: client.id,
            usedAt: null,
          },
          data: { usedAt: now },
        });
        const refreshToken = newOpaque();
        await tx.refreshToken.create({
          data: {
            sessionId: live.session.id,
            clientId: client.id,
            tokenHash: hashOpaque(refreshToken),
          },
        });
        // A code exchange counts as activity (AC-2)
        const session = await tx.session.update({
          where: { id: live.session.id },
          data: {
            lastActivityAt: now,
            idleExpiresAt: this.sessions.idleCutoff(live.session.kind, now),
            ...(userAddress ? { lastSeenIp: userAddress } : {}),
          },
        });
        await this.sessions.addAudience(tx, session.id, aud, {
          ip: userAddress,
          clientId: client.id,
        });
        return {
          kind: 'issue',
          session,
          refreshToken,
          user: live.user,
          roles,
          systems,
          aud,
        };
      },
    );
    return this.finish(client.id, 'authorization_code', outcome);
  }

  /** Refresh token rotation, one transaction (spec 0003, Rotation, step by step). */
  async refresh(
    client: OAuthClient,
    input: { refreshToken: string; audience?: SystemType },
    userAddress: string | null,
  ): Promise<UserTokenAnswer> {
    if (!isOpaqueShape(input.refreshToken)) {
      return this.refuse(client.id, 'malformed');
    }
    const aud = input.audience ?? client.system;
    if (!aud) return this.refuse(client.id, 'client_without_system');
    const presented = input.refreshToken;
    const now = new Date();
    const graceMs = this.sessions.settings.graceSeconds * 1000;

    const outcome = await this.prisma.$transaction(
      async (tx): Promise<Outcome> => {
        // 1. The row, locked, so two refreshes with one token never both rotate it (AC-10)
        const [row] = await tx.$queryRaw<TokenRow[]>`
          SELECT "id", "session_id", "client_id", "used_at", "grace_cipher", "grace_until"
          FROM "refresh_tokens" WHERE "token_hash" = ${hashOpaque(presented)} FOR UPDATE`;
        if (!row) return { kind: 'invalid', reason: 'unknown_token' };

        // 2. The session must be live; a cutoff found here is enforced now
        const live = await this.liveSession(tx, row.session_id, now);
        if (live.kind !== 'live') return live;

        // 3. Only the client the token was issued to may use it, and that ends nothing
        if (row.client_id !== client.id)
          return { kind: 'invalid', reason: 'client_mismatch' };

        // 6. Used and past grace: reuse ends the whole session (AC-9)
        const inGrace =
          row.used_at !== null &&
          row.grace_until !== null &&
          now <= row.grace_until &&
          row.grace_cipher !== null;
        if (row.used_at && !inGrace) {
          await this.sessions.end(
            tx,
            row.session_id,
            SessionEndReason.REFRESH_REUSE,
            { clientId: client.id },
          );
          return { kind: 'invalid', reason: 'token_reused' };
        }

        // 7, checked before any write: roles for the audience (AC-41), and the ones this
        // client allows (spec 0004, AC-19)
        const granted = await this.rolesFor(
          tx,
          live.session.userId,
          aud,
          client,
        );
        if (granted.kind !== 'ok') return granted;
        const { roles, systems } = granted;

        let refreshToken: string;
        if (inGrace) {
          // 5. Within grace: the same new token again (AC-8), on any replica
          const child = openGrace(row.grace_cipher!, presented, row.id);
          if (!child) return { kind: 'invalid', reason: 'grace_unreadable' };
          refreshToken = child;
        } else {
          // 4. Unused: rotate
          refreshToken = newOpaque();
          await tx.refreshToken.update({
            where: { id: row.id },
            data: {
              usedAt: now,
              graceUntil: new Date(now.getTime() + graceMs),
              graceCipher: new Uint8Array(
                sealGrace(refreshToken, presented, row.id),
              ),
            },
          });
          await tx.refreshToken.create({
            data: {
              sessionId: row.session_id,
              clientId: client.id,
              tokenHash: hashOpaque(refreshToken),
              parentId: row.id,
            },
          });
        }

        // A web refresh is never activity; a mobile refresh extends the session (AC-2)
        const mobile = live.session.kind === SessionKind.MOBILE;
        const session = await tx.session.update({
          where: { id: live.session.id },
          data: {
            ...(mobile
              ? {
                  lastActivityAt: now,
                  idleExpiresAt: this.sessions.idleCutoff(
                    SessionKind.MOBILE,
                    now,
                  ),
                }
              : {}),
            ...(userAddress ? { lastSeenIp: userAddress } : {}),
          },
        });
        await this.sessions.addAudience(tx, session.id, aud, {
          ip: userAddress,
          clientId: client.id,
        });
        return {
          kind: 'issue',
          session,
          refreshToken,
          user: live.user,
          roles,
          systems,
          aud,
        };
      },
    );
    return this.finish(client.id, 'refresh_token', outcome);
  }

  /**
   * The mobile grant checks alone (spec 0004, AC-19; suite spec 0009, AC-11): the client's own
   * system, `NO_SYSTEM_ACCESS` and `APP_NOT_ALLOWED`. Starts nothing, so the login can run them
   * before the email step and the step's verify route can run them again.
   */
  async checkMobileGrant(
    client: OAuthClient,
    userId: string,
  ): Promise<MobileGrant> {
    const aud = client.system;
    if (!aud) return this.refuse(client.id, 'client_without_system');
    const granted = await this.rolesFor(this.prisma, userId, aud, client);
    if (granted.kind !== 'ok') {
      return this.refuseGrant(client.id, 'mobile_login', granted);
    }
    return { client, aud, roles: granted.roles, systems: granted.systems };
  }

  /**
   * A native login (spec 0003, AC-28): the password and `checkMobileGrant` already passed.
   * Creates the mobile session and its first refresh token, then signs an access token for the
   * client's own system, answered like the user grants.
   */
  async startMobile(
    grant: MobileGrant,
    input: {
      user: { id: string; name: string; email: string };
      deviceName: string | null;
      meta: RequestMeta;
    },
  ): Promise<UserTokenAnswer> {
    const { client, aud, roles, systems } = grant;
    const { session, refreshToken } = await this.sessions.createMobile({
      userId: input.user.id,
      clientId: client.id,
      audience: aud,
      deviceName: input.deviceName,
      meta: input.meta,
    });
    return this.finish(client.id, 'mobile_login', {
      kind: 'issue',
      session,
      refreshToken,
      user: input.user,
      roles,
      systems,
      aud,
    });
  }

  /** The session behind a code or token, live, with an active account; ends it at a cutoff. */
  private async liveSession(
    tx: Tx,
    sessionId: string,
    now: Date,
  ): Promise<
    | {
        kind: 'live';
        session: Session;
        user: { id: string; name: string; email: string };
      }
    | { kind: 'invalid'; reason: string }
  > {
    const session = await tx.session.findUnique({
      where: { id: sessionId },
      include: {
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
    if (!session || session.endedAt)
      return { kind: 'invalid', reason: 'session_ended' };
    const reason = cutoffReason(session, now);
    if (reason) {
      await this.sessions.end(tx, session.id, reason);
      return { kind: 'invalid', reason: 'session_ended' };
    }
    if (!session.user.isActive || session.user.deletedAt) {
      return { kind: 'invalid', reason: 'account_inactive' };
    }
    const { user, ...row } = session;
    return {
      kind: 'live',
      session: row,
      user: { id: user.id, name: user.name, email: user.email },
    };
  }

  /**
   * The roles a token for `aud` carries on this client: the ones held there, kept only when the
   * client's `allowedRoles` lets them through (spec 0004, AC-19). None held answers
   * `NO_SYSTEM_ACCESS`; held but none allowed answers `APP_NOT_ALLOWED`.
   */
  private async rolesFor(
    tx: Tx | PrismaService,
    userId: string,
    aud: SystemType,
    client: Pick<OAuthClient, 'allowedRoles'>,
  ): Promise<GrantRoles> {
    // Every system's rows: the audience's roles, and `user.systems` read fresh (spec 0007, AC-6)
    const rows = await tx.userRoleAssignment.findMany({
      where: { userId },
      select: { role: true, system: true },
    });
    const held = rows
      .filter((r) => r.system === aud)
      .map((r) => ({ role: r.role, system: r.system }));
    if (held.length === 0) return { kind: 'no_access', aud };

    const allowed = allowedCodes(client.allowedRoles, aud);
    const roles = filterAllowed(held, allowed);
    if (roles.length > 0)
      return { kind: 'ok', roles, systems: launcherOrder(rows) };

    // Names in the client's list order, from the catalog
    const named = await tx.systemRole.findMany({
      where: { system: aud, code: { in: allowed ?? [] } },
      select: { code: true, name: true },
    });
    const names = (allowed ?? []).flatMap((code) => {
      const row = named.find((n) => n.code === code);
      return row ? [row.name] : [];
    });
    return { kind: 'not_allowed', message: appNotAllowedMessage(names) };
  }

  private async finish(
    clientId: string,
    grant: string,
    outcome: Outcome,
  ): Promise<UserTokenAnswer> {
    if (outcome.kind === 'invalid')
      return this.refuse(clientId, outcome.reason);
    if (outcome.kind === 'no_access' || outcome.kind === 'not_allowed') {
      return this.refuseGrant(clientId, grant, outcome);
    }
    const { session, user, roles, systems, aud } = outcome;
    const accessToken = await this.tokens.signUserToken({
      sub: user.id,
      email: user.email,
      aud,
      roles,
      sid: session.id,
      clientId,
    });
    // AC-39: never the token itself
    this.logger.log(
      `issued user token client=${clientId} grant=${grant} sid=${session.id} user=${user.id} aud=${aud}`,
    );
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.tokens.settings.accessTokenMinutes * 60,
      refresh_token: outcome.refreshToken,
      sid: session.id,
      session_expires_at: sessionExpiresAt(session).toISOString(),
      ...(session.absoluteExpiresAt
        ? {
            session_absolute_expires_at:
              session.absoluteExpiresAt.toISOString(),
          }
        : {}),
      user: { ...user, roles, systems },
    };
  }

  /** 403 `NO_SYSTEM_ACCESS` or `APP_NOT_ALLOWED`, logged without the user. */
  private refuseGrant(
    clientId: string,
    grant: string,
    outcome: Exclude<GrantRoles, { kind: 'ok' }>,
  ): never {
    if (outcome.kind === 'no_access') {
      this.logger.warn(
        `refused grant client=${clientId} grant=${grant} reason=no_system_access`,
      );
      throw coded(
        HttpStatus.FORBIDDEN,
        'NO_SYSTEM_ACCESS',
        `This account has no access to ${outcome.aud}`,
      );
    }
    this.logger.warn(
      `refused grant client=${clientId} grant=${grant} reason=app_not_allowed`,
    );
    throw coded(HttpStatus.FORBIDDEN, 'APP_NOT_ALLOWED', outcome.message);
  }

  private refuse(clientId: string, reason: string): never {
    this.logger.warn(`refused grant client=${clientId} reason=${reason}`);
    throw invalidGrant();
  }
}
