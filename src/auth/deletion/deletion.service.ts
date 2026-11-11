import {
  HttpStatus,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  AccountEventType,
  DeletionRequestStatus,
  Prisma,
  ReauthPurpose,
  SessionEndReason,
  SystemType,
} from '@prisma/client';
import type { Env } from '../../config/env';
import { MailService } from '../../shared/mail.service';
import { PrismaService } from '../../shared/prisma.service';
import type { Email } from '../codes/code-emails';
import { coded } from '../errors';
import { AccountEventsService } from '../events/account-events.service';
import {
  DELETION_REQUEST_REASON,
  PasswordCheckReason,
} from '../events/event-types';
import type { RequestMeta } from '../events/request-meta';
import { PasswordCheckService } from '../reauth/password-check.service';
import { CatalogService } from '../roles/catalog.service';
import { SessionService } from '../sessions/session.service';
import {
  adminSystems,
  assertAnotherAdmin,
  change,
  lockAccount,
} from '../user-changes';
import { assertInSystem, type AdminCaller } from '../user-scope';
import {
  decodeDeletionCursor,
  encodeDeletionCursor,
  type DeletionView as View,
} from './deletion-cursor';
import {
  accountClosedEmail,
  accountClosedForAdminsEmail,
  accountRestoredEmail,
  requestCancelledEmail,
  requestForAdminsEmail,
  requestReceivedEmail,
  requestRejectedEmail,
} from './deletion-emails';

type Tx = Prisma.TransactionClient;

/** The signed in person acting on their own account. */
export type SelfCaller = { sub: string; sid: string; meta: RequestMeta };

/** Spec 0012, API surface: a request as every route answers it. */
export type DeletionRequestView = {
  id: string;
  status: DeletionRequestStatus;
  reason: string | null;
  requestedAt: string;
  decidedAt: string | null;
  decisionNote: string | null;
  eraseAfter: string | null;
  user?: { id: string; name: string; email: string; systems: SystemType[] };
};

/** One account in its grace period (AC-9, `view=grace`). */
export type GraceItem = {
  user: { id: string; name: string; email: string };
  deletedAt: string;
  eraseAfter: string;
  requestId: string | null;
};

export type Page<T> = { data: T[]; nextCursor: string | null };

export const REASON_MAX = 500;
const DAY_MS = 86_400_000;

const REQUEST_SELECT = {
  id: true,
  userId: true,
  status: true,
  reason: true,
  requestedAt: true,
  decidedAt: true,
  decisionNote: true,
} satisfies Prisma.AccountDeletionRequestSelect;

type RequestRow = Prisma.AccountDeletionRequestGetPayload<{
  select: typeof REQUEST_SELECT;
}>;

export const validationFailed = (message: string) =>
  coded(HttpStatus.BAD_REQUEST, 'VALIDATION_FAILED', message);
const deletionPending = () =>
  coded(
    HttpStatus.CONFLICT,
    'DELETION_PENDING',
    'You already asked to delete your account',
  );
const notPending = () =>
  coded(
    HttpStatus.CONFLICT,
    'NOT_PENDING',
    'This request was already decided or cancelled',
  );
const selfDecision = () =>
  coded(
    HttpStatus.FORBIDDEN,
    'SELF_DECISION',
    "You can't decide your own deletion request",
  );
export const notRestorable = () =>
  coded(
    HttpStatus.CONFLICT,
    'NOT_RESTORABLE',
    'Only a deleted account that is not erased yet can be restored',
  );

const isUniqueViolation = (error: unknown) => {
  if (typeof error !== 'object' || error === null) return false;
  const code = (error as { code?: string }).code;
  if (code === 'P2002') return true;
  // A raw query clash comes back wrapped; the Postgres code is in the message or meta
  const meta = (error as { meta?: { code?: string } }).meta;
  return meta?.code === '23505';
};

/** The person's trimmed reason, null when empty (AC-4). */
export function cleanReason(reason: unknown): string | null {
  if (reason === undefined || reason === null) return null;
  if (typeof reason !== 'string') {
    throw validationFailed('reason must be text');
  }
  const trimmed = reason.trim();
  if (trimmed.length > REASON_MAX) {
    throw validationFailed(`reason must be at most ${REASON_MAX} characters`);
  }
  return trimmed || null;
}

/** The admin's note on a reject, 1 to 500 characters after trimming (AC-12). */
export function cleanNote(note: unknown): string {
  const trimmed = typeof note === 'string' ? note.trim() : '';
  if (trimmed.length < 1 || trimmed.length > REASON_MAX) {
    throw validationFailed(`note must be from 1 to ${REASON_MAX} characters`);
  }
  return trimmed;
}

/** `limit` 1 to 100, default 50 (AC-9). */
export function parseLimit(raw: unknown): number {
  if (raw === undefined) return 50;
  if (typeof raw !== 'string' || !/^\d{1,3}$/.test(raw)) {
    throw validationFailed('limit must be a whole number from 1 to 100');
  }
  const limit = Number(raw);
  if (limit < 1 || limit > 100) {
    throw validationFailed('limit must be a whole number from 1 to 100');
  }
  return limit;
}

export function parseView(raw: unknown): View {
  if (raw !== 'pending' && raw !== 'grace') {
    throw validationFailed('view must be pending or grace');
  }
  return raw;
}

/**
 * Spec 0012: the person's deletion request, the admin decisions and the emails that go with
 * them. Every path that changes a request or its account locks the `users` row first
 * (`lockAccount`), then the request row, and moves status only from the state it expects.
 */
@Injectable()
export class DeletionService {
  private readonly logger = new Logger(DeletionService.name);
  private readonly graceDays: number;
  private readonly reviewLink: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly events: AccountEventsService,
    private readonly catalog: CatalogService,
    private readonly sessions: SessionService,
    private readonly passwords: PasswordCheckService,
    private readonly mail: MailService,
    config: ConfigService<Env, true>,
  ) {
    this.graceDays = config.get('ACCOUNT_ERASURE_GRACE_DAYS', { infer: true });
    this.reviewLink = config
      .get('PORTAL_URL', { infer: true })
      .replace(/\/+$/, '');
  }

  /** When a soft deleted account is erased (Value sourcing: computed at read time). */
  eraseAfter(deletedAt: Date): Date {
    return new Date(deletedAt.getTime() + this.graceDays * DAY_MS);
  }

  /** AC-1, AC-2: recheck the password, then hand out a reauth token for `purpose`. */
  async verifyPassword(
    caller: SelfCaller,
    password: unknown,
    purpose: unknown,
  ): Promise<{ reauthToken: string; expiresAt: string }> {
    if (purpose !== ReauthPurpose.ACCOUNT_DELETION) {
      throw validationFailed('purpose must be ACCOUNT_DELETION');
    }
    if (typeof password !== 'string' || password.length === 0) {
      throw validationFailed('password is required');
    }
    await this.passwords.verifyOwnPassword({
      userId: caller.sub,
      password,
      reason: PasswordCheckReason.ACCOUNT_DELETION,
      sid: caller.sid,
      meta: caller.meta,
    });
    return this.passwords.issueReauthToken(
      caller.sub,
      caller.sid,
      ReauthPurpose.ACCOUNT_DELETION,
    );
  }

  /**
   * AC-4, AC-5: lock the account, check pending, check `LAST_ADMIN`, use the token, insert. The
   * two refusals leave the token unused. A clash on the one pending index is DELETION_PENDING.
   */
  async request(
    caller: SelfCaller,
    reauthToken: unknown,
    rawReason: unknown,
  ): Promise<DeletionRequestView> {
    const reason = cleanReason(rawReason);
    const userId = caller.sub;
    let saved: { row: RequestRow; person: Person };
    try {
      saved = await this.prisma.$transaction(async (tx) => {
        await lockAccount(tx, userId);
        const person = await this.person(tx, userId);
        if (!person) throw new NotFoundException('User not found');
        const pending = await tx.accountDeletionRequest.findFirst({
          where: { userId, status: DeletionRequestStatus.PENDING },
          select: { id: true },
        });
        if (pending) throw deletionPending();
        const admins = await this.catalog.adminRoles(tx);
        for (const system of adminSystems(person.roles, admins)) {
          await assertAnotherAdmin(tx, userId, system);
        }
        await this.passwords.consumeReauthToken(
          tx,
          typeof reauthToken === 'string' ? reauthToken : undefined,
          userId,
          caller.sid,
          ReauthPurpose.ACCOUNT_DELETION,
        );
        // Millisecond time from here, so the keyset cursor (ms) is exact
        const row = await tx.accountDeletionRequest.create({
          data: { userId, reason, requestedAt: new Date() },
          select: REQUEST_SELECT,
        });
        await this.events.record(tx, {
          userId,
          actorId: userId,
          type: AccountEventType.DELETION_REQUESTED,
          sessionId: caller.sid,
          meta: caller.meta,
        });
        return { row, person };
      });
    } catch (error) {
      if (isUniqueViolation(error)) throw deletionPending();
      throw error;
    }

    const { row, person } = saved;
    await this.send(userId, 'DELETION_REQUESTED', person.email, () =>
      requestReceivedEmail({ name: person.name }),
    );
    const admins = await this.adminsOf(systemsOf(person.roles), [userId]);
    for (const admin of admins) {
      await this.send(admin.id, 'DELETION_REQUESTED_ADMIN', admin.email, () =>
        requestForAdminsEmail({
          adminName: admin.name,
          personName: person.name,
          personEmail: person.email,
          reason,
          reviewLink: this.reviewLink,
        }),
      );
    }
    return this.view(row, null);
  }

  /** AC-6: the person's latest request, or null. */
  async own(userId: string): Promise<{ request: DeletionRequestView | null }> {
    const row = await this.prisma.accountDeletionRequest.findFirst({
      where: { userId },
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
      select: { ...REQUEST_SELECT, user: { select: { deletedAt: true } } },
    });
    if (!row) return { request: null };
    return { request: this.view(row, row.user.deletedAt) };
  }

  /** AC-7: cancels a pending request; nothing to cancel is not an error. */
  async cancel(caller: SelfCaller): Promise<void> {
    const userId = caller.sub;
    const person = await this.prisma.$transaction(async (tx) => {
      await lockAccount(tx, userId);
      const { count } = await tx.accountDeletionRequest.updateMany({
        where: { userId, status: DeletionRequestStatus.PENDING },
        data: {
          status: DeletionRequestStatus.CANCELLED,
          cancelledAt: new Date(),
        },
      });
      if (count === 0) return null;
      await this.events.record(tx, {
        userId,
        actorId: userId,
        type: AccountEventType.DELETION_CANCELLED,
        sessionId: caller.sid,
        meta: caller.meta,
      });
      return this.person(tx, userId);
    });
    if (person) {
      await this.send(userId, 'DELETION_CANCELLED', person.email, () =>
        requestCancelledEmail({ name: person.name }),
      );
    }
  }

  /** AC-9: pending requests, or accounts in grace, of people holding a role in `system`. */
  async list(
    system: SystemType,
    query: { view?: unknown; cursor?: unknown; limit?: unknown },
  ): Promise<Page<DeletionRequestView> | Page<GraceItem>> {
    const view = parseView(query.view);
    const limit = parseLimit(query.limit);
    if (query.cursor !== undefined && typeof query.cursor !== 'string') {
      throw validationFailed('cursor must be text');
    }
    const after = query.cursor
      ? decodeDeletionCursor(query.cursor, view)
      : null;

    if (view === 'pending') {
      const rows = await this.prisma.accountDeletionRequest.findMany({
        where: {
          status: DeletionRequestStatus.PENDING,
          user: { deletedAt: null, roles: { some: { system } } },
          ...(after
            ? {
                OR: [
                  { requestedAt: { gt: after.at } },
                  { requestedAt: after.at, id: { gt: after.id } },
                ],
              }
            : {}),
        },
        orderBy: [{ requestedAt: 'asc' }, { id: 'asc' }],
        take: limit + 1,
        select: {
          ...REQUEST_SELECT,
          user: {
            select: {
              id: true,
              name: true,
              email: true,
              roles: { select: { system: true } },
            },
          },
        },
      });
      const page = rows.slice(0, limit);
      const last = page[page.length - 1];
      return {
        data: page.map((row) => ({
          ...this.view(row, null),
          user: {
            id: row.user.id,
            name: row.user.name,
            email: row.user.email,
            systems: systemsOf(row.user.roles),
          },
        })),
        nextCursor:
          rows.length > limit && last
            ? encodeDeletionCursor('pending', last.requestedAt, last.id)
            : null,
      };
    }

    const users = await this.prisma.user.findMany({
      where: {
        deletedAt: { not: null },
        erasedAt: null,
        roles: { some: { system } },
        ...(after
          ? {
              OR: [
                { deletedAt: { gt: after.at } },
                { deletedAt: after.at, id: { gt: after.id } },
              ],
            }
          : {}),
      },
      orderBy: [{ deletedAt: 'asc' }, { id: 'asc' }],
      take: limit + 1,
      select: {
        id: true,
        name: true,
        email: true,
        deletedAt: true,
        deletionRequests: {
          where: { status: DeletionRequestStatus.APPROVED },
          orderBy: { requestedAt: 'desc' },
          take: 1,
          select: { id: true },
        },
      },
    });
    const page = users.slice(0, limit);
    const last = page[page.length - 1];
    return {
      data: page.map((user) => ({
        user: { id: user.id, name: user.name, email: user.email },
        deletedAt: user.deletedAt!.toISOString(),
        eraseAfter: this.eraseAfter(user.deletedAt!).toISOString(),
        requestId: user.deletionRequests[0]?.id ?? null,
      })),
      nextCursor:
        users.length > limit && last
          ? encodeDeletionCursor('grace', last.deletedAt!, last.id)
          : null,
    };
  }

  /**
   * AC-10, AC-11: soft deletes the account as an admin delete does, without `assertNotShared`
   * (the request is the person's consent), and closes the request as APPROVED.
   */
  async approve(id: string, actor: AdminCaller): Promise<DeletionRequestView> {
    const done = await this.prisma.$transaction(async (tx) => {
      const { person, userId } = await this.lockForDecision(tx, id, actor);
      if (person.isActive) {
        const admins = await this.catalog.adminRoles(tx);
        for (const system of adminSystems(person.roles, admins)) {
          await assertAnotherAdmin(tx, userId, system);
        }
      }
      const now = new Date();
      const decided = await tx.accountDeletionRequest.updateMany({
        where: { id, status: DeletionRequestStatus.PENDING },
        data: {
          status: DeletionRequestStatus.APPROVED,
          decidedById: actor.id,
          decidedSystem: actor.system,
          decidedAt: now,
        },
      });
      if (decided.count !== 1) throw notPending();
      await tx.user.update({
        where: { id: userId },
        data: { deletedAt: now, isActive: false, lockedAt: null },
      });
      await this.events.record(
        tx,
        change(userId, actor, AccountEventType.DELETED, {
          reason: DELETION_REQUEST_REASON,
        }),
      );
      await this.sessions.endAllForUser(tx, userId, SessionEndReason.DELETED, {
        endedById: actor.id,
        system: actor.system,
        ip: actor.meta?.ip,
      });
      const row = await tx.accountDeletionRequest.findUniqueOrThrow({
        where: { id },
        select: REQUEST_SELECT,
      });
      return { row, person, deletedAt: now };
    });

    await this.notifyClosed(
      { ...done.person, id: done.row.userId },
      done.deletedAt,
      actor,
    );
    return this.withUser(this.view(done.row, done.deletedAt), done.person);
  }

  /** AC-11, AC-12: rejects with a required note, and tells the person. */
  async reject(
    id: string,
    rawNote: unknown,
    actor: AdminCaller,
  ): Promise<DeletionRequestView> {
    const note = cleanNote(rawNote);
    const done = await this.prisma.$transaction(async (tx) => {
      const { person, userId } = await this.lockForDecision(tx, id, actor);
      const decided = await tx.accountDeletionRequest.updateMany({
        where: { id, status: DeletionRequestStatus.PENDING },
        data: {
          status: DeletionRequestStatus.REJECTED,
          decidedById: actor.id,
          decidedSystem: actor.system,
          decidedAt: new Date(),
          decisionNote: note,
        },
      });
      if (decided.count !== 1) throw notPending();
      await this.events.record(
        tx,
        change(userId, actor, AccountEventType.DELETION_REJECTED, {
          system: actor.system,
        }),
      );
      const row = await tx.accountDeletionRequest.findUniqueOrThrow({
        where: { id },
        select: REQUEST_SELECT,
      });
      return { row, person };
    });

    await this.send(
      done.row.userId,
      'DELETION_REJECTED',
      done.person.email,
      () => requestRejectedEmail({ name: done.person.name, note }),
    );
    return this.withUser(this.view(done.row, null), done.person);
  }

  /**
   * The AC-10 emails after an approval or an admin delete: the person gets the erasure date, the
   * admins of their systems (except the decider) are told who did it.
   */
  async notifyClosed(
    person: {
      id: string;
      name: string;
      email: string;
      roles: { system: SystemType }[];
    },
    deletedAt: Date,
    actor: AdminCaller,
  ): Promise<void> {
    const eraseAfter = this.eraseAfter(deletedAt);
    await this.send(person.id, 'ACCOUNT_CLOSED', person.email, () =>
      accountClosedEmail({ name: person.name, eraseAfter }),
    );
    const decider = await this.prisma.user.findUnique({
      where: { id: actor.id },
      select: { name: true },
    });
    const admins = await this.adminsOf(systemsOf(person.roles), [
      person.id,
      actor.id,
    ]);
    for (const admin of admins) {
      await this.send(admin.id, 'ACCOUNT_CLOSED_ADMIN', admin.email, () =>
        accountClosedForAdminsEmail({
          adminName: admin.name,
          personName: person.name,
          personEmail: person.email,
          deciderName: decider?.name ?? 'An admin',
          eraseAfter,
        }),
      );
    }
  }

  /** AC-13: the AC-10 emails after `DELETE /auth/users/:id`, read after its commit. */
  async notifyAdminDelete(userId: string, actor: AdminCaller): Promise<void> {
    const person = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        email: true,
        deletedAt: true,
        roles: { select: { system: true } },
      },
    });
    if (!person?.deletedAt) return;
    await this.notifyClosed(person, person.deletedAt, actor);
  }

  /** AC-14: the restored email. */
  async notifyRestored(userId: string): Promise<void> {
    const person = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { name: true, email: true },
    });
    if (!person) return;
    await this.send(userId, 'ACCOUNT_RESTORED', person.email, () =>
      accountRestoredEmail({ name: person.name }),
    );
  }

  /**
   * AC-11: the request's person, then their row lock, then the request row lock. 404 for a person
   * outside the admin's system (or no such request), 403 on your own, 409 when not pending.
   */
  private async lockForDecision(
    tx: Tx,
    id: string,
    actor: AdminCaller,
  ): Promise<{ person: Person; userId: string }> {
    const head = await tx.accountDeletionRequest.findUnique({
      where: { id },
      select: { userId: true },
    });
    if (!head) throw new NotFoundException('Deletion request not found');
    await lockAccount(tx, head.userId);
    const [row] = await tx.$queryRaw<{ status: DeletionRequestStatus }[]>`
      SELECT "status" FROM "account_deletion_requests" WHERE "id" = ${id}::uuid FOR UPDATE`;
    const person = await this.person(tx, head.userId, true);
    assertInSystem(person, actor.system);
    if (head.userId === actor.id) throw selfDecision();
    if (row?.status !== DeletionRequestStatus.PENDING) throw notPending();
    return { person, userId: head.userId };
  }

  private async person(
    tx: Tx,
    userId: string,
    includeDeleted = false,
  ): Promise<Person | null> {
    return tx.user.findFirst({
      where: { id: userId, ...(includeDeleted ? {} : { deletedAt: null }) },
      select: PERSON_SELECT,
    });
  }

  /**
   * Active, not deleted holders of the admin role of any of `systems`, minus `except`
   * (Value sourcing: `system_roles.is_system_admin`).
   */
  private adminsOf(
    systems: SystemType[],
    except: string[],
  ): Promise<{ id: string; name: string; email: string }[]> {
    if (systems.length === 0) return Promise.resolve([]);
    return this.prisma.user.findMany({
      where: {
        id: { notIn: except },
        isActive: true,
        deletedAt: null,
        roles: {
          some: {
            system: { in: systems },
            systemRole: { isSystemAdmin: true },
          },
        },
      },
      select: { id: true, name: true, email: true },
      orderBy: { id: 'asc' },
    });
  }

  private view(row: RequestRow, deletedAt: Date | null): DeletionRequestView {
    return {
      id: row.id,
      status: row.status,
      reason: row.reason,
      requestedAt: row.requestedAt.toISOString(),
      decidedAt: row.decidedAt?.toISOString() ?? null,
      decisionNote: row.decisionNote,
      eraseAfter:
        row.status === DeletionRequestStatus.APPROVED && deletedAt
          ? this.eraseAfter(deletedAt).toISOString()
          : null,
    };
  }

  private withUser(
    view: DeletionRequestView,
    person: Person,
  ): DeletionRequestView {
    return {
      ...view,
      user: {
        id: person.id,
        name: person.name,
        email: person.email,
        systems: systemsOf(person.roles),
      },
    };
  }

  /** A notice email after commit. A failure is logged without the address and never thrown. */
  private async send(
    userId: string,
    kind: string,
    to: string,
    build: () => Email,
  ): Promise<void> {
    try {
      await this.mail.sendMail({
        to,
        ...build(),
        tag: `user=${userId} purpose=${kind}`,
      });
    } catch (error) {
      this.logger.error(
        `notice email failed user=${userId} purpose=${kind}: ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }
}

const PERSON_SELECT = {
  id: true,
  name: true,
  email: true,
  isActive: true,
  roles: { select: { role: true, system: true } },
} satisfies Prisma.UserSelect;

type Person = Prisma.UserGetPayload<{ select: typeof PERSON_SELECT }>;

/** Each system once, sorted. */
export function systemsOf(roles: { system: SystemType }[]): SystemType[] {
  return [...new Set(roles.map((r) => r.system))].sort();
}
