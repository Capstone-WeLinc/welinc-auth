import { Injectable } from '@nestjs/common';
import {
  AccountEventCategory,
  AccountEventType,
  Prisma,
  SystemType,
} from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import type { ActivityFilters } from './activity-query';
import { encodeEventCursor } from './event-cursor';
import { TYPE_CATEGORY } from './event-types';
import { NO_META, type RequestMeta } from './request-meta';

type Db = Prisma.TransactionClient | PrismaService;

/** One event to write (spec 0011, Data model). `category` follows from `type`. */
export type EventInput = {
  userId: string;
  /** Null or left out: nobody acted. The user's own id: the person did it. */
  actorId?: string | null;
  type: AccountEventType;
  reason?: string | null;
  /** The system the event belongs to; left out means account wide. */
  system?: SystemType | null;
  sessionId?: string | null;
  clientId?: string | null;
  field?: string | null;
  oldValue?: string | null;
  newValue?: string | null;
  attemptsLeft?: number | null;
  meta?: RequestMeta;
};

export type ActorKind = 'SELF' | 'ADMIN' | 'SYSTEM';

/** One event as the read routes answer it, narrowed per route (Field visibility). */
export type EventView = {
  id: string;
  category: AccountEventCategory;
  type: AccountEventType;
  reason: string | null;
  system: SystemType | null;
  sessionId: string | null;
  client?: string | null;
  field: string | null;
  oldValue: string | null;
  newValue: string | null;
  attemptsLeft: number | null;
  address: string | null;
  localNetwork: boolean;
  device: string | null;
  userAgent: string | null;
  country: string | null;
  network: string | null;
  createdAt: string;
  actor: { kind: ActorKind; id?: string; name?: string };
};

export type EventPage<T = EventView> = {
  data: T[];
  nextCursor: string | null;
};

/**
 * Private, loopback, link local and shared addresses (AC-17): stored with no place, and read
 * back as `localNetwork: true`.
 */
export function isLocalAddress(ip: string | null): boolean {
  if (!ip) return false;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(ip);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      (a === 100 && b >= 64 && b <= 127)
    );
  }
  const v6 = ip.toLowerCase();
  return v6 === '::1' || /^f[cd]/.test(v6) || /^fe[89ab]/.test(v6);
}

export function actorKind(row: {
  userId: string;
  actorId: string | null;
}): ActorKind {
  if (row.actorId === null) return 'SYSTEM';
  return row.actorId === row.userId ? 'SELF' : 'ADMIN';
}

/** The columns every view reads, plus the actor's name for admin views. */
const VIEW_SELECT = {
  id: true,
  userId: true,
  actorId: true,
  category: true,
  type: true,
  reason: true,
  system: true,
  sessionId: true,
  clientId: true,
  field: true,
  oldValue: true,
  newValue: true,
  attemptsLeft: true,
  ip: true,
  device: true,
  userAgent: true,
  country: true,
  network: true,
  createdAt: true,
} satisfies Prisma.AccountEventSelect;

export type EventRow = Prisma.AccountEventGetPayload<{
  select: typeof VIEW_SELECT;
}>;

/** The person's own view (AC-11): every field of their own data, the actor only as a kind. */
export function ownView(row: EventRow): EventView {
  return {
    id: row.id,
    category: row.category,
    type: row.type,
    reason: row.reason,
    system: row.system,
    sessionId: row.sessionId,
    client: row.clientId,
    field: row.field,
    oldValue: row.oldValue,
    newValue: row.newValue,
    attemptsLeft: row.attemptsLeft,
    address: row.ip,
    localNetwork: isLocalAddress(row.ip),
    device: row.device,
    userAgent: row.userAgent,
    country: row.country,
    network: row.network,
    createdAt: row.createdAt.toISOString(),
    actor: { kind: actorKind(row) },
  };
}

/**
 * The one writer of `account_events` (spec 0011). Every write runs inside the transaction of the
 * action it records (AC-7), so callers pass their `tx`.
 */
@Injectable()
export class AccountEventsService {
  constructor(private readonly prisma: PrismaService) {}

  /** The row to insert for an input. */
  rowOf(input: EventInput): Prisma.AccountEventCreateManyInput {
    const meta = input.meta ?? NO_META;
    return {
      userId: input.userId,
      actorId: input.actorId ?? null,
      category: TYPE_CATEGORY[input.type],
      type: input.type,
      reason: input.reason ?? null,
      system: input.system ?? null,
      sessionId: input.sessionId ?? null,
      clientId: input.clientId ?? null,
      field: input.field ?? null,
      oldValue: input.oldValue ?? null,
      newValue: input.newValue ?? null,
      attemptsLeft: input.attemptsLeft ?? null,
      ip: meta.ip,
      device: meta.device,
      userAgent: meta.userAgent,
    };
  }

  async record(db: Db, input: EventInput): Promise<void> {
    await db.accountEvent.create({ data: this.rowOf(input) });
  }

  async recordMany(db: Db, inputs: EventInput[]): Promise<void> {
    if (inputs.length === 0) return;
    await db.accountEvent.createMany({
      data: inputs.map((input) => this.rowOf(input)),
    });
  }

  /** `GET /auth/profile/activity` (AC-11): the caller's own events from every system. */
  async listOwn(userId: string, filters: ActivityFilters): Promise<EventPage> {
    const rows = await this.prisma.accountEvent.findMany({
      where: {
        userId,
        ...(filters.categories ? { category: { in: filters.categories } } : {}),
        ...keysetWhere(filters),
      },
      select: VIEW_SELECT,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: filters.limit + 1,
    });
    return pageOf(rows, filters.limit, ownView);
  }
}

/** `(created_at, id) < cursor`, and the date bounds, as a Prisma filter. */
export function keysetWhere(
  filters: Pick<ActivityFilters, 'cursor' | 'from' | 'before'>,
): Prisma.AccountEventWhereInput {
  const and: Prisma.AccountEventWhereInput[] = [];
  if (filters.cursor) {
    const { createdAt, id } = filters.cursor;
    and.push({
      OR: [{ createdAt: { lt: createdAt } }, { createdAt, id: { lt: id } }],
    });
  }
  if (filters.from) and.push({ createdAt: { gte: filters.from } });
  if (filters.before) and.push({ createdAt: { lt: filters.before } });
  return and.length > 0 ? { AND: and } : {};
}

/** Cuts the `limit + 1` rows to a page; the extra row only sets `nextCursor`. */
export function pageOf<R extends { createdAt: Date; id: string }, V>(
  rows: R[],
  limit: number,
  view: (row: R) => V,
): EventPage<V> {
  const page = rows.slice(0, limit);
  return {
    data: page.map(view),
    nextCursor:
      rows.length > limit ? encodeEventCursor(page[page.length - 1]) : null,
  };
}
