import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../shared/prisma.service';
import {
  FEED_START,
  decodeFeedCursor,
  decodePageCursor,
  encodeFeedCursor,
  encodePageCursor,
  type FeedPosition,
} from './directory-cursor';
import {
  fromSnapshot,
  fromUserRow,
  type DirectoryChange,
  type DirectoryChangeType,
  type DirectoryUser,
  type DirectoryView,
  type FeedSnapshot,
} from './directory-user';

type FeedRow = {
  seq: bigint;
  txid: string;
  type: DirectoryChangeType;
  snapshot: FeedSnapshot;
  created_at: Date;
};

const USER_SELECT = {
  id: true,
  name: true,
  email: true,
  contact: true,
  profilePicture: true,
  isActive: true,
  deletedAt: true,
  erasedAt: true,
  updatedAt: true,
  roles: { select: { system: true, role: true, temporaryGrantId: true } },
} satisfies Prisma.UserSelect;

/**
 * The user directory for system backends (spec 0005). Reads run as plain statements, never in
 * an interactive transaction: an old snapshot would only hold the feed back.
 */
@Injectable()
export class DirectoryService {
  constructor(private readonly prisma: PrismaService) {}

  /** `directory_feed.epoch`, read per call so a restored database is noticed at once. */
  async epoch(): Promise<string> {
    const feed = await this.prisma.directoryFeed.findUniqueOrThrow({
      where: { id: true },
      select: { epoch: true },
    });
    return feed.epoch;
  }

  /**
   * The safe point: the last feed row whose transaction is older than every transaction still
   * running. Every row at or below it is committed, and no later commit can land below it.
   */
  async safePoint(): Promise<FeedPosition> {
    const rows = await this.prisma.$queryRaw<{ txid: string; seq: bigint }[]>`
      SELECT "txid"::text AS "txid", "seq"
        FROM "directory_changes"
       WHERE "txid" < pg_snapshot_xmin(pg_current_snapshot())
       ORDER BY "directory_changes"."txid" DESC, "directory_changes"."seq" DESC
       LIMIT 1`;
    return rows.length === 0
      ? FEED_START
      : { txid: BigInt(rows[0].txid), seq: BigInt(rows[0].seq) };
  }

  /** AC-4: one page of everyone who holds a role in the caller's system, by id. */
  async listUsers(
    view: DirectoryView,
    cursor: string | undefined,
    limit: number,
  ): Promise<{
    users: DirectoryUser[];
    next: string | null;
    changesCursor: string;
  }> {
    const afterId = cursor === undefined ? undefined : decodePageCursor(cursor);
    const epoch = await this.epoch();
    // Taken in a statement before the scan, so a reader starting here misses nothing
    const safe = await this.safePoint();

    const rows = await this.prisma.user.findMany({
      where: {
        roles: { some: { system: view.system } },
        ...(afterId === undefined ? {} : { id: { gt: afterId } }),
      },
      orderBy: { id: 'asc' },
      take: limit + 1,
      select: USER_SELECT,
    });
    const page = rows.slice(0, limit);

    return {
      users: page.map((row) => fromUserRow(row, view)),
      next:
        rows.length > limit ? encodePageCursor(page[page.length - 1].id) : null,
      changesCursor: encodeFeedCursor(epoch, safe),
    };
  }

  /** AC-5: the caller's changes after `after`, in `(txid, seq)` order, up to the safe point. */
  async changes(
    view: DirectoryView,
    after: string | undefined,
    limit: number,
  ): Promise<{ changes: DirectoryChange[]; next: string; hasMore: boolean }> {
    const epoch = await this.epoch();
    const from =
      after === undefined ? FEED_START : decodeFeedCursor(after, epoch);
    const safe = await this.safePoint();

    const rows = await this.prisma.$queryRaw<FeedRow[]>`
      SELECT "seq", "txid"::text AS "txid", "type", "snapshot", "created_at"
        FROM "directory_changes"
       WHERE ("txid", "seq") > (${from.txid.toString()}::xid8, ${from.seq})
         AND ("txid", "seq") <= (${safe.txid.toString()}::xid8, ${safe.seq})
         AND "systems" @> ARRAY[${view.system}::"SystemType"]
       ORDER BY "directory_changes"."txid", "directory_changes"."seq"
       LIMIT ${limit + 1}`;

    const hasMore = rows.length > limit;
    const page = rows.slice(0, limit);
    const changes = page.map((row) => ({
      cursor: encodeFeedCursor(epoch, {
        txid: BigInt(row.txid),
        seq: BigInt(row.seq),
      }),
      type: row.type,
      at: row.created_at.toISOString(),
      user: fromSnapshot(row.snapshot, view),
    }));

    // A short page moves the reader to the safe point (every row it returned is at or below
    // it), so a system with few people doesn't scan the same rows again. A reader already past
    // the safe point (never expected) stays where it is.
    const next = hasMore
      ? changes[changes.length - 1].cursor
      : encodeFeedCursor(epoch, comparePositions(safe, from) > 0 ? safe : from);

    return { changes, next, hasMore };
  }
  /**
   * AC-6: current state of the asked ids that hold, or ever held, a role in the caller's system
   * (a role row now, or a feed row naming the system). Every other id, unknown and hard deleted
   * ones included, is in `missing`. Reads current state, so it has no lag.
   */
  async lookup(
    view: DirectoryView,
    ids: string[],
  ): Promise<{ users: DirectoryUser[]; missing: string[] }> {
    const wanted = ids.map((id) => id.toLowerCase());
    const [rows, history] = await Promise.all([
      this.prisma.user.findMany({
        where: { id: { in: wanted } },
        select: USER_SELECT,
      }),
      this.prisma.$queryRaw<{ user_id: string }[]>`
        SELECT DISTINCT "user_id"::text AS "user_id"
          FROM "directory_changes"
         WHERE "user_id" = ANY(${wanted}::uuid[])
           AND "systems" @> ARRAY[${view.system}::"SystemType"]`,
    ]);
    const onceHeld = new Set(history.map((row) => row.user_id));
    const byId = new Map(
      rows
        .filter(
          (row) =>
            onceHeld.has(row.id) ||
            row.roles.some((assignment) => assignment.system === view.system),
        )
        .map((row) => [row.id, row]),
    );

    const users: DirectoryUser[] = [];
    const missing: string[] = [];
    wanted.forEach((id, index) => {
      const row = byId.get(id);
      if (row) users.push(fromUserRow(row, view));
      else missing.push(ids[index]);
    });
    return { users, missing };
  }
}

export function comparePositions(a: FeedPosition, b: FeedPosition): number {
  if (a.txid !== b.txid) return a.txid < b.txid ? -1 : 1;
  if (a.seq !== b.seq) return a.seq < b.seq ? -1 : 1;
  return 0;
}
