-- Suite spec 0017, AC-22: when the person last signed in (the web sign in or a native login),
-- for the People list's "Last signed in" sort and the person page facts. Milliseconds, so a
-- keyset cursor round trip through JavaScript never loses precision. Written forward only, in
-- the sign in's own transaction (session.service.ts); a refresh or SYSTEM_OPENED never moves it.
ALTER TABLE "users" ADD COLUMN "last_signed_in_at" TIMESTAMPTZ(3);

-- Backfill from each account's newest kept SIGNED_IN event. Sign ins the event retention sweep
-- already removed are gone, so those accounts start as null ("Never"). The directory trigger
-- compares snapshots and this column isn't in one, so the backfill writes no feed rows.
UPDATE "users" u
SET "last_signed_in_at" = e."at"
FROM (
    SELECT "user_id", MAX("created_at") AS "at"
    FROM "account_events"
    WHERE "type" = 'SIGNED_IN'
    GROUP BY "user_id"
) e
WHERE e."user_id" = u."id";

-- The "Last signed in" order: newest first, never signed in last, then id (AC-20).
CREATE INDEX "users_last_signed_in_at_id_idx" ON "users" ("last_signed_in_at" DESC NULLS LAST, "id");
