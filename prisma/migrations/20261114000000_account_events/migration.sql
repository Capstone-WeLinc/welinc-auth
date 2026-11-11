-- Spec 0011: one append only account_events table replaces user_changes (AC-8, AC-10).

-- CreateEnum
CREATE TYPE "AccountEventCategory" AS ENUM ('SIGN_IN', 'SESSION', 'CODE', 'ACCOUNT');

-- CreateEnum
CREATE TYPE "AccountEventType" AS ENUM (
  'SIGNED_IN', 'SIGN_IN_FAILED', 'LOCKED_OUT',
  'SYSTEM_OPENED', 'SIGNED_OUT', 'SESSION_ENDED',
  'CODE_SENT', 'CODE_MAIL_FAILED', 'CODE_USED', 'CODE_RETIRED',
  'CREATED', 'UPDATED', 'ROLE_CHANGED', 'ACTIVATED', 'DEACTIVATED', 'UNLOCKED', 'DELETED',
  'SESSIONS_ENDED', 'PASSWORD_CHANGED', 'PICTURE_CHANGED'
);

-- CreateTable
CREATE TABLE "account_events" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "actor_id" UUID,
    "category" "AccountEventCategory" NOT NULL,
    "type" "AccountEventType" NOT NULL,
    "reason" VARCHAR(40),
    "system" "SystemType",
    "session_id" UUID,
    "client_id" TEXT,
    "field" VARCHAR(50),
    "old_value" TEXT,
    "new_value" TEXT,
    "attempts_left" SMALLINT,
    "ip" INET,
    "device" VARCHAR(100),
    "user_agent" VARCHAR(512),
    "country" CHAR(2),
    "network" VARCHAR(120),
    "asn" INTEGER,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "account_events_pkey" PRIMARY KEY ("id"),
    -- Written from TYPE_CATEGORY in src/auth/events/event-types.ts (a unit test keeps them equal)
    CONSTRAINT "account_events_type_category_check" CHECK (
      ("category" = 'SIGN_IN' AND "type" IN ('SIGNED_IN', 'SIGN_IN_FAILED', 'LOCKED_OUT'))
      OR ("category" = 'SESSION' AND "type" IN ('SYSTEM_OPENED', 'SIGNED_OUT', 'SESSION_ENDED'))
      OR ("category" = 'CODE' AND "type" IN ('CODE_SENT', 'CODE_MAIL_FAILED', 'CODE_USED', 'CODE_RETIRED'))
      OR ("category" = 'ACCOUNT' AND "type" IN ('CREATED', 'UPDATED', 'ROLE_CHANGED', 'ACTIVATED',
        'DEACTIVATED', 'UNLOCKED', 'DELETED', 'SESSIONS_ENDED', 'PASSWORD_CHANGED', 'PICTURE_CHANGED'))
    )
);

-- CreateIndex
CREATE INDEX "account_events_user_id_created_at_id_idx" ON "account_events"("user_id", "created_at" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "account_events_system_created_at_id_idx" ON "account_events"("system", "created_at" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "account_events_created_at_id_idx" ON "account_events"("created_at" DESC, "id" DESC);

-- CreateIndex
CREATE INDEX "account_events_ip_created_at_idx" ON "account_events"("ip", "created_at" DESC);

-- AddForeignKey
ALTER TABLE "account_events" ADD CONSTRAINT "account_events_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_events" ADD CONSTRAINT "account_events_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AC-8: append only. UPDATE always raises. DELETE raises for ACCOUNT rows always, and for other
-- rows unless the sweep set welinc.event_sweep to 'on' in its own transaction (an unset setting
-- reads as null). TRUNCATE skips row triggers; only the local seed --reset uses it.
CREATE FUNCTION "account_events_append_only"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'account_events is append only: UPDATE is not allowed'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD."category" = 'ACCOUNT' THEN
    RAISE EXCEPTION 'account_events is append only: ACCOUNT rows are kept forever'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF current_setting('welinc.event_sweep', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'account_events is append only: only the sweep deletes old rows'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN OLD;
END;
$$;

CREATE TRIGGER "account_events_append_only"
  BEFORE UPDATE OR DELETE ON "account_events"
  FOR EACH ROW EXECUTE FUNCTION "account_events_append_only"();

-- AC-10: copy every user_changes row. RESET_SENT becomes CODE_SENT with reason PASSWORD_RESET.
INSERT INTO "account_events" ("id", "user_id", "actor_id", "category", "type", "reason", "field", "old_value", "new_value", "created_at")
SELECT
  uc."id",
  uc."user_id",
  uc."actor_id",
  (CASE WHEN uc."action" = 'RESET_SENT' THEN 'CODE' ELSE 'ACCOUNT' END)::"AccountEventCategory",
  (CASE WHEN uc."action" = 'RESET_SENT' THEN 'CODE_SENT' ELSE uc."action"::text END)::"AccountEventType",
  CASE WHEN uc."action" = 'RESET_SENT' THEN 'PASSWORD_RESET' END,
  uc."field",
  uc."old_value",
  uc."new_value",
  uc."created_at"
FROM "user_changes" uc
WHERE uc."action" <> 'ROLE_CHANGED';

-- ROLE_CHANGED rows split per system: each side's `ROLE@SYSTEM` entries grouped by system,
-- a row only for a system whose two sides differ (null for an empty side). The first split row
-- of each (by system order) keeps the old id; the others get a new one.
WITH entries AS (
  SELECT uc."id", side.kind, side.entry, split_part(side.entry, '@', 2) AS sys
  FROM "user_changes" uc
  CROSS JOIN LATERAL (
    SELECT 'old' AS kind, unnest(string_to_array(uc."old_value", ',')) AS entry
    UNION ALL
    SELECT 'new', unnest(string_to_array(uc."new_value", ','))
  ) side
  WHERE uc."action" = 'ROLE_CHANGED' AND side.entry <> ''
),
per_system AS (
  SELECT
    "id",
    sys,
    string_agg(entry, ',' ORDER BY entry) FILTER (WHERE kind = 'old') AS old_value,
    string_agg(entry, ',' ORDER BY entry) FILTER (WHERE kind = 'new') AS new_value
  FROM entries
  WHERE sys IN ('VRMS', 'VMMS', 'BMS')
  GROUP BY "id", sys
),
changed AS (
  SELECT ps.*, row_number() OVER (PARTITION BY ps."id" ORDER BY ps.sys) AS n
  FROM per_system ps
  WHERE ps.old_value IS DISTINCT FROM ps.new_value
)
INSERT INTO "account_events" ("id", "user_id", "actor_id", "category", "type", "system", "field", "old_value", "new_value", "created_at")
SELECT
  CASE WHEN c.n = 1 THEN uc."id" ELSE gen_random_uuid() END,
  uc."user_id",
  uc."actor_id",
  'ACCOUNT',
  'ROLE_CHANGED',
  c.sys::"SystemType",
  uc."field",
  c.old_value,
  c.new_value,
  uc."created_at"
FROM changed c
JOIN "user_changes" uc ON uc."id" = c."id";

-- A ROLE_CHANGED row with no system that differs (none expected) is kept whole, account wide,
-- so no history is lost.
INSERT INTO "account_events" ("id", "user_id", "actor_id", "category", "type", "field", "old_value", "new_value", "created_at")
SELECT uc."id", uc."user_id", uc."actor_id", 'ACCOUNT', 'ROLE_CHANGED', uc."field", uc."old_value", uc."new_value", uc."created_at"
FROM "user_changes" uc
WHERE uc."action" = 'ROLE_CHANGED'
  AND NOT EXISTS (SELECT 1 FROM "account_events" ae WHERE ae."id" = uc."id");

-- DropTable
DROP TABLE "user_changes";

-- DropEnum
DROP TYPE "UserChangeAction";
