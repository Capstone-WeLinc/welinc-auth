-- Spec 0005: the user directory change feed. Hand written (not `migrate dev` output): Prisma
-- can't express triggers or `xid8`. One transaction, in the order AC-1 sets: the feed row with
-- a new epoch, the changes table, the backfill, then the triggers.
--
-- How it works: a deferred trigger on `users` and `user_roles` runs at commit, rebuilds the
-- person's snapshot from the final state of the transaction and writes at most one row per
-- person per transaction (upsert on (txid, user_id)), or none when nothing a system can see
-- changed. If the function fails, the user write fails: there is no exception handler.
--
-- Changing a watched field or adding a role table means changing `directory_snapshot` below.
-- Never use TRUNCATE, COPY or session_replication_role = replica on users or user_roles: they
-- skip the triggers. Rollback: see down.sql next to this file.

BEGIN;

-- AC-1: the single feed row and its epoch (a restored or rebuilt database gets a new one)
CREATE TABLE "directory_feed" (
    "id" BOOLEAN NOT NULL DEFAULT true,
    "epoch" UUID NOT NULL DEFAULT gen_random_uuid(),

    CONSTRAINT "directory_feed_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "directory_feed_single_row" CHECK ("id")
);

INSERT INTO "directory_feed" DEFAULT VALUES;

-- AC-1: the feed. No foreign key to users, so a hard delete keeps its `deleted` row
CREATE TABLE "directory_changes" (
    "seq" BIGSERIAL NOT NULL,
    "txid" xid8 NOT NULL DEFAULT pg_current_xact_id(),
    "user_id" UUID NOT NULL,
    "type" TEXT NOT NULL,
    "systems" "SystemType"[] NOT NULL,
    "snapshot" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "directory_changes_pkey" PRIMARY KEY ("seq"),
    CONSTRAINT "directory_changes_type_check" CHECK (
        "type" IN ('created', 'updated', 'roles_changed', 'activated', 'deactivated', 'deleted')
    )
);

CREATE UNIQUE INDEX "directory_changes_txid_user_id_key" ON "directory_changes"("txid", "user_id");
CREATE INDEX "directory_changes_txid_seq_idx" ON "directory_changes"("txid", "seq");
CREATE INDEX "directory_changes_user_id_txid_seq_idx" ON "directory_changes"("user_id", "txid", "seq");
CREATE INDEX "directory_changes_systems_idx" ON "directory_changes" USING GIN ("systems");

-- The person as systems see them: roles sorted by system then role so equal states compare
-- equal. Null when the user row doesn't exist (a hard delete).
CREATE FUNCTION directory_snapshot(p_user_id UUID) RETURNS JSONB
LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object(
        'id', u."id",
        'name', u."name",
        'email', u."email",
        'contact', u."contact",
        'profilePicture', u."profile_picture",
        'isActive', u."is_active",
        'deletedAt', u."deleted_at",
        'updatedAt', u."updated_at",
        'roles', COALESCE(
            (SELECT jsonb_agg(
                        jsonb_build_object('system', r."system", 'role', r."role")
                        ORDER BY r."system", r."role")
               FROM "user_roles" r
              WHERE r."user_id" = u."id"),
            '[]'::jsonb)
    )
    FROM "users" u
    WHERE u."id" = p_user_id
$$;

-- The systems a snapshot's roles belong to
CREATE FUNCTION directory_snapshot_systems(p_snapshot JSONB) RETURNS "SystemType"[]
LANGUAGE sql IMMUTABLE AS $$
    SELECT COALESCE(
        array_agg(DISTINCT (r ->> 'system')::"SystemType" ORDER BY (r ->> 'system')::"SystemType"),
        '{}')
    FROM jsonb_array_elements(COALESCE(p_snapshot -> 'roles', '[]'::jsonb)) r
$$;

-- AC-2: write (or rebuild, or remove) this transaction's row for one person. `p_deleted_row` is
-- the old `users` row, passed only by a hard delete of the user.
CREATE FUNCTION directory_write_change(p_user_id UUID, p_deleted_row JSONB) RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE
    v_txid xid8 := pg_current_xact_id();
    v_snap JSONB;
    v_prev JSONB;
    v_type TEXT;
    v_hard_delete BOOLEAN := false;
BEGIN
    v_snap := directory_snapshot(p_user_id);

    -- The previous state: the person's latest row from another transaction
    SELECT c."snapshot" INTO v_prev
      FROM "directory_changes" c
     WHERE c."user_id" = p_user_id AND c."txid" <> v_txid
     ORDER BY c."txid" DESC, c."seq" DESC
     LIMIT 1;

    IF v_snap IS NULL THEN
        -- The user row is gone at commit. Only the users delete itself knows the old row; a
        -- later firing for the cascaded role rows leaves what it wrote alone.
        IF p_deleted_row IS NULL THEN
            RETURN;
        END IF;
        v_hard_delete := true;
        v_snap := jsonb_build_object(
            'id', p_deleted_row -> 'id',
            'name', p_deleted_row -> 'name',
            'email', p_deleted_row -> 'email',
            'contact', p_deleted_row -> 'contact',
            'profilePicture', p_deleted_row -> 'profile_picture',
            'isActive', p_deleted_row -> 'is_active',
            'deletedAt', COALESCE(p_deleted_row -> 'deleted_at', 'null'::jsonb),
            'updatedAt', p_deleted_row -> 'updated_at',
            'roles', COALESCE(v_prev -> 'roles', '[]'::jsonb)
        );
        IF v_snap -> 'deletedAt' = 'null'::jsonb THEN
            v_snap := jsonb_set(v_snap, '{deletedAt}', to_jsonb(CURRENT_TIMESTAMP));
        END IF;
    END IF;

    -- Nothing a system can see changed: no row for this transaction
    IF v_prev IS NOT NULL AND (v_snap - 'updatedAt') = (v_prev - 'updatedAt') THEN
        DELETE FROM "directory_changes"
         WHERE "txid" = v_txid AND "user_id" = p_user_id;
        RETURN;
    END IF;

    -- First match wins
    IF v_hard_delete THEN
        v_type := 'deleted';
    ELSIF v_prev IS NULL THEN
        v_type := 'created';
    ELSIF v_snap -> 'deletedAt' <> 'null'::jsonb AND v_prev -> 'deletedAt' = 'null'::jsonb THEN
        v_type := 'deleted';
    ELSIF (v_prev -> 'isActive')::boolean AND NOT (v_snap -> 'isActive')::boolean THEN
        v_type := 'deactivated';
    ELSIF NOT (v_prev -> 'isActive')::boolean AND (v_snap -> 'isActive')::boolean THEN
        v_type := 'activated';
    ELSIF (v_prev -> 'roles') <> (v_snap -> 'roles') THEN
        v_type := 'roles_changed';
    ELSE
        v_type := 'updated';
    END IF;

    INSERT INTO "directory_changes" ("txid", "user_id", "type", "systems", "snapshot")
    VALUES (
        v_txid,
        p_user_id,
        v_type,
        ARRAY(
            SELECT DISTINCT s
              FROM unnest(directory_snapshot_systems(v_snap) || directory_snapshot_systems(v_prev)) s
             ORDER BY s
        ),
        v_snap
    )
    ON CONFLICT ("txid", "user_id") DO UPDATE
       SET "type" = EXCLUDED."type",
           "systems" = EXCLUDED."systems",
           "snapshot" = EXCLUDED."snapshot";
END;
$$;

-- The trigger function for both tables
CREATE FUNCTION directory_record_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'users' THEN
        IF TG_OP = 'DELETE' THEN
            PERFORM directory_write_change(OLD."id", to_jsonb(OLD));
        ELSE
            PERFORM directory_write_change(NEW."id", NULL);
        END IF;
    ELSE
        IF TG_OP IN ('UPDATE', 'DELETE') THEN
            PERFORM directory_write_change(OLD."user_id", NULL);
        END IF;
        IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND NEW."user_id" <> OLD."user_id") THEN
            PERFORM directory_write_change(NEW."user_id", NULL);
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

-- AC-1: the backfill, one `created` row for everyone who holds a role (soft deleted included)
INSERT INTO "directory_changes" ("user_id", "type", "systems", "snapshot")
SELECT u."id", 'created', directory_snapshot_systems(directory_snapshot(u."id")), directory_snapshot(u."id")
  FROM "users" u
 WHERE EXISTS (SELECT 1 FROM "user_roles" r WHERE r."user_id" = u."id")
 ORDER BY u."id";

-- AC-2: deferred, so each firing sees the final state of its transaction
CREATE CONSTRAINT TRIGGER "directory_users_change"
    AFTER INSERT OR UPDATE OR DELETE ON "users"
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION directory_record_change();

CREATE CONSTRAINT TRIGGER "directory_user_roles_change"
    AFTER INSERT OR UPDATE OR DELETE ON "user_roles"
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION directory_record_change();

-- A forgotten open transaction would hold the feed's safe point back (spec 0005, decided calls)
ALTER ROLE CURRENT_USER SET idle_in_transaction_session_timeout = '60s';

COMMIT;
