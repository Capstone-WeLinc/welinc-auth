-- Spec 0012, build plan task 3: erasure. Hand written (functions only, no tables).
--
-- 1. AC-16: account_events stays append only, with one narrow way through: inside a transaction
--    that ran set_config('welinc.erasure', 'on', true), an UPDATE may only blank the personal
--    columns (ip, device, user_agent, country, network, asn), and old_value and new_value only on
--    rows whose field is name, email, contact or profilePicture. Every other column must stay
--    equal, compared one by one. Anything else raises as before. DELETE keeps its rules.
-- 2. AC-17: directory_snapshot() carries erasedAt, so the feed can say a person is erased. A
--    snapshot written before this migration has no erasedAt key; the "nothing changed" check
--    reads a missing key as null, so this migration alone writes no feed rows.

CREATE OR REPLACE FUNCTION "account_events_append_only"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF current_setting('welinc.erasure', true) = 'on'
       -- Never changed by an erasure
       AND NEW."id" = OLD."id"
       AND NEW."user_id" = OLD."user_id"
       AND NEW."actor_id" IS NOT DISTINCT FROM OLD."actor_id"
       AND NEW."category" = OLD."category"
       AND NEW."type" = OLD."type"
       AND NEW."reason" IS NOT DISTINCT FROM OLD."reason"
       AND NEW."system" IS NOT DISTINCT FROM OLD."system"
       AND NEW."session_id" IS NOT DISTINCT FROM OLD."session_id"
       AND NEW."client_id" IS NOT DISTINCT FROM OLD."client_id"
       AND NEW."field" IS NOT DISTINCT FROM OLD."field"
       AND NEW."attempts_left" IS NOT DISTINCT FROM OLD."attempts_left"
       AND NEW."created_at" = OLD."created_at"
       -- The personal columns may only become null
       AND (NEW."ip" IS NULL OR NEW."ip" IS NOT DISTINCT FROM OLD."ip")
       AND (NEW."device" IS NULL OR NEW."device" IS NOT DISTINCT FROM OLD."device")
       AND (NEW."user_agent" IS NULL OR NEW."user_agent" IS NOT DISTINCT FROM OLD."user_agent")
       AND (NEW."country" IS NULL OR NEW."country" IS NOT DISTINCT FROM OLD."country")
       AND (NEW."network" IS NULL OR NEW."network" IS NOT DISTINCT FROM OLD."network")
       AND (NEW."asn" IS NULL OR NEW."asn" IS NOT DISTINCT FROM OLD."asn")
       -- The values only on a personal field, and only to null
       AND (NEW."old_value" IS NOT DISTINCT FROM OLD."old_value"
            OR (NEW."old_value" IS NULL AND OLD."field" IN ('name', 'email', 'contact', 'profilePicture')))
       AND (NEW."new_value" IS NOT DISTINCT FROM OLD."new_value"
            OR (NEW."new_value" IS NULL AND OLD."field" IN ('name', 'email', 'contact', 'profilePicture')))
    THEN
      RETURN NEW;
    END IF;
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

-- The person as systems see them, now with erasedAt (spec 0012, AC-17)
CREATE OR REPLACE FUNCTION directory_snapshot(p_user_id UUID) RETURNS JSONB
LANGUAGE sql STABLE AS $$
    SELECT jsonb_build_object(
        'id', u."id",
        'name', u."name",
        'email', u."email",
        'contact', u."contact",
        'profilePicture', u."profile_picture",
        'isActive', u."is_active",
        'deletedAt', u."deleted_at",
        'erasedAt', u."erased_at",
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

-- As in 20261111000000_directory_feed, plus erasedAt on a hard delete and in the compare
CREATE OR REPLACE FUNCTION directory_write_change(p_user_id UUID, p_deleted_row JSONB) RETURNS VOID
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
            'erasedAt', COALESCE(p_deleted_row -> 'erased_at', 'null'::jsonb),
            'updatedAt', p_deleted_row -> 'updated_at',
            'roles', COALESCE(v_prev -> 'roles', '[]'::jsonb)
        );
        IF v_snap -> 'deletedAt' = 'null'::jsonb THEN
            v_snap := jsonb_set(v_snap, '{deletedAt}', to_jsonb(CURRENT_TIMESTAMP));
        END IF;
    END IF;

    -- Nothing a system can see changed: no row. A missing erasedAt (older rows) reads as null.
    IF v_prev IS NOT NULL
       AND (v_snap - 'updatedAt' - 'erasedAt') = (v_prev - 'updatedAt' - 'erasedAt')
       AND COALESCE(v_snap -> 'erasedAt', 'null'::jsonb) = COALESCE(v_prev -> 'erasedAt', 'null'::jsonb) THEN
        DELETE FROM "directory_changes"
         WHERE "txid" = v_txid AND "user_id" = p_user_id;
        RETURN;
    END IF;

    -- First match wins. An erasure stays `updated`: readers check `erased` (spec 0012)
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
