-- Spec 0013, build plan tasks 12 and 14: temporary access, and the rule that a suite admin
-- holds no permanent system role.

-- CreateEnum
CREATE TYPE "TemporaryGrantEnd" AS ENUM ('EXPIRED', 'ENDED_EARLY', 'SUITE_ADMIN_REMOVED');

-- CreateTable: a suite admin's own role in one system for 1 to 8 hours (AC-9 to AC-11)
CREATE TABLE "temporary_grants" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "system" "SystemType" NOT NULL,
    "role" VARCHAR(40) NOT NULL,
    "reason" VARCHAR(500) NOT NULL,
    "started_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "ended_at" TIMESTAMPTZ(6),
    "end_reason" "TemporaryGrantEnd",
    "ended_by_id" UUID,

    CONSTRAINT "temporary_grants_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "temporary_grants_hours_check" CHECK (
        "expires_at" >= "started_at" + interval '1 hour'
        AND "expires_at" <= "started_at" + interval '8 hours'
    ),
    CONSTRAINT "temporary_grants_end_check" CHECK (
        ("ended_at" IS NULL AND "end_reason" IS NULL)
        OR ("ended_at" IS NOT NULL AND "end_reason" IS NOT NULL)
    )
);

ALTER TABLE "temporary_grants" ADD CONSTRAINT "temporary_grants_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "temporary_grants" ADD CONSTRAINT "temporary_grants_ended_by_id_fkey" FOREIGN KEY ("ended_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "temporary_grants" ADD CONSTRAINT "temporary_grants_system_role_fkey" FOREIGN KEY ("system", "role") REFERENCES "system_roles"("system", "code") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- One live grant per person and system; the minute sweep reads live grants by end time
CREATE UNIQUE INDEX "temporary_grants_live_key" ON "temporary_grants" ("user_id", "system") WHERE "ended_at" IS NULL;
CREATE INDEX "temporary_grants_live_expiry_idx" ON "temporary_grants" ("expires_at") WHERE "ended_at" IS NULL;
CREATE INDEX "temporary_grants_started_at_id_idx" ON "temporary_grants" ("started_at" DESC, "id" DESC);

-- AlterTable: a role row that a temporary grant gave
ALTER TABLE "user_roles" ADD COLUMN "temporary_grant_id" UUID;
CREATE UNIQUE INDEX "user_roles_temporary_grant_id_key" ON "user_roles" ("temporary_grant_id");
ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_temporary_grant_id_fkey" FOREIGN KEY ("temporary_grant_id") REFERENCES "temporary_grants"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AC-3: a suite admin holds no permanent role. Checked at commit (deferred), so a race or a
-- future write path can't break it. The service maps the error to 409 SUITE_ADMIN_NO_ROLES.
CREATE OR REPLACE FUNCTION suite_admin_no_roles() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM "user_roles" r
          JOIN "suite_admins" s ON s."user_id" = r."user_id"
         WHERE r."user_id" = NEW."user_id"
           AND r."temporary_grant_id" IS NULL
    ) THEN
        RAISE EXCEPTION 'suite_admin_no_roles: a suite admin holds no permanent system role'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER "user_roles_suite_admin_no_roles"
    AFTER INSERT OR UPDATE ON "user_roles"
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION suite_admin_no_roles();

CREATE CONSTRAINT TRIGGER "suite_admins_no_roles"
    AFTER INSERT ON "suite_admins"
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION suite_admin_no_roles();

-- The person as systems see them, now with `temporary` on each role (AC-11)
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
                        jsonb_build_object(
                            'system', r."system",
                            'role', r."role",
                            'temporary', r."temporary_grant_id" IS NOT NULL)
                        ORDER BY r."system", r."role")
               FROM "user_roles" r
              WHERE r."user_id" = u."id"),
            '[]'::jsonb)
    )
    FROM "users" u
    WHERE u."id" = p_user_id
$$;
