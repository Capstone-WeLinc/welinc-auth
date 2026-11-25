-- Suite spec 0018, phase 1 (additive): custom role columns on system_roles, default_roles on
-- system_permissions, the append only role_events table, and a per role index on
-- permission_changes. The tables and columns come from `prisma migrate diff`; the CHECK, the
-- partial unique index, the trigger and the default_roles fill are hand written. Today's
-- portal, VMMS, BMS and VRMS keep working unchanged: every new column is defaulted or null.

-- CreateEnum
CREATE TYPE "RoleEventKind" AS ENUM ('CREATED', 'RENAMED', 'DESCRIBED', 'DELETED');

-- AlterTable: the built in roles whose catalog default is on (written only by catalog:sync)
ALTER TABLE "system_permissions" ADD COLUMN "default_roles" VARCHAR(40)[] NOT NULL DEFAULT ARRAY[]::VARCHAR(40)[];

-- AlterTable: every existing role stays built in
ALTER TABLE "system_roles" ADD COLUMN "copied_from" VARCHAR(40),
ADD COLUMN "created_by_id" UUID,
ADD COLUMN "deleted_at" TIMESTAMPTZ(6),
ADD COLUMN "is_built_in" BOOLEAN NOT NULL DEFAULT true;

-- A custom role is never the system admin role
ALTER TABLE "system_roles" ADD CONSTRAINT "system_roles_custom_not_admin"
  CHECK ("is_built_in" OR NOT "is_system_admin");

-- Live custom role names are unique per system, ignoring case. Built in names are left out on
-- purpose: catalog:sync never checks names, so a later built in rename can't fail a deploy (the
-- create and rename routes refuse a custom name equal to a live built in one instead).
CREATE UNIQUE INDEX "system_roles_custom_name_key" ON "system_roles" ("system", lower("name"))
  WHERE "deleted_at" IS NULL AND NOT "is_built_in";

-- CreateTable
CREATE TABLE "role_events" (
    "id" UUID NOT NULL,
    "system" "SystemType" NOT NULL,
    "role" VARCHAR(40) NOT NULL,
    "kind" "RoleEventKind" NOT NULL,
    "from_value" VARCHAR(200),
    "to_value" VARCHAR(200),
    "actor_id" UUID,
    "actor_name" VARCHAR(100),
    "actor_email" VARCHAR(255),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "role_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "role_events_system_role_created_at_id_idx" ON "role_events"("system", "role", "created_at" DESC, "id" DESC);

-- CreateIndex: one role's History and lastChanged
CREATE INDEX "permission_changes_system_role_created_at_id_idx" ON "permission_changes"("system", "role", "created_at" DESC, "id" DESC);

-- AddForeignKey
ALTER TABLE "role_events" ADD CONSTRAINT "role_events_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "system_roles" ADD CONSTRAINT "system_roles_created_by_id_fkey" FOREIGN KEY ("created_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- role_events is append only, like permission_changes (spec 0013): inside a transaction that ran
-- set_config('welinc.erasure', 'on', true), an UPDATE may only blank actor_name and actor_email.
-- DELETE always raises; TRUNCATE is allowed (the local seed --reset).
CREATE FUNCTION "role_events_append_only"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND current_setting('welinc.erasure', true) = 'on'
     AND NEW."id" = OLD."id"
     AND NEW."system" = OLD."system"
     AND NEW."role" = OLD."role"
     AND NEW."kind" = OLD."kind"
     AND NEW."from_value" IS NOT DISTINCT FROM OLD."from_value"
     AND NEW."to_value" IS NOT DISTINCT FROM OLD."to_value"
     AND NEW."actor_id" IS NOT DISTINCT FROM OLD."actor_id"
     AND NEW."created_at" = OLD."created_at"
     AND (NEW."actor_name" IS NULL OR NEW."actor_name" IS NOT DISTINCT FROM OLD."actor_name")
     AND (NEW."actor_email" IS NULL OR NEW."actor_email" IS NOT DISTINCT FROM OLD."actor_email")
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'role_events is append only: % is not allowed', TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "role_events_append_only"
  BEFORE UPDATE OR DELETE ON "role_events"
  FOR EACH ROW EXECUTE FUNCTION "role_events_append_only"();

-- Fill default_roles once from the catalog as it stands (prisma/catalog/vrms.ts), so the first
-- catalog:sync after this migration reports no change. Keys not listed (none today) stay empty
-- until the sync writes them.
UPDATE "system_permissions" AS p
   SET "default_roles" = v.roles
  FROM (VALUES
  ('VRMS', 'ticket.view', ARRAY['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.view_all', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.create', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'ticket.work', ARRAY['CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.administer', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'ticket.verify', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.costs.view', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.costs.edit', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'ticket.assign', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.edit', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'ticket.unlock', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'ticket.checklist.edit', ARRAY['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.files.add', ARRAY['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.documents.add', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ticket.files.remove_any', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'ai.use', ARRAY['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'audit.view', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'analytics.view', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'config.read', ARRAY['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'mechanics.view', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'vehicle.manage', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'knowledge.view', ARRAY['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'knowledge.suggest', ARRAY['ADMIN', 'CHIEF_MECHANIC', 'MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'knowledge.edit', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[]),
  ('VRMS', 'team.manage', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'settings.manage', ARRAY['ADMIN']::VARCHAR(40)[]),
  ('VRMS', 'lookups.manage', ARRAY['ADMIN', 'CHIEF_MECHANIC']::VARCHAR(40)[])
  ) AS v(system, key, roles)
 WHERE p."system" = v.system::"SystemType" AND p."key" = v.key;
