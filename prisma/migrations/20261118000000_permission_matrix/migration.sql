-- Spec 0013, build plan task 19 (AC-25): the central permission matrix. The tables come from
-- `prisma migrate diff`; the append only trigger at the end is hand written.
--
-- system_permissions and role_permissions are written by `npm run catalog:sync` (and the matrix
-- PATCH for unlocked cells); permission_matrices.version is the ETag systems poll with;
-- permission_changes keeps every changed cell.
-- CreateTable
CREATE TABLE "system_permissions" (
    "system" "SystemType" NOT NULL,
    "key" VARCHAR(60) NOT NULL,
    "label" VARCHAR(100) NOT NULL,
    "group" VARCHAR(40) NOT NULL,
    "description" VARCHAR(300) NOT NULL,
    "sort_order" INTEGER NOT NULL,
    "locked_roles" VARCHAR(40)[],

    CONSTRAINT "system_permissions_pkey" PRIMARY KEY ("system","key")
);

-- CreateTable
CREATE TABLE "role_permissions" (
    "system" "SystemType" NOT NULL,
    "role" VARCHAR(40) NOT NULL,
    "key" VARCHAR(60) NOT NULL,
    "allowed" BOOLEAN NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,
    "updated_by_id" UUID,

    CONSTRAINT "role_permissions_pkey" PRIMARY KEY ("system","role","key")
);

-- CreateTable
CREATE TABLE "permission_matrices" (
    "system" "SystemType" NOT NULL,
    "version" INTEGER NOT NULL DEFAULT 1,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "permission_matrices_pkey" PRIMARY KEY ("system")
);

-- CreateTable
CREATE TABLE "permission_changes" (
    "id" UUID NOT NULL,
    "system" "SystemType" NOT NULL,
    "role" VARCHAR(40) NOT NULL,
    "key" VARCHAR(60) NOT NULL,
    "before" BOOLEAN,
    "after" BOOLEAN,
    "actor_id" UUID,
    "actor_name" VARCHAR(100),
    "actor_email" VARCHAR(255),
    "note" VARCHAR(500),
    "imported" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "permission_changes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "permission_changes_system_created_at_id_idx" ON "permission_changes"("system", "created_at" DESC, "id" DESC);

-- AddForeignKey
ALTER TABLE "system_permissions" ADD CONSTRAINT "system_permissions_system_fkey" FOREIGN KEY ("system") REFERENCES "systems"("code") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_system_role_fkey" FOREIGN KEY ("system", "role") REFERENCES "system_roles"("system", "code") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_system_key_fkey" FOREIGN KEY ("system", "key") REFERENCES "system_permissions"("system", "key") ON DELETE CASCADE ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "role_permissions" ADD CONSTRAINT "role_permissions_updated_by_id_fkey" FOREIGN KEY ("updated_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "permission_matrices" ADD CONSTRAINT "permission_matrices_system_fkey" FOREIGN KEY ("system") REFERENCES "systems"("code") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AddForeignKey
ALTER TABLE "permission_changes" ADD CONSTRAINT "permission_changes_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;


-- permission_changes is append only (AC-27), with one narrow way through for erasure (spec
-- 0012): inside a transaction that ran set_config('welinc.erasure', 'on', true), an UPDATE may
-- only blank actor_name and actor_email. Every other column must stay equal. DELETE always
-- raises; TRUNCATE is allowed (the local seed --reset).
CREATE FUNCTION "permission_changes_append_only"() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND current_setting('welinc.erasure', true) = 'on'
     AND NEW."id" = OLD."id"
     AND NEW."system" = OLD."system"
     AND NEW."role" = OLD."role"
     AND NEW."key" = OLD."key"
     AND NEW."before" IS NOT DISTINCT FROM OLD."before"
     AND NEW."after" IS NOT DISTINCT FROM OLD."after"
     AND NEW."actor_id" IS NOT DISTINCT FROM OLD."actor_id"
     AND NEW."note" IS NOT DISTINCT FROM OLD."note"
     AND NEW."imported" = OLD."imported"
     AND NEW."created_at" = OLD."created_at"
     AND (NEW."actor_name" IS NULL OR NEW."actor_name" IS NOT DISTINCT FROM OLD."actor_name")
     AND (NEW."actor_email" IS NULL OR NEW."actor_email" IS NOT DISTINCT FROM OLD."actor_email")
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'permission_changes is append only: % is not allowed', TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER "permission_changes_append_only"
  BEFORE UPDATE OR DELETE ON "permission_changes"
  FOR EACH ROW EXECUTE FUNCTION "permission_changes_append_only"();
