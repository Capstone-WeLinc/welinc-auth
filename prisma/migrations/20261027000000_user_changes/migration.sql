-- Spec 0009, AC-20: a record of every admin change to a user.

-- CreateEnum
CREATE TYPE "UserChangeAction" AS ENUM ('CREATED', 'UPDATED', 'ROLE_CHANGED', 'ACTIVATED', 'DEACTIVATED', 'UNLOCKED', 'RESET_SENT', 'DELETED');

-- CreateTable
CREATE TABLE "user_changes" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "actor_id" UUID NOT NULL,
    "actor_email" VARCHAR(255) NOT NULL,
    "action" "UserChangeAction" NOT NULL,
    "field" VARCHAR(50),
    "old_value" TEXT,
    "new_value" TEXT,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "user_changes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "user_changes_user_id_created_at_id_idx" ON "user_changes"("user_id", "created_at" DESC, "id" DESC);

-- AddForeignKey
ALTER TABLE "user_changes" ADD CONSTRAINT "user_changes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_changes" ADD CONSTRAINT "user_changes_actor_id_fkey" FOREIGN KEY ("actor_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

