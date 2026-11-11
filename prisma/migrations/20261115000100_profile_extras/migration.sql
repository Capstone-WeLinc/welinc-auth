-- Spec 0012: password recheck and account deletion requests (build plan task 1).

-- CreateEnum
CREATE TYPE "DeletionRequestStatus" AS ENUM ('PENDING', 'CANCELLED', 'REJECTED', 'APPROVED', 'RESTORED', 'ERASED');

-- CreateEnum
CREATE TYPE "ReauthPurpose" AS ENUM ('ACCOUNT_DELETION');

-- AlterTable: "in grace" is deleted_at set and erased_at null
ALTER TABLE "users" ADD COLUMN "erased_at" TIMESTAMPTZ(6);

-- CreateTable
CREATE TABLE "account_deletion_requests" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "status" "DeletionRequestStatus" NOT NULL DEFAULT 'PENDING',
    "reason" VARCHAR(500),
    "requested_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "decided_by_id" UUID,
    "decided_system" "SystemType",
    "decided_at" TIMESTAMPTZ(6),
    "decision_note" VARCHAR(500),
    "cancelled_at" TIMESTAMPTZ(6),
    "restored_at" TIMESTAMPTZ(6),
    "restored_by_id" UUID,
    "erased_at" TIMESTAMPTZ(6),

    CONSTRAINT "account_deletion_requests_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reauth_tokens" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "purpose" "ReauthPurpose" NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "used_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "reauth_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "account_deletion_requests_status_requested_at_idx" ON "account_deletion_requests"("status", "requested_at");

-- CreateIndex
CREATE INDEX "account_deletion_requests_user_id_idx" ON "account_deletion_requests"("user_id");

-- Key invariant: at most one PENDING request per person (a clash answers DELETION_PENDING, AC-5)
CREATE UNIQUE INDEX "account_deletion_requests_one_pending" ON "account_deletion_requests"("user_id") WHERE "status" = 'PENDING';

-- CreateIndex
CREATE UNIQUE INDEX "reauth_tokens_token_hash_key" ON "reauth_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "reauth_tokens_created_at_idx" ON "reauth_tokens"("created_at");

-- AddForeignKey
ALTER TABLE "account_deletion_requests" ADD CONSTRAINT "account_deletion_requests_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_deletion_requests" ADD CONSTRAINT "account_deletion_requests_decided_by_id_fkey" FOREIGN KEY ("decided_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_deletion_requests" ADD CONSTRAINT "account_deletion_requests_restored_by_id_fkey" FOREIGN KEY ("restored_by_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reauth_tokens" ADD CONSTRAINT "reauth_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "reauth_tokens" ADD CONSTRAINT "reauth_tokens_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- The type to category CHECK, rebuilt from TYPE_CATEGORY in src/auth/events/event-types.ts
ALTER TABLE "account_events" DROP CONSTRAINT "account_events_type_category_check";
ALTER TABLE "account_events" ADD CONSTRAINT "account_events_type_category_check" CHECK (
  ("category" = 'SIGN_IN' AND "type" IN ('SIGNED_IN', 'SIGN_IN_FAILED', 'LOCKED_OUT',
    'PASSWORD_CONFIRMED', 'PASSWORD_CONFIRM_FAILED'))
  OR ("category" = 'SESSION' AND "type" IN ('SYSTEM_OPENED', 'SIGNED_OUT', 'SESSION_ENDED'))
  OR ("category" = 'CODE' AND "type" IN ('CODE_SENT', 'CODE_MAIL_FAILED', 'CODE_USED', 'CODE_RETIRED'))
  OR ("category" = 'ACCOUNT' AND "type" IN ('CREATED', 'UPDATED', 'ROLE_CHANGED', 'ACTIVATED',
    'DEACTIVATED', 'UNLOCKED', 'DELETED', 'SESSIONS_ENDED', 'PASSWORD_CHANGED', 'PICTURE_CHANGED',
    'DELETION_REQUESTED', 'DELETION_CANCELLED', 'DELETION_REJECTED', 'RESTORED', 'ERASED'))
);
