-- Spec 0013, build plan task 1: suite admins and the admin sign in code.

-- CreateTable
CREATE TABLE "suite_admins" (
    "user_id" UUID NOT NULL,
    "granted_by_id" UUID,
    "granted_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" VARCHAR(500),

    CONSTRAINT "suite_admins_pkey" PRIMARY KEY ("user_id")
);

-- AddForeignKey
ALTER TABLE "suite_admins" ADD CONSTRAINT "suite_admins_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "suite_admins" ADD CONSTRAINT "suite_admins_granted_by_id_fkey" FOREIGN KEY ("granted_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AlterTable: when the session passed an emailed code (AC-5 to AC-7); never cleared
ALTER TABLE "sessions" ADD COLUMN "sign_in_code_at" TIMESTAMPTZ(6);

-- The type to category CHECK, rebuilt from TYPE_CATEGORY in src/auth/events/event-types.ts
ALTER TABLE "account_events" DROP CONSTRAINT "account_events_type_category_check";
ALTER TABLE "account_events" ADD CONSTRAINT "account_events_type_category_check" CHECK (
  ("category" = 'SIGN_IN' AND "type" IN ('SIGNED_IN', 'SIGN_IN_FAILED', 'LOCKED_OUT',
    'PASSWORD_CONFIRMED', 'PASSWORD_CONFIRM_FAILED', 'ADMIN_CODE_PASSED'))
  OR ("category" = 'SESSION' AND "type" IN ('SYSTEM_OPENED', 'SIGNED_OUT', 'SESSION_ENDED'))
  OR ("category" = 'CODE' AND "type" IN ('CODE_SENT', 'CODE_MAIL_FAILED', 'CODE_USED', 'CODE_RETIRED'))
  OR ("category" = 'ACCOUNT' AND "type" IN ('CREATED', 'UPDATED', 'ROLE_CHANGED', 'ACTIVATED',
    'DEACTIVATED', 'UNLOCKED', 'DELETED', 'SESSIONS_ENDED', 'PASSWORD_CHANGED', 'PICTURE_CHANGED',
    'DELETION_REQUESTED', 'DELETION_CANCELLED', 'DELETION_REJECTED', 'RESTORED', 'ERASED',
    'SUITE_ADMIN_ACTIONED', 'SUITE_ADMIN_REMOVED', 'TEMP_ACCESS_STARTED', 'TEMP_ACCESS_ENDED',
    'ADMIN_RECOVERY'))
);
