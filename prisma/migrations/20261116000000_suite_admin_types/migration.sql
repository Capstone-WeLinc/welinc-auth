-- Spec 0013: the new enum values, on their own. Postgres can't use an enum value in the
-- transaction that added it, so the CHECK that names them lives in the next migration.

ALTER TYPE "AccountEventType" ADD VALUE 'SUITE_ADMIN_ACTIONED';
ALTER TYPE "AccountEventType" ADD VALUE 'SUITE_ADMIN_REMOVED';
ALTER TYPE "AccountEventType" ADD VALUE 'TEMP_ACCESS_STARTED';
ALTER TYPE "AccountEventType" ADD VALUE 'TEMP_ACCESS_ENDED';
ALTER TYPE "AccountEventType" ADD VALUE 'ADMIN_RECOVERY';
ALTER TYPE "AccountEventType" ADD VALUE 'ADMIN_CODE_PASSED';

ALTER TYPE "SessionEndReason" ADD VALUE 'TEMP_ACCESS_ENDED';

ALTER TYPE "ReauthPurpose" ADD VALUE 'ADMIN_ACTION';
ALTER TYPE "ReauthPurpose" ADD VALUE 'TEMPORARY_ACCESS';
