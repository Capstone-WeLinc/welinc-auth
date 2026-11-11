-- Spec 0012: the new account event types, on their own. Postgres can't use an enum value in the
-- transaction that added it, so the CHECK that names them lives in the next migration.

ALTER TYPE "AccountEventType" ADD VALUE 'PASSWORD_CONFIRMED';
ALTER TYPE "AccountEventType" ADD VALUE 'PASSWORD_CONFIRM_FAILED';
ALTER TYPE "AccountEventType" ADD VALUE 'DELETION_REQUESTED';
ALTER TYPE "AccountEventType" ADD VALUE 'DELETION_CANCELLED';
ALTER TYPE "AccountEventType" ADD VALUE 'DELETION_REJECTED';
ALTER TYPE "AccountEventType" ADD VALUE 'RESTORED';
ALTER TYPE "AccountEventType" ADD VALUE 'ERASED';
