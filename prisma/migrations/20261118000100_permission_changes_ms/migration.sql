-- Spec 0013, build plan task 21: millisecond created_at on permission_changes, so the history's
-- keyset cursor (the account_events cursor, ms ISO plus id) matches rows exactly.
-- AlterTable
ALTER TABLE "permission_changes" ALTER COLUMN "created_at" SET DATA TYPE TIMESTAMPTZ(3);

