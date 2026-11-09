-- Spec 0005 rollback (not run by Prisma): drops the directory feed. Run it by hand, then delete
-- the "20261111000000_directory_feed" row from "_prisma_migrations". If the feed is created
-- again later it gets a new epoch, so a system's old cursor answers INVALID_CURSOR and it reads
-- everything again.
BEGIN;
DROP TRIGGER IF EXISTS "directory_users_change" ON "users";
DROP TRIGGER IF EXISTS "directory_user_roles_change" ON "user_roles";
DROP FUNCTION IF EXISTS directory_record_change();
DROP FUNCTION IF EXISTS directory_write_change(UUID, JSONB);
DROP FUNCTION IF EXISTS directory_snapshot_systems(JSONB);
DROP FUNCTION IF EXISTS directory_snapshot(UUID);
DROP TABLE IF EXISTS "directory_changes";
DROP TABLE IF EXISTS "directory_feed";
ALTER ROLE CURRENT_USER RESET idle_in_transaction_session_timeout;
COMMIT;
