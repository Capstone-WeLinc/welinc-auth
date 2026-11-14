-- Suite spec 0013, AC-4, AC-9 and AC-12: SUITE_ADMIN_ACTIONED, SUITE_ADMIN_REMOVED,
-- TEMP_ACCESS_STARTED and ADMIN_RECOVERY carry the person's written reason (10 to 500
-- characters, like suite_admins.reason and temporary_grants.reason). varchar(40) only fit the
-- short codes, so any reason over 40 characters failed the whole write with a 500.
-- Widening a varchar rewrites nothing and fires no row trigger.
ALTER TABLE "account_events" ALTER COLUMN "reason" TYPE VARCHAR(500);
