-- Spec 0009: one table for every emailed code, and users.password_set. Hand written: Prisma
-- can't express the check constraint or the partial unique index. One transaction.

BEGIN;

CREATE TYPE "VerificationPurpose" AS ENUM ('PASSWORD_SETUP', 'PASSWORD_RESET', 'SIGN_IN', 'EMAIL_CHANGE');

-- AC-16: true when the email is verified, or when the account never had a code at all (its admin
-- typed the password); false otherwise (setup still pending). email_verified stays as it is.
-- password_set is not in the directory snapshot (AC-23), so the backfill must not reach the feed:
-- for a person with no feed row yet (no role) the trigger would write a `created` row. The feed
-- trigger is switched off for this one statement only, inside this transaction.
ALTER TABLE "users" ADD COLUMN "password_set" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "users" DISABLE TRIGGER "directory_users_change";
UPDATE "users" u SET "password_set" = true
WHERE u."email_verified" = true
   OR NOT EXISTS (SELECT 1 FROM "password_reset_tokens" t WHERE t."user_id" = u."id");
ALTER TABLE "users" ENABLE TRIGGER "directory_users_change";

CREATE TABLE "verification_codes" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "purpose" "VerificationPurpose" NOT NULL,
    "code_hash" TEXT NOT NULL,
    "challenge_hash" CHAR(64),
    "new_email" VARCHAR(255),
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "used_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "verification_codes_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "verification_codes_purpose_fields_check" CHECK (
        ("challenge_hash" IS NULL OR "purpose" = 'SIGN_IN')
        AND ("new_email" IS NULL OR "purpose" = 'EMAIL_CHANGE')
    )
);

CREATE INDEX "verification_codes_user_id_purpose_created_at_idx"
    ON "verification_codes" ("user_id", "purpose", "created_at" DESC);

-- A ticket finds exactly one row; moved between rows on resend (AC-10), so cleared first
CREATE UNIQUE INDEX "verification_codes_challenge_hash_key"
    ON "verification_codes" ("challenge_hash") WHERE "challenge_hash" IS NOT NULL;

ALTER TABLE "verification_codes" ADD CONSTRAINT "verification_codes_user_id_fkey"
    FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Codes already sent stop working; anyone mid setup or reset asks again (Consequences)
DROP TABLE "password_reset_tokens";

COMMIT;
