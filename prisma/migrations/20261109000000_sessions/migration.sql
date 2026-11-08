-- Spec 0003: server side sessions, chained refresh tokens, login requests and login codes.
-- Replaces the unused refresh_tokens table (it never held a row). Rollback: drop the four
-- tables and two enums, and recreate the old empty refresh_tokens.

-- AlterEnum
ALTER TYPE "UserChangeAction" ADD VALUE 'SESSIONS_ENDED';

-- CreateEnum
CREATE TYPE "SessionKind" AS ENUM ('WEB', 'MOBILE');

-- CreateEnum
CREATE TYPE "SessionEndReason" AS ENUM ('LOGOUT', 'IDLE', 'MAX_AGE', 'USER_ENDED', 'ADMIN_ENDED', 'DEACTIVATED', 'DELETED', 'PASSWORD_CHANGED', 'REFRESH_REUSE', 'CODE_REUSE', 'MAX_SESSIONS');

-- DropTable (unused since it was created)
DROP TABLE "refresh_tokens";

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "kind" "SessionKind" NOT NULL,
    "login_client_id" VARCHAR(64) NOT NULL,
    "device_name" VARCHAR(100),
    "user_agent" VARCHAR(512),
    "created_ip" VARCHAR(45),
    "last_seen_ip" VARCHAR(45),
    "sso_handle_hash" CHAR(64),
    "audiences" "SystemType"[] DEFAULT ARRAY[]::"SystemType"[],
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_activity_at" TIMESTAMPTZ(6) NOT NULL,
    "idle_expires_at" TIMESTAMPTZ(6) NOT NULL,
    "absolute_expires_at" TIMESTAMPTZ(6),
    "ended_at" TIMESTAMPTZ(6),
    "end_reason" "SessionEndReason",
    "ended_by_id" UUID,

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "sessions_end_together" CHECK (("ended_at" IS NULL) = ("end_reason" IS NULL))
);

-- CreateTable
CREATE TABLE "refresh_tokens" (
    "id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "client_id" VARCHAR(64) NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "parent_id" UUID,
    "used_at" TIMESTAMPTZ(6),
    "grace_cipher" BYTEA,
    "grace_until" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "login_requests" (
    "id_hash" CHAR(64) NOT NULL,
    "client_id" VARCHAR(64) NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "code_challenge" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "used_at" TIMESTAMPTZ(6),

    CONSTRAINT "login_requests_pkey" PRIMARY KEY ("id_hash")
);

-- CreateTable
CREATE TABLE "authorization_codes" (
    "code_hash" CHAR(64) NOT NULL,
    "client_id" VARCHAR(64) NOT NULL,
    "session_id" UUID NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "code_challenge" TEXT NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "used_at" TIMESTAMPTZ(6),

    CONSTRAINT "authorization_codes_pkey" PRIMARY KEY ("code_hash")
);

-- CreateIndex
CREATE UNIQUE INDEX "sessions_sso_handle_hash_key" ON "sessions"("sso_handle_hash");
CREATE INDEX "sessions_user_id_ended_at_idx" ON "sessions"("user_id", "ended_at");
CREATE INDEX "sessions_ended_at_idx" ON "sessions"("ended_at");
-- The hourly sweep looks only at live sessions past their idle cutoff
CREATE INDEX "sessions_idle_expires_at_live_idx" ON "sessions"("idle_expires_at") WHERE "ended_at" IS NULL;
CREATE UNIQUE INDEX "refresh_tokens_token_hash_key" ON "refresh_tokens"("token_hash");
CREATE UNIQUE INDEX "refresh_tokens_parent_id_key" ON "refresh_tokens"("parent_id");
-- The one live token rule: at most one unused refresh token per (session, client)
CREATE UNIQUE INDEX "refresh_tokens_one_unused_idx" ON "refresh_tokens"("session_id", "client_id") WHERE "used_at" IS NULL;
CREATE INDEX "login_requests_expires_at_idx" ON "login_requests"("expires_at");
CREATE INDEX "authorization_codes_expires_at_idx" ON "authorization_codes"("expires_at");

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE NO ACTION ON UPDATE CASCADE;
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_ended_by_id_fkey" FOREIGN KEY ("ended_by_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_login_client_id_fkey" FOREIGN KEY ("login_client_id") REFERENCES "oauth_clients"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "oauth_clients"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_parent_id_fkey" FOREIGN KEY ("parent_id") REFERENCES "refresh_tokens"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "login_requests" ADD CONSTRAINT "login_requests_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "oauth_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "oauth_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "authorization_codes" ADD CONSTRAINT "authorization_codes_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
