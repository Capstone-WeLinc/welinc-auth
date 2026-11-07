-- Spec 0002, AC-13 and AC-17: the client registry and the client assertion replay table.

-- CreateEnum
CREATE TYPE "ClientKind" AS ENUM ('FIRST_PARTY_WEB', 'CONFIDENTIAL', 'PUBLIC_NATIVE', 'SERVICE');

-- CreateTable
CREATE TABLE "oauth_clients" (
    "id" VARCHAR(64) NOT NULL,
    "kind" "ClientKind" NOT NULL,
    "system" "SystemType",
    "grants" TEXT[],
    "user_audiences" TEXT[],
    "service_scopes" JSONB NOT NULL DEFAULT '{}',
    "redirect_uris" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "web_address" VARCHAR(255),
    "jwks" JSONB,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "oauth_clients_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "client_assertion_jtis" (
    "client_id" VARCHAR(64) NOT NULL,
    "jti" VARCHAR(128) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "client_assertion_jtis_pkey" PRIMARY KEY ("client_id","jti")
);

-- CreateIndex
CREATE INDEX "client_assertion_jtis_expires_at_idx" ON "client_assertion_jtis"("expires_at");

-- AddForeignKey
ALTER TABLE "client_assertion_jtis" ADD CONSTRAINT "client_assertion_jtis_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "oauth_clients"("id") ON DELETE CASCADE ON UPDATE CASCADE;

