-- Suite spec 0014, AC-6: whether a phone app client has shipped, for the portal's phone only state.
-- Set only by seed:clients (authoritative, like allowed_roles).
ALTER TABLE "oauth_clients" ADD COLUMN "app_released" BOOLEAN NOT NULL DEFAULT false;
