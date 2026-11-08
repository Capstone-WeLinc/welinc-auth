-- Spec 0004, AC-18: the roles each app may serve, per audience. {} lets every role through.
ALTER TABLE "oauth_clients" ADD COLUMN "allowed_roles" JSONB NOT NULL DEFAULT '{}';
