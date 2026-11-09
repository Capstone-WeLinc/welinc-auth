-- Spec 0007, AC-5: one line per system for the portal launcher card. The temporary default
-- fills existing rows; db:deploy runs catalog:sync right after, which writes the real lines.
ALTER TABLE "systems" ADD COLUMN "description" VARCHAR(200) NOT NULL DEFAULT '';
ALTER TABLE "systems" ALTER COLUMN "description" DROP DEFAULT;
