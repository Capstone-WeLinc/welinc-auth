-- Suite spec 0017, AC-20: the People list's "Newest first" sort pages by (created_at, id) with
-- a keyset cursor that goes through JavaScript, which keeps milliseconds only. At microseconds
-- a cursor could skip people made in the same millisecond, so created_at keeps milliseconds,
-- like last_signed_in_at. Existing values round by under a millisecond. Changing a column type
-- fires no row trigger, so the directory feed writes nothing.
ALTER TABLE "users" ALTER COLUMN "created_at" TYPE TIMESTAMPTZ(3);
