-- Spec 0004: roles per system. Hand written (not `migrate dev` output) so `user_roles.role`
-- turns from the "UserRole" enum into text in place: Prisma would drop and recreate the column.

-- AC-6: the catalog tables
CREATE TABLE "systems" (
    "code" "SystemType" NOT NULL,
    "name" VARCHAR(100) NOT NULL,
    "max_roles_per_user" INTEGER,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "systems_pkey" PRIMARY KEY ("code")
);

CREATE TABLE "system_roles" (
    "system" "SystemType" NOT NULL,
    "code" VARCHAR(40) NOT NULL,
    "name" VARCHAR(60) NOT NULL,
    "description" VARCHAR(200) NOT NULL,
    "sort_order" INTEGER NOT NULL,
    "is_system_admin" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "system_roles_pkey" PRIMARY KEY ("system","code")
);

ALTER TABLE "system_roles" ADD CONSTRAINT "system_roles_system_fkey" FOREIGN KEY ("system") REFERENCES "systems"("code") ON DELETE RESTRICT ON UPDATE RESTRICT;

-- AC-6: the starting catalog, exactly what prisma/catalog/*.ts holds, so the first
-- `npm run catalog:sync` reports no change (catalog-migration.spec.ts checks it)
INSERT INTO "systems" ("code", "name", "max_roles_per_user", "updated_at") VALUES
    ('VRMS', 'Vehicle Repair Management System', 1, CURRENT_TIMESTAMP),
    ('VMMS', 'Vehicle Maintenance Management System', 1, CURRENT_TIMESTAMP),
    ('BMS', 'Booking Management System', 1, CURRENT_TIMESTAMP);

INSERT INTO "system_roles" ("system", "code", "name", "description", "sort_order", "is_system_admin", "updated_at") VALUES
    ('VRMS', 'ADMIN', 'Admin', 'Manages VRMS users, settings and every ticket', 0, true, CURRENT_TIMESTAMP),
    ('VRMS', 'CHIEF_MECHANIC', 'Chief Mechanic', 'Assigns work and verifies finished repairs', 1, false, CURRENT_TIMESTAMP),
    ('VRMS', 'MECHANIC', 'Mechanic', 'Works the repair tickets assigned to them', 2, false, CURRENT_TIMESTAMP),
    ('VMMS', 'ADMIN', 'Admin', 'Manages VMMS users and settings', 0, true, CURRENT_TIMESTAMP),
    ('VMMS', 'OPERATIONS', 'Operations', 'Runs maintenance planning and schedules', 1, false, CURRENT_TIMESTAMP),
    ('VMMS', 'CHIEF_MECHANIC', 'Chief Mechanic', 'Leads the maintenance mechanics', 2, false, CURRENT_TIMESTAMP),
    ('VMMS', 'MECHANIC', 'Mechanic', 'Does scheduled maintenance work', 3, false, CURRENT_TIMESTAMP),
    ('BMS', 'ADMIN', 'Admin', 'Manages BMS users and settings', 0, true, CURRENT_TIMESTAMP),
    ('BMS', 'OPERATIONS', 'Operations', 'Plans trips and dispatch', 1, false, CURRENT_TIMESTAMP),
    ('BMS', 'CUSTOMER_SUPPORT', 'Customer Support', 'Handles bookings and customers', 2, false, CURRENT_TIMESTAMP),
    ('BMS', 'DRIVER', 'Driver', 'Drives assigned trips (BMS mobile)', 3, false, CURRENT_TIMESTAMP),
    ('BMS', 'HELPER', 'Helper', 'Assists drivers on trips (BMS mobile)', 4, false, CURRENT_TIMESTAMP);

-- AC-7: fix rows that break the new rules before the foreign key goes on. Every account counts,
-- inactive and soft deleted ones included. Notices name the user id only, never an email.
DO $$
DECLARE
    r RECORD;
    touched uuid[] := '{}';
BEGIN
    -- A (system, role) pair the system doesn't have
    FOR r IN
        SELECT ur."id", ur."user_id", ur."system", ur."role"::text AS "role"
        FROM "user_roles" ur
        LEFT JOIN "system_roles" sr ON sr."system" = ur."system" AND sr."code" = ur."role"::text
        WHERE sr."code" IS NULL
        ORDER BY ur."user_id", ur."system", ur."role"::text
    LOOP
        DELETE FROM "user_roles" WHERE "id" = r."id";
        touched := array_append(touched, r."user_id");
        RAISE NOTICE 'user %: removed % %, not a % role', r."user_id", r."system", r."role", r."system";
    END LOOP;

    -- More roles in a system than its limit: keep the most powerful, then the oldest
    FOR r IN
        SELECT ranked."id", ranked."user_id", ranked."system", ranked."role", ranked."kept_role"
        FROM (
            SELECT ur."id", ur."user_id", ur."system", ur."role"::text AS "role",
                row_number() OVER w AS "n",
                first_value(ur."role"::text) OVER w AS "kept_role"
            FROM "user_roles" ur
            JOIN "system_roles" sr ON sr."system" = ur."system" AND sr."code" = ur."role"::text
            WINDOW w AS (PARTITION BY ur."user_id", ur."system" ORDER BY sr."sort_order", ur."created_at", ur."id")
        ) ranked
        JOIN "systems" s ON s."code" = ranked."system"
        WHERE s."max_roles_per_user" IS NOT NULL AND ranked."n" > s."max_roles_per_user"
        ORDER BY ranked."user_id", ranked."system", ranked."n"
    LOOP
        DELETE FROM "user_roles" WHERE "id" = r."id";
        touched := array_append(touched, r."user_id");
        RAISE NOTICE 'user %: removed % %, kept % %', r."user_id", r."system", r."role", r."system", r."kept_role";
    END LOOP;

    -- Kept as it is: it can't sign in anywhere (NO_SYSTEM_ACCESS)
    FOR r IN
        SELECT DISTINCT u."id"
        FROM "users" u
        WHERE u."id" = ANY(touched)
          AND NOT EXISTS (SELECT 1 FROM "user_roles" ur WHERE ur."user_id" = u."id")
        ORDER BY u."id"
    LOOP
        RAISE NOTICE 'user %: no roles left', r."id";
    END LOOP;
END $$;

-- AC-8: the role becomes text, keeping every value, and must name a catalog role
ALTER TABLE "user_roles" ALTER COLUMN "role" TYPE VARCHAR(40) USING "role"::text;

DROP TYPE "UserRole";

ALTER TABLE "user_roles" ADD CONSTRAINT "user_roles_system_role_fkey" FOREIGN KEY ("system", "role") REFERENCES "system_roles"("system", "code") ON DELETE RESTRICT ON UPDATE RESTRICT;
