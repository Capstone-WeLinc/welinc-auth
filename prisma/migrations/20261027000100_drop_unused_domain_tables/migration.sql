-- welinc-auth owns only users, roles, reset codes, refresh tokens and the admin change record.
-- The early schema also created the repair, booking and maintenance tables here; no code in
-- this service reads them and each domain service keeps its own copy in its own database.
DROP TABLE IF EXISTS
  "_RepairTicketMechanics",
  "audit_logs",
  "bookings",
  "checklist_items",
  "checklist_templates",
  "drivers",
  "garages",
  "maintenance_schedules",
  "mechanics",
  "repair_issues",
  "repair_parts",
  "repair_tickets",
  "shop_change_logs",
  "vehicles";

DROP TYPE IF EXISTS "AccountType";
DROP TYPE IF EXISTS "MaintenanceIntervalType";
DROP TYPE IF EXISTS "MaintenanceStatus";
DROP TYPE IF EXISTS "MaintenanceTriggerType";
DROP TYPE IF EXISTS "RepairStatus";
DROP TYPE IF EXISTS "VehicleStatus";
