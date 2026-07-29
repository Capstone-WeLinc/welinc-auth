try {
  require("dotenv/config");
} catch {
  // dotenv optional
}
import { defineConfig } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
    seed: "ts-node -r tsconfig-paths/register prisma/seed.ts",
  },
  datasource: {
    url: process.env["DATABASE_URL"] || "postgresql://welinc_auth_user:welinc_auth_pass@localhost:5432/welinc_auth_db?schema=public",
  },
});

