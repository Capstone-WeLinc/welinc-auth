# welinc-auth

## Overview

The shared auth service for the WeLinc suite: NestJS 11 with Prisma 7 on PostgreSQL, listening on port 3001 (set by `PORT`). It handles login, OTP and password reset, user management for admins, profiles, and it signs the JWTs that every other service checks. It is reached through the gateway at `/auth`. This repo is shared with the other groups, so keep changes small and check with the team first.

## Key files

| File | Owns |
|---|---|
| `src/main.ts` | Bootstrap, security headers, strict global `ValidationPipe`, CORS, static `/uploads/` |
| `src/auth/auth.controller.ts` | All `/auth/*` routes: login, forgot password, verify OTP, reset password, `me`, user admin, profile |
| `src/auth/auth.service.ts` | Login, lockout (5 failed attempts), OTP and reset flows, user and profile logic |
| `src/auth/guards/`, `decorators/roles.decorator.ts` | `JwtAuthGuard`, `RolesGuard`, `@Roles()` |
| `src/auth/strategies/jwt.strategy.ts` | JWT validation, works out the requested system from the token, `Origin` or `Referer` |
| `src/auth/dto/` | Request DTOs validated with `class-validator` |
| `src/shared/` | `PrismaService`, `MailService` (logs instead of sending when SMTP is blank), `SharedModule` |
| `prisma/schema.prisma`, `prisma/migrations/` | `User`, `UserRoleAssignment` (role plus system), `PasswordResetToken`, `RefreshToken` |
| `prisma/seed.ts`, `prisma/seeds/` | Seed users |
| `nginx.conf` | The gateway on port 3000, routing `/auth`, `/vrms`, `/repairs`, `/ai`, `/analytics` |

## Commands

```bash
npm run start:dev    # nest --watch
npm run lint         # runs eslint with --fix, so it edits files
npm run build
npm run test         # Jest unit tests
npm run test:e2e
npm run seed
npm run studio       # Prisma Studio on 5555
npx prisma generate
npx prisma migrate dev   # asks first, see root rules
```

## Conventions

- Routes use `JwtAuthGuard`, plus `RolesGuard` with `@Roles(UserRole.ADMIN)` for user admin routes.
- A user holds roles per system (`UserRoleAssignment`, `SystemType`). The JWT carries `roles: [{ role, system }]`, and the portal and each app read that to decide where a user lands.
- The global `ValidationPipe` uses `whitelist` and `forbidNonWhitelisted`, so every body needs a DTO and unknown fields are rejected.
- CORS allows localhost always, plus the origins in `CORS_ORIGINS` (comma separated, `*` allows all).
- Every schema change needs a timestamped migration folder under `prisma/migrations/`.
- New variables go in `.env.example` only (today: `PORT`, `NODE_ENV`, `DATABASE_URL`, `JWT_SECRET`, `JWT_ACCESS_EXPIRY`, `JWT_REFRESH_EXPIRY`, `SEMAPHORE_*`, `SMTP_*`, `CORS_ORIGINS`).

## Gotchas

- `JWT_SECRET` must match the one `welinc-backend-vrms` verifies with, or every VRMS request returns 401.
- A locked account (5 failed logins) stays locked until an admin calls `PATCH /auth/users/:id/unlock`.
- `src/common/*` and the folders under `src/shared/` (garages, mechanics, notifications, vehicles) are empty placeholders.
- `npm run lint` fixes files in place, so check `git diff` afterwards.
- Nginx here is the workspace gateway for every service, so a route change for VRMS or AI is edited in this repo. That crosses repos and needs a spec first.
- Spec 0007's follow up: adding a mechanic here creates no VRMS `Mechanic` row. See the auth boundary feature in `docs/scope/foundations.md`.

## Agent skills

- [nestjs-best-practices](../.claude/skills/nestjs-best-practices/): `kadajett/agent-nestjs-skills`, modules, DI and security
- [prisma-client-api](../.claude/skills/prisma-client-api/), [prisma-cli](../.claude/skills/prisma-cli/): `prisma/skills`, Prisma 7 queries and CLI

_Drafted by /audit from the repo, worth a quick human pass. Edit freely: once a line stops matching this draft, later runs treat it as curated and will flag rather than overwrite it._
