# welinc-auth

## Overview

The shared auth service for the WeLinc suite: NestJS 11 with Prisma 7 on PostgreSQL, listening on port 3001 (set by `PORT`). It handles login, OTP and password reset, user management for admins, profiles, and it signs the JWTs that every other service checks. It is reached through the gateway at `/auth`. This repo is shared with the other groups, so keep changes small and check with the team first.

## Key files

| File | Owns |
|---|---|
| `src/main.ts` | Bootstrap, security headers, strict global `ValidationPipe`, CORS, static `/uploads/` |
| `src/auth/auth.controller.ts` | All `/auth/*` routes: login, forgot password, verify OTP, reset password, `me`, user admin, profile |
| `src/auth/auth.service.ts` | Login, lockout (5 failed attempts), OTP and reset flows, user and profile logic |
| `src/auth/guards/`, `decorators/` | `JwtAuthGuard`, `OptionalJwtAuthGuard` (never rejects, for public routes that act differently for a signed in admin), `RolesGuard`, `@Roles()`, `@ServiceScope()` (lets a service token with that scope into a route) |
| `src/auth/guards/request-authenticator.ts` | Turns a bearer token into a user or service caller. The system is the token's `aud`; a `?system=` that differs answers 403 `WRONG_AUDIENCE`. `GET /auth/me?system=VRMS` is how backend-vrms checks each caller |
| `src/auth/keys/` | `SigningKeyRing` (loads and self tests `AUTH_SIGNING_KEYS` at startup), `rotation.ts` (the add, promote, remove steps and the waits they enforce), `kid.ts` |
| `src/auth/tokens/` | `TokenService` (ES256 sign and verify with `jose`), `token-config.ts` (issuer, lifetimes, audiences), `login-system.ts` (which system a login token is for) |
| `src/auth/clients/` | `POST /auth/token` (client credentials with a `private_key_jwt` assertion, `jti` replay table, 120 a minute per address) and its OAuth error bodies |
| `src/auth/well-known.controller.ts` | `GET /auth/.well-known/jwks.json` and `oauth-authorization-server` |
| `scripts/`, `docs/keys.md` | The `keys:*` scripts that write keys into env files, and the rotation runbook |
| `src/auth/user-scope.ts` | The system scope rules for admin user endpoints (spec 0011): who the caller may see, shared account checks and the other system admin block |
| `src/auth/user-changes.ts` | Admin change record helpers (`UserChange` rows), the last admin guard and the changes cursor |
| `src/auth/dto/` | Request DTOs validated with `class-validator` |
| `src/shared/` | `PrismaService`, `MailService` (logs instead of sending when SMTP is blank, in development only; in production it throws), `SharedModule` |
| `prisma/schema.prisma`, `prisma/migrations/` | `User`, `UserRoleAssignment` (role plus system), `PasswordResetToken`, `RefreshToken`, `UserChange`, `OAuthClient` (the client registry), `ClientAssertionJti` (replay guard) |
| `prisma/seed.ts`, `prisma/seeds/` | Seed users; `seeds/clients.seed.ts` is the client registry `seed:clients` applies |
| `nginx.conf` | The gateway on port 3000, routing `/auth`, `/vrms`, `/repairs` |

## Commands

```bash
npm run start:dev    # nest --watch
npm run lint         # runs eslint with --fix, so it edits files
npm run build
npm run test         # Jest unit tests
npm run test:e2e
npm run seed
npm run studio       # Prisma Studio on 5555
npm run keys:dev     # local signing key plus the VRMS client key pair, written into both .env files
npm run seed:clients # applies the client registry and the CLIENT_*_JWKS public keys
npm run keys:rotate -- <env file> <add|promote|remove> [--now] [<kid>]
npm run keys:client -- <client id> <private env file> <public env file> [--force]
npx prisma generate
npx prisma migrate dev   # asks first, see root rules
```

## Conventions

- Routes use `JwtAuthGuard`, plus `RolesGuard` with `@Roles(UserRole.ADMIN)` for user admin routes.
- A user holds roles per system (`UserRoleAssignment`, `SystemType`). Tokens are ES256 with a single `aud` (spec 0002): a user token (`token_use: user`) is for one system and carries `roles: [{ role, system }]`; welinc-auth picks that system at login and answers it as `system`. A service token (`token_use: service`, `aud: AUTH`) carries `scope`. Never sign with anything but `TokenService`.
- The global `ValidationPipe` uses `whitelist` and `forbidNonWhitelisted`, so every body needs a DTO and unknown fields are rejected.
- CORS allows localhost always, plus the origins in `CORS_ORIGINS` (comma separated, `*` allows all).
- Every schema change needs a timestamped migration folder under `prisma/migrations/`.
- New variables go in `.env.example` only (today: `PORT`, `NODE_ENV`, `DATABASE_URL`, `AUTH_ISSUER`, `AUTH_SIGNING_KEYS`, `CLIENT_<ID>_JWKS`, `ACCESS_TOKEN_MINUTES`, `SERVICE_TOKEN_MINUTES`, `TRUST_PROXY_HOPS`, `SMTP_*`, `CORS_ORIGINS`, `PORTAL_URL`; the last is required when `NODE_ENV=production`).
- Admin user endpoints act only on users who hold a role in the caller's system (404 for anyone else), and list each user's `roles` for that system only, plus `otherSystems`. An admin may only add, change or remove roles of their own system. A shared account (a role elsewhere) can't be deleted, and its password and email can't be set when it is `ADMIN` in another system (403). Keep these rules, in `user-scope.ts`, on any new admin user route.
- `GET /auth/users/lookup?q=` (2 characters at least, ADMIN, 30 calls a minute) returns only id, name, email and system names of active accounts outside the caller's system. `POST /auth/users` with an existing email answers 409 `ACCOUNT_EXISTS`; `attachExisting: true` adds only the caller's system roles to it.
- Every admin write to a user writes `UserChange` rows in the same transaction. No admin can deactivate, delete or demote themselves or the last active admin of a system (409); keep both rules on any new user write path.

## Gotchas

- There is no `JWT_SECRET`. A missing or bad `AUTH_SIGNING_KEYS` stops startup; run `npm run keys:dev` once locally. `AUTH_ISSUER` must be the same string in every service, or every check fails.
- A locked account (5 failed logins) stays locked until an admin calls `PATCH /auth/users/:id/unlock`.
- `src/common/*` and the folders under `src/shared/` (garages, mechanics, notifications, vehicles) are empty placeholders.
- `npm run lint` fixes files in place, so check `git diff` afterwards.
- Nginx here is the workspace gateway for every service, so a route change for VRMS or AI is edited in this repo. That crosses repos and needs a spec first.
- This is the only owner of accounts, passwords, codes and roles for VRMS (spec 0009). backend-vrms copies mechanics into its own `Mechanic` rows through its sync, so a mechanic added here shows in the VRMS picker after the Users page runs it.

## Agent skills

- [nestjs-best-practices](../.claude/skills/nestjs-best-practices/): `kadajett/agent-nestjs-skills`, modules, DI and security
- [prisma-client-api](../.claude/skills/prisma-client-api/), [prisma-cli](../.claude/skills/prisma-cli/): `prisma/skills`, Prisma 7 queries and CLI

_Drafted by /audit from the repo, worth a quick human pass. Edit freely: once a line stops matching this draft, later runs treat it as curated and will flag rather than overwrite it._
