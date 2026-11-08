# welinc-auth

## Overview

The shared auth service for the WeLinc suite: NestJS 11 with Prisma 7 on PostgreSQL, listening on port 3001 (set by `PORT`). It handles login, OTP and password reset, user management for admins, profiles, and it signs the JWTs that every other service checks. It is reached through the gateway at `/auth`. This repo is shared with the other groups, so keep changes small and check with the team first.

## Key files

| File | Owns |
|---|---|
| `src/main.ts` | Bootstrap, security headers, strict global `ValidationPipe`, CORS, static `/uploads/` |
| `src/auth/auth.controller.ts` | The `/auth/*` routes for people: forgot password, verify OTP, reset password, `me`, user admin, profile (login lives in `sessions/`) |
| `src/auth/auth.service.ts` | `checkCredentials` (password, lockout after 5 failed attempts, the system pick), OTP and reset flows, user and profile logic |
| `src/auth/guards/`, `decorators/` | `JwtAuthGuard` (skips a request already authenticated), `OptionalJwtAuthGuard` (never rejects, for public routes that act differently for a signed in admin), `@SystemAdmin()` with `SystemAdminGuard` (the caller holds their system's `isSystemAdmin` role, read per request), `@ServiceScope()` (lets a service token with that scope into a route) |
| `src/auth/roles/`, `prisma/catalog/`, `prisma/catalog-sync.ts` | Spec 0004: one role file per system (`vrms.ts`, `vmms.ts`, `bms.ts`; order is display and power order, the admin role first), `catalog:sync` (pure plan and refusals in `catalog-plan.ts`), `CatalogService` (`UNKNOWN_ROLE`, `ROLE_LIMIT`, admin roles; no cache), the public `GET /auth/systems` (`systems.controller.ts`, `Cache-Control` and `ETag`), and `allowed-roles.ts` (`oauth_clients.allowed_roles`, `APP_NOT_ALLOWED`). `testing/catalog.fake.ts` is the catalog for unit tests |
| `src/auth/guards/request-authenticator.ts` | Turns a bearer token into a user or service caller. The system is the token's `aud`; a `?system=` that differs answers 403 `WRONG_AUDIENCE`. A user token works only while its session (`sid`) is live (401 `SESSION_ENDED`); an expired one answers 401 `TOKEN_EXPIRED` (spec 0003) |
| `src/auth/keys/` | `SigningKeyRing` (loads and self tests `AUTH_SIGNING_KEYS` at startup), `rotation.ts` (the add, promote, remove steps and the waits they enforce), `kid.ts` |
| `src/auth/tokens/` | `TokenService` (ES256 sign and verify with `jose`), `token-config.ts` (issuer, lifetimes, audiences), `login-system.ts` (which system a login token is for) |
| `src/auth/clients/` | `POST /auth/token` (client credentials, plus the code exchange and refresh grants from `sessions/`, all with a `private_key_jwt` assertion; `jti` replay table) and its OAuth error bodies. A call with a valid assertion counts 600 a minute per client and skips the per address count; every other call and every refused assertion counts 120 a minute per address |
| `src/auth/sessions/` | Server side sessions (spec 0003): `session.service.ts` (create with the 10 session cap under an advisory lock, lazy idle and age cutoffs, `end` with a reason), `user-grants.service.ts` (code exchange and refresh rotation with the 10 s grace cipher and reuse detection, one transaction with `FOR UPDATE`), `authorize.service.ts` (`/auth/authorize`, login requests, login codes, the escaped error page), `sso.controller.ts` (`/auth/login`, `/auth/sso`, `/auth/authorize`, `/auth/authorize/resume`, `/auth/session`), `csrf.ts` (`PortalCsrfGuard`), `sso-cookie.ts`, `opaque.ts` (random values, SHA-256, PKCE, the grace cipher), `session-config.ts` |
| `src/auth/sessions/session-end.controller.ts`, `session-sweeper.ts`, `mobile.controller.ts`, `sessions.controller.ts`, `device-label.ts` | Spec 0003 endings and views: `/auth/logout` (refresh token, `sid` with an assertion, or the SSO cookie) and `/auth/session/activity` (2 pings a minute per `sid` count); the hourly sweep (`@nestjs/schedule`, `pg_try_advisory_xact_lock`, batches of 1,000); `/auth/mobile/login` for `vmms-mobile`; `GET/DELETE /auth/me/sessions` and the admin `GET/DELETE /auth/users/:id/sessions` (one `SESSIONS_ENDED` change); the display only `<browser> on <OS>` label |
| `src/auth/well-known.controller.ts` | `GET /auth/.well-known/jwks.json` and `oauth-authorization-server` |
| `scripts/`, `docs/keys.md` | The `keys:*` scripts that write keys into env files, and the rotation runbook |
| `src/auth/user-scope.ts` | The system scope rules for admin user endpoints (spec 0011): who the caller may see, shared account checks and the other system admin block |
| `src/auth/user-changes.ts` | Admin change record helpers (`UserChange` rows), the last admin guard and the changes cursor |
| `src/auth/dto/` | Request DTOs validated with `class-validator` |
| `src/shared/` | `PrismaService`, `MailService` (logs instead of sending when SMTP is blank, in development only; in production it throws), `SharedModule` |
| `prisma/schema.prisma`, `prisma/migrations/` | `User`, `UserRoleAssignment` (role plus system), `PasswordResetToken`, `UserChange`, `OAuthClient` (the client registry), `ClientAssertionJti` (replay guard), and spec 0003's `Session`, `RefreshToken` (one row per issued token, chained by `parentId`), `LoginRequest`, `AuthorizationCode`. Two partial indexes live only in the migration SQL: one unused refresh token per (session, client), and live sessions by idle cutoff |
| `prisma/seed.ts`, `prisma/seeds/` | Seed users; `seeds/clients.seed.ts` is the client registry `seed:clients` applies, with each system's callback from `API_PUBLIC_URL` and its web address from `CLIENT_<ID>_WEB_ADDRESS` (the portal's from `PORTAL_URL`) |
| `nginx.conf` | The gateway on port 3000, routing `/auth`, `/vrms`, `/repairs`. It answers CORS itself from an exact origin `map` (the four local web ports), with `always`, and hides upstream CORS headers |

## Commands

```bash
npm run start:dev    # nest --watch
npm run lint         # runs eslint with --fix, so it edits files
npm run build
npm run test         # Jest unit tests
npm run test:e2e
npm run test:db      # migration tests on a throwaway database; locally: docker exec welinc_auth_service npm run test:db
npm run seed
npm run studio       # Prisma Studio on 5555
npm run keys:dev     # local signing key plus the VRMS client key pair, written into both .env files
npm run db:deploy    # prisma migrate deploy, then catalog:sync; use it instead of a bare migrate deploy
npm run catalog:sync # makes systems and system_roles match prisma/catalog/ (--dry-run to preview); refuses unsafe changes
npm run seed:clients # applies the client registry and the CLIENT_*_JWKS public keys (after db:deploy)
npm run keys:rotate -- <env file> <add|promote|remove> [--now] [<kid>]
npm run keys:client -- <client id> <private env file> <public env file> [--force]
npx prisma generate
npx prisma migrate dev   # asks first, see root rules
```

## Conventions

- Routes use `JwtAuthGuard`; user admin routes use `@SystemAdmin()` (it authenticates too). There is no `UserRole` enum: a role is a `RoleCode` string checked against the catalog, and `npm run build` fails on a `UserRole` import (`scripts/check-no-user-role.mjs`). A role change is a pull request to `prisma/catalog/<system>.ts` plus a deploy; never write `system_roles` by hand (spec 0004).
- A user holds roles per system (`UserRoleAssignment`, `SystemType`). Tokens are ES256 with a single `aud` (spec 0002): a user token (`token_use: user`) is for one system, carries `roles: [{ role, system }]` and its session's `sid`, and comes only from the `/auth/token` code exchange or refresh (spec 0003). `/auth/login` sets the `welinc_sso` cookie and never answers a token; it answers `{ user, system, url }` with the system welinc-auth picks. A service token (`token_use: service`, `aud: AUTH`) carries `scope`. Never sign with anything but `TokenService`.
- The global `ValidationPipe` uses `whitelist` and `forbidNonWhitelisted`, so every body needs a DTO and unknown fields are rejected.
- CORS allows localhost always, plus the origins in `CORS_ORIGINS` (comma separated, `*` allows all). Through the gateway, browsers see only nginx's exact allow list instead.
- Every POST that a cookie authenticates runs `PortalCsrfGuard`: `Content-Type: application/json`, `Origin` exactly `PORTAL_URL`, and `Sec-Fetch-Site` same origin or same site when sent (403 `CSRF_REJECTED`). Only welinc-auth writes `sessions`, and an ended session never comes back. Log lines name `sid`, user, reason and client, never a token, code, handle or request id.
- Every schema change needs a timestamped migration folder under `prisma/migrations/`.
- New variables go in `.env.example` only (today: `PORT`, `NODE_ENV`, `DATABASE_URL`, `AUTH_ISSUER`, `AUTH_SIGNING_KEYS`, `CLIENT_<ID>_JWKS`, `ACCESS_TOKEN_MINUTES`, `SERVICE_TOKEN_MINUTES`, `TRUST_PROXY_HOPS`, `WEB_SESSION_IDLE_MINUTES`, `WEB_SESSION_MAX_HOURS`, `MOBILE_SESSION_IDLE_DAYS`, `REFRESH_REUSE_GRACE_SECONDS`, `MAX_SESSIONS_PER_USER`, `SESSION_RETENTION_DAYS`, `SSO_COOKIE_SECURE`, `API_PUBLIC_URL`, `CLIENT_<ID>_WEB_ADDRESS`, `SMTP_*`, `CORS_ORIGINS`, `PORTAL_URL`; the last is required when `NODE_ENV=production`).
- Admin user endpoints act only on users who hold a role in the caller's system (404 for anyone else), and list each user's `roles` for that system only, plus `otherSystems`. An admin may only add, change or remove roles of their own system. A shared account (a role elsewhere) can't be deleted, and its password and email can't be set when it is `ADMIN` in another system (403). Keep these rules, in `user-scope.ts`, on any new admin user route.
- `GET /auth/users/lookup?q=` (2 characters at least, ADMIN, 30 calls a minute) returns only id, name, email and system names of active accounts outside the caller's system. `POST /auth/users` with an existing email answers 409 `ACCOUNT_EXISTS`; `attachExisting: true` adds only the caller's system roles to it.
- Every admin write to a user writes `UserChange` rows in the same transaction. No admin can deactivate, delete or demote themselves or the last active admin of a system (409); keep both rules on any new user write path.

## Gotchas

- There is no `JWT_SECRET`. A missing or bad `AUTH_SIGNING_KEYS` stops startup; run `npm run keys:dev` once locally. `AUTH_ISSUER` must be the same string in every service, or every check fails.
- A locked account (5 failed logins) stays locked until an admin calls `PATCH /auth/users/:id/unlock`. The lock blocks new logins only: live sessions keep working, and `/auth/session` still answers 200 (spec 0003).
- To test login with curl, send `Origin: http://localhost:8000` and `Content-Type: application/json`, or `/auth/login` answers 403 `CSRF_REJECTED`. It answers no token: get one through `GET /vrms/session/start` and the callback, then `POST /vrms/session/refresh`.
- `src/common/*` and the folders under `src/shared/` (garages, mechanics, notifications, vehicles) are empty placeholders.
- `npm run lint` fixes files in place, so check `git diff` afterwards.
- Nginx here is the workspace gateway for every service, so a route change for VRMS or AI is edited in this repo. That crosses repos and needs a spec first.
- This is the only owner of accounts, passwords, codes and roles for VRMS (spec 0009). backend-vrms copies mechanics into its own `Mechanic` rows through its sync, so a mechanic added here shows in the VRMS picker after the Users page runs it.

## Agent skills

- [nestjs-best-practices](../.claude/skills/nestjs-best-practices/): `kadajett/agent-nestjs-skills`, modules, DI and security
- [prisma-client-api](../.claude/skills/prisma-client-api/), [prisma-cli](../.claude/skills/prisma-cli/): `prisma/skills`, Prisma 7 queries and CLI

_Drafted by /audit from the repo, worth a quick human pass. Edit freely: once a line stops matching this draft, later runs treat it as curated and will flag rather than overwrite it._
