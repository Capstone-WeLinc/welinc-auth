# welinc-auth

## Overview

The shared auth service for the WeLinc suite: NestJS 11 with Prisma 7 on PostgreSQL, listening on port 3001 (set by `PORT`). It handles login, OTP and password reset, user management for admins, profiles, and it signs the JWTs that every other service checks. It is reached through the gateway at `/auth`. This repo is shared with the other groups, so keep changes small and check with the team first.

## Key files

| File | Owns |
|---|---|
| `src/main.ts` | Bootstrap, security headers, strict global `ValidationPipe`, CORS, static `/uploads/` |
| `src/auth/auth.controller.ts` | The `/auth/*` routes for people: forgot password, verify OTP, reset password, `me`, user admin, profile (login lives in `sessions/`) |
| `src/auth/auth.service.ts` | `checkCredentials` (password, lockout after 5 failed attempts, inactive accounts; the caller decides which systems apply), OTP and reset flows, user and profile logic |
| `src/auth/guards/`, `decorators/` | `JwtAuthGuard` (skips a request already authenticated), `OptionalJwtAuthGuard` (never rejects, for public routes that act differently for a signed in admin), `@SystemAdmin()` with `SystemAdminGuard` (the caller holds their system's `isSystemAdmin` role, read per request), `@ServiceScope()` (lets a service token with that scope into a route) |
| `src/auth/roles/`, `prisma/catalog/`, `prisma/catalog-sync.ts` | Role catalog (spec 0004): one file per system (order is display and power order, admin first) with its `description` and optional `permissions` keys; `catalog:sync` applies them through the pure `catalog-plan.ts` and `permission-plan.ts`; `CatalogService`; the public `GET /auth/systems`; `allowed-roles.ts`. `testing/catalog.fake.ts` is the unit test catalog |
| `src/auth/permissions/` | Central permission matrix (spec 0013): `matrix.service.ts` (reads, and the all or nothing `PATCH` under `FOR UPDATE`), the service read `GET /auth/permissions/:system` (own system only), the admin routes, `import-plan.ts` |
| `src/auth/guards/request-authenticator.ts` | Turns a bearer token into a user or service caller; checks `aud` against `?system=` and that the token's `sid` session is live |
| `src/auth/keys/` | `SigningKeyRing` (loads and self tests `AUTH_SIGNING_KEYS` at startup), `rotation.ts` (the add, promote, remove steps and the waits they enforce), `kid.ts` |
| `src/auth/tokens/` | `TokenService` (ES256 sign and verify with `jose`), `token-config.ts` (issuer, lifetimes, audiences) |
| `src/auth/clients/` | `POST /auth/token` (every grant, `private_key_jwt` assertions, the `jti` replay table) and its OAuth error bodies; the rate limits are the constants in `token-endpoint.service.ts` |
| `src/auth/sessions/` | Server side sessions (spec 0003): `session.service.ts`, `user-grants.service.ts` (code exchange and refresh rotation), `authorize.service.ts`, `sso.controller.ts` (`/auth/login`, `/auth/sso`, `/auth/authorize*`, `/auth/session`), `launcher.ts` (the systems list, spec 0007), `csrf.ts` (`PortalCsrfGuard`), cookie and opaque value helpers |
| `src/auth/sessions/session-end.controller.ts`, `session-sweeper.ts`, `mobile.controller.ts`, `sessions.controller.ts`, `device-label.ts` | Logout, activity pings, the hourly sweep, `/auth/mobile/login`, the `me` and admin sessions views, the device label |
| `src/auth/directory/` | User directory for system backends (spec 0005, see its `README.md`): `directory.read` service tokens only, the caller's system roles only, phone only with `directory.contact` |
| `src/auth/codes/` | The one code service (spec 0009) for setup, reset, sign in and email change codes: argon2 hashed in `verification_codes`, one live code per family; `testing/codes.fake.ts` is the unit test fake |
| `src/auth/well-known.controller.ts` | `GET /auth/.well-known/jwks.json` and `oauth-authorization-server` |
| `scripts/`, `docs/keys.md` | CLI scripts (`keys:*`, `admin:recover`, `geo:fetch`, the `UserRole` build check) and the key rotation runbook |
| `src/auth/user-scope.ts` | The system scope rules for admin user endpoints (spec 0011): who the caller may see, shared account checks and the other system admin block |
| `src/auth/user-changes.ts` | Admin safety guards (last admin, self change) and the `ACCOUNT` event builders for admin writes |
| `src/auth/events/` | Spec 0011: `account-events.service.ts` is the only writer of the append only `account_events` (inside the caller's transaction); the activity routes; `event-types.ts`, kept in step with the migration CHECK by `event-types.spec.ts`; the optional geo lookup (`npm run geo:fetch`) |
| `src/auth/deletion/`, `src/auth/reauth/password-check.service.ts` | Spec 0012: reauth tokens (`password-check.service.ts`, wrong passwords share the login lockout), deletion requests, and `erasure.service.ts` (run by the hourly sweep after `ACCOUNT_ERASURE_GRACE_DAYS`). Guide: `docs/integration/account-screens.md` in the workspace repo |
| `src/auth/dto/` | Request DTOs validated with `class-validator` |
| `src/config/` | Spec 0010: `env.ts` (the one zod schema for every runtime variable, `validateEnv` run by `ConfigModule` at boot, the production rules, `envWarnings`, `testEnv`), `check-env.ts` (`npm run env:check`), the Jest `setupFiles` fixtures |
| `src/openapi/` | VRMS spec 0026, the docs at `/auth/docs`: `document.ts` (builds the OpenAPI document in a stable order), `docs.ts` (mounts Scalar, the document and the bundle behind `API_DOCS_ENABLED`), `decorators.ts` (the security scheme and error reply decorators every route uses), `expect-reply.ts` (reply tests against the committed `docs/openapi.json`) |
| `src/shared/` | `PrismaService`, `MailService`, `SharedModule` |
| `prisma/schema.prisma`, `prisma/migrations/` | The schema. Triggers (directory feed, append only tables, suite admins hold no roles) and partial indexes exist only in migration SQL, and a later `CREATE OR REPLACE` wins (`20261115000200_account_erasure`, `20261117000000_suite_admin_powers`) |
| `prisma/seed.ts`, `prisma/seeds/` | Seed manifest (spec 0006): `seeds/people.json` is the only roster (fixed ids), checked by `manifest.ts` (`seedGuard`: production needs `SEED_ALLOW=staging`, `--reset` is local only); `seeds/clients.seed.ts` is the client registry. Guide: `docs/integration/seed-accounts.md` in the workspace repo |

## Commands

```bash
npm run start:dev    # nest --watch
npm run lint         # eslint --fix edits files; check git diff afterwards
npm run build
npm run env:check    # checks the environment without starting the app (after a build); exits 1 with the list
npm run openapi      # rewrites docs/openapi.json from the built app; commit it with any route, DTO or reply class change
npm run openapi:check  # exits 1 when docs/openapi.json differs from the code (CI runs it)
npm run test         # Jest unit tests
npm run test:e2e
npm run test:db      # migration tests on a throwaway database; locally: docker exec welinc_auth_service npm run test:db (CI runs them too, the `db` job)
npm run seed         # upserts the people.json roster, then the clients; --reset (local only) removes every user first
npm run seed:check -- <path>  # does a system's copy of people.json match the manifest
npm run studio       # Prisma Studio on 5555
npm run keys:dev     # local signing key plus the VRMS client key pair, written into both .env files
npm run db:deploy    # prisma migrate deploy, then catalog:sync; use it instead of a bare migrate deploy
npm run db:deploy:job  # env:check, then db:deploy: what the hosted migration job runs (deploy.yml sets it with job update; no dash arguments, VRMS spec 0008)
npm run catalog:sync # makes systems, system_roles and the permission keys and cells match prisma/catalog/ (--dry-run to preview); refuses unsafe changes
npm run permissions:import -- <SYSTEM> <file>  # one time: a system's matrix and history from backend-vrms's permissions:export; refuses once anyone edited the matrix here or it was imported already
npm run admin:recover  # spec 0013: makes a person a suite admin when no suite admin can sign in (needs a reason; see src/auth/admin/AGENTS.md)
npm run geo:fetch    # downloads the DB-IP Lite country and ASN files into geo/ (git ignored; --soft warns instead of failing); the Docker build and setup.sh run it with --soft
npm run seed:clients # applies the client registry and the CLIENT_*_JWKS public keys (after db:deploy)
npm run keys:rotate -- <env file> <add|promote|remove> [--now] [<kid>]
npm run keys:client -- <client id> <private env file> <public env file> [--force]
npx prisma generate
npx prisma migrate dev   # creates the migration folder; ask before running
```

## Conventions

- Routes use `JwtAuthGuard`; user admin routes use `@SystemAdmin()` (it authenticates too). There is no `UserRole` enum: a role is a `RoleCode` string checked against the catalog, and `npm run build` fails on a `UserRole` import (`scripts/check-no-user-role.mjs`). A role change is a pull request to `prisma/catalog/<system>.ts` plus a deploy; never write `system_roles` by hand (spec 0004).
- Roles are per system (`UserRoleAssignment`). Tokens are ES256 with one `aud`: user tokens (`token_use: user`, `roles`, `sid`) come only from the `/auth/token` code exchange or refresh; service tokens (`aud: AUTH`) carry `scope`. `/auth/login` sets `welinc_sso` and never answers a token; for an unverified email it answers 200 `{ status: "EMAIL_VERIFICATION_REQUIRED", … }` (finished by `/auth/login/verify-email`), and every login client must handle that body. Sign only with `TokenService`.
- The global `ValidationPipe` uses `whitelist` and `forbidNonWhitelisted`, so every body needs a DTO and unknown fields are rejected.
- CORS allows localhost plus `CORS_ORIGINS` (comma separated bare origins; `*` is refused at boot). Through the gateway, browsers see only the gateway's allow list.
- Every POST that a cookie authenticates runs `PortalCsrfGuard`: `Content-Type: application/json`, `Origin` exactly `PORTAL_URL`, and `Sec-Fetch-Site` same origin or same site when sent (403 `CSRF_REJECTED`). Only welinc-auth writes `sessions`, and an ended session never comes back. Log lines name `sid`, user, reason and client, never a token, code, handle or request id.
- Every schema change needs a timestamped migration folder under `prisma/migrations/`.
- Every runtime variable is defined once in `src/config/env.ts` (spec 0010); `CORS_ORIGINS` and `PORTAL_URL` are required in every mode. A new one goes in that schema and in `.env.example` together, or the drift test in `env.spec.ts` fails. Read it through `ConfigService<Env, true>` (`config.get('NAME', { infer: true })`), never `process.env`: lint fails on `process.env` outside `src/config/`, `prisma/`, `prisma.config.ts`, `scripts/` and tests. A module that needs config at setup uses `registerAsync` with `useFactory`, never a read at import time. Production adds rules: `https` and no `localhost` URLs, `SSO_COOKIE_SECURE=true`, `TRUST_PROXY_HOPS` at least 1, and SMTP.
- Admin user endpoints act only on users who hold a role in the caller's system (404 for anyone else), and list each user's `roles` for that system only, plus `otherSystems`. An admin may only add, change or remove roles of their own system. A shared account (a role elsewhere) can't be deleted, and its email can't be set when it is `ADMIN` in another system (403). Admins can't set anyone's password at all (spec 0009): a new user gets a setup code, and an admin email change sets `email_verified` false. Keep these rules, in `user-scope.ts`, on any new admin user route.
- `GET /auth/users/lookup?q=` (2 characters at least, ADMIN, 30 calls a minute) returns only id, name, email and system names of active accounts outside the caller's system. `POST /auth/users` with an existing email answers 409 `ACCOUNT_EXISTS`; `attachExisting: true` adds only the caller's system roles to it.
- Only Postgres writes `directory_changes`: deferred triggers on `users` and `user_roles` write at most one row per person per transaction, and none when nothing a system can see changed. A new user write path needs no feed code, but a new field systems can see means a new migration that changes the trigger's snapshot (spec 0005).
- `GET /auth/users` is for admins only: a service token gets 403 `WRONG_TOKEN_USE` (spec 0005, AC-9). System backends read people through `/auth/directory/*`.
- Every admin write to a user writes `ACCOUNT` events (spec 0011, `AccountEventsService`) in the same transaction, and so does every sign in, session end and code step. A new write path records its event in its own `tx`; a trigger refuses every `UPDATE` and any `DELETE` of an `ACCOUNT` row, and refuses other deletes unless the transaction ran `set_config('welinc.event_sweep', 'on', true)`, which only the retention sweep does. `TRUNCATE` is allowed (the local seed `--reset`). No admin can deactivate, delete or demote themselves or the last active admin of a system (409); keep both rules on any new user write path.
- `permission_changes` is append only too (spec 0013): a trigger refuses every `UPDATE` and `DELETE`, except that erasure (`welinc.erasure` on) may blank `actor_name` and `actor_email`; `erasure.service.ts` does that for the erased person. Every write that changes a matrix cell writes one row per changed cell and raises `permission_matrices.version` with `version = version + 1` in the same transaction, since systems poll on that version.

## Gotchas

- In `prisma/seeds/people.json` a person's `password` is a key of the file's `passwords` map, not the password itself (`ops` means `ops1234`); `docs/integration/seed-accounts.md` lists the real ones.
- `@scalar/nestjs-api-reference` is ES module only and the Jest config doesn't transform it, so a spec that imports `src/openapi/docs.ts` mocks it (see `docs.spec.ts`).
- `argon2` stays on 0.44 (`dependabot.yml` skips 0.45 and up): 0.45 ships no prebuilt binary for Intel Macs, so `npm install` has to compile it and fails on a Mac without full C++ build tools.
- There is no `JWT_SECRET`. A missing or bad `AUTH_SIGNING_KEYS` stops startup; run `npm run keys:dev` once locally. `AUTH_ISSUER` must be the same string in every service, or every check fails.
- In development, mail to an address on `DEV_EMAIL_DOMAINS` (`src/shared/dev-email-domains.ts`: `welinc.com`, `localhost`, `test.com`, `example.com`) is printed to the log, never sent, even with `SMTP_*` set; real addresses still use SMTP. Read a seed account's code with `docker logs welinc_auth_service`. Staging runs `NODE_ENV=production`, so the same rule there needs `SEED_MAIL_TO_LOG=true` (suite spec 0009 AC-32; set by Bicep on staging's `auth-service` only, refused with `SENTRY_ENVIRONMENT=production`); read staging codes with `az containerapp logs show -n auth-service -g rg-welinc-staging --tail 50`.
- The right password on a deactivated account answers 403 `ACCOUNT_INACTIVE`; a wrong one stays the generic 401, so an inactive account is never revealed without its password.
- A locked account (5 failed logins in a row) stays locked for 15 minutes (suite spec 0015, `src/auth/lockout.ts`), or until an admin calls `PATCH /auth/users/:id/unlock` or a reset code is used. Check a lock with `lockActive(lockedAt)`, never `lockedAt !== null`: a lock that ran out is cleared lazily. The lock blocks new logins, and since spec 0012 every user route (`verify-password`, `/auth/me`, the profile and password routes) answers 403 `ACCOUNT_LOCKED`. Live sessions are not ended, and `/auth/session` still answers 200 (spec 0003).
- To test login with curl, send `Origin: http://localhost:8000` and `Content-Type: application/json`, or `/auth/login` answers 403 `CSRF_REJECTED`. It takes `email` and `password` (sending `system` gets 400) and answers the launcher list, the same body as `GET /auth/sso`. For an unverified account it answers the code step body (read the code from the log when `SMTP_*` is blank). It answers no token: get one through `GET /vrms/session/start` and the callback, then `POST /vrms/session/refresh`.
- This is the only owner of accounts, passwords, codes and roles; system backends copy people, never write them.
- CI audits with `audit-ci` (`audit-ci.jsonc`), not `npm audit`: high or critical in what ships fails the build. Update the package first; only when no fix exists, add the advisory id to the allowlist with its reason and a review date. Never lower the level or run `npm audit fix --force`.

## Agent skills

- [nestjs-best-practices](../.claude/skills/nestjs-best-practices/): `kadajett/agent-nestjs-skills`, modules, DI and security
- [prisma-client-api](../.claude/skills/prisma-client-api/), [prisma-cli](../.claude/skills/prisma-cli/): `prisma/skills`, Prisma 7 queries and CLI

## Context files

- [src/auth/admin/AGENTS.md](src/auth/admin/AGENTS.md): the cookie based `/auth/admin/*` API (suite spec 0013): admin code step up, suite admins, temporary access, recovery, alerts and the report

_Drafted by /audit from the repo, worth a quick human pass. Edit freely: once a line stops matching this draft, later runs treat it as curated and will flag rather than overwrite it._
