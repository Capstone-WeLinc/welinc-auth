# Admin section (`/auth/admin/*`)

## Overview

The portal's admin API from suite spec 0013: suite admins, system admins, the admin sign in code (step up), temporary access, recovery and the suite report. Every route here is authenticated by the `welinc_sso` cookie, never a bearer token, and mirrors the older bearer `/auth/users*` routes (deprecated, still used by system admins). The matrix routes live next door in `src/auth/permissions/admin-permissions.controller.ts` and reuse this folder's guard and scope helpers.

## Key files

| File | Owns |
|---|---|
| `admin-session.guard.ts` | `AdminSessionGuard`: live cookie session, then `ACCOUNT_LOCKED`, then admin standing, then the code. `@AdminRoute(level)` lowers the default `admin-code` level to `admin` (the code routes) or `signed-in` (`GET me`); `portalAdmin(req)` reads the caller it stored |
| `admin-standing.service.ts` | `AdminStanding` `{ suiteAdmin, adminOf }` from permanent roles only, read per request with no cache; `codeRequired()` reads `ADMIN_SIGN_IN_CODE` |
| `admin-errors.ts` | Every coded error of the section; some are thrown from `auth.service.ts` |
| `admin.controller.ts` | `GET me` (standing, code state, temporary grants for suite admins), `POST code` and `POST code/verify` (the step up; the ticket must belong to the caller) |
| `admin-accounts.controller.ts`, `people-page.ts` | The portal people routes (`users`, `users/lookup`, `users/:id/*`, `activity`, `deletion-requests`) and their `systemScope`, `accountScope` and `readScope` helpers; the People groups with `counts`, the three sorts, the status lists and the keyset cursor (`INVALID_CURSOR`) |
| `suite-admin.controller.ts`, `suite-admins.service.ts` | Suite admin list, add and remove; temporary grants routes; `GET report` |
| `temporary-grants.service.ts` | Temporary grants: create (suite admins, for themselves only), end (`endInTx`), list, and the minute expiry sweep |
| `admin-recovery.service.ts` | The `npm run admin:recover` logic (`scripts/admin-recover.ts`), `lockSuiteAdmins`, `reasonProblem` |
| `admin-alerts.service.ts`, `admin-alert-emails.ts` | Alert emails to active suite admins plus active admins of the systems concerned |
| `admin-report.service.ts` | The suite admin landing report (0013 AC-19) |
| `account-sessions.service.ts` | An admin's view and end of one person's sessions |
| `admin.dto.ts` | Request DTOs for the section |

## Conventions

- Every class here sits behind `AdminSessionGuard`; its default level is `admin-code`, so a new route needs the code unless it opts down with `@AdminRoute`. Writes also carry `PortalCsrfGuard`.
- Suite only routes check `standing.suiteAdmin` inside the handler or service (`NOT_SUITE_ADMIN`); system scoped routes go through `systemScope` or `accountScope` (`NOT_ADMIN_OF_SYSTEM`). Keep the `user-scope.ts` rules on any new people route.
- The three People reads (list, person, activity) use `readScope`: every system the caller admins (suite spec 0017). Every write stays on `accountScope`, one system; never widen a write to `ReadScope`.
- Admin standing never counts temporary grants: a temporary `ADMIN` role gives that system's app access, not the portal admin section.
- Every suite admin change takes `pg_advisory_xact_lock(hashtext('suite_admins'))` first (`lockSuiteAdmins`), then the target row `FOR UPDATE`. At most 3 suite admins (`MAX_SUITE_ADMINS`, from `prisma/seeds/manifest`). Nobody removes themselves (`SELF_ROLE`) or the last suite admin (`LAST_SUITE_ADMIN`); removing one first ends their live temporary grants.
- A suite admin holds no system roles (`HOLDS_SYSTEM_ROLES`, and a deferred trigger maps to `SUITE_ADMIN_NO_ROLES`).
- Sensitive writes need a reauth token bound to this cookie session: `ADMIN_ACTION` for suite admin changes, and for the people writes that can take one (create, update, unlock, reset code, ending sessions; the service answers `REAUTH_REQUIRED` when it wants it, for example when the target is an admin); `TEMPORARY_ACCESS` for a grant. It is consumed inside the write's transaction.
- Temporary grants: 1 to 8 hours (default 4), a reason of 10 to 500 characters, one live grant per person and system (a unique constraint, mapped to `GRANT_ACTIVE`). The grant row and its role row are written together; `endInTx` deletes the role row, stamps the end, writes `TEMP_ACCESS_ENDED` and ends that system's sessions.
- Every admin write records its account event in the same transaction (`SUITE_ADMIN_ACTIONED`, `SUITE_ADMIN_REMOVED`, `TEMP_ACCESS_STARTED`, `TEMP_ACCESS_ENDED`, `ADMIN_RECOVERY`, `SESSIONS_ENDED`).
- Alerts go out after commit through `AdminAlertsService`, which never throws and sends in the background; a failed email never rolls a change back. `admin:recover` calls `flush()` so the script waits for its mail.
- Responses are `Cache-Control: no-store`.

## Gotchas

- Nest runs the class level `AdminSessionGuard` before the method level `PortalCsrfGuard`, so a cookie with no session answers 401 before a CSRF 403.
- Routes in `suite-admin.controller.ts` keep the `admin-code` level, so a system admin who owes the code gets `ADMIN_CODE_REQUIRED` before `NOT_SUITE_ADMIN`.
- `GET users/lookup` is declared before `GET users/:id` on purpose; keep that order.
- Grant expiry: a minute sweep (one replica at a time) plus `roles/live-roles.ts`, which leaves out expired grants on every role read; a new `user_roles` read must go through it.
- `@SystemAdmin()` on the bearer routes (`guards/system-admin.guard.ts`) enforces the same code, so the deprecated routes need it too.
- Tests live outside the folder: `auth.service.admin.spec.ts`, `guards/guards.spec.ts`, `sessions/sso.controller.spec.ts`, `permissions/matrix.service.spec.ts`, with fakes in `testing/admin.fake.ts`.

## Related specs

- [Suite spec 0013, suite admin model](../../../../docs/specs/_root/0013-suite-admin-model/index.md)

_Drafted by /audit from the repo, worth a quick human pass. Edit freely: once a line stops matching this draft, later runs treat it as curated and will flag rather than overwrite it._
