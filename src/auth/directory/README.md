# User directory for systems (spec 0005)

System backends (VRMS, VMMS, BMS and their analytics services) read people from here instead of the auth database. The contract is in `docs/specs/_root/0001-shared-services-contract/` section 9 of the workspace; the design is in spec 0005.

## Routes

All three take only a backend's own service token (`aud: AUTH`) holding `directory.read`. A person's token, an admin's included, gets 403 `FORBIDDEN`. The caller's system is its client's `system` in `oauth_clients`, read on each request. Each client may make 120 calls a minute (429 `RATE_LIMITED` with `Retry-After`).

| Route | What it answers |
|---|---|
| `GET /auth/directory/users?cursor&limit` | Everyone who holds a role in the caller's system, by id, 100 a page (500 at most), with `next` and `changesCursor` (where to start the feed after a full read) |
| `GET /auth/directory/changes?after&limit` | The changes after `after`, in order, as `{ changes, next, hasMore }` |
| `POST /auth/directory/users/lookup` | `{ ids }` (1 to 200): `{ users, missing }`, current state, including people who once held a role in the caller's system |

Roles in the answer are the caller's system's only. `phone` is filled only for a token that also holds `directory.contact`. There is no `phoneVerified` (spec 0012: no system verifies phones). `erased` is true once the person's personal data was replaced by "Deleted user" (spec 0012); the feed says it with an `updated` change.

## How the feed is written

Postgres writes the feed, not the TypeScript code. Deferred triggers on `users` and `user_roles` (migration `20261111000000_directory_feed`) run at commit, rebuild the person's snapshot from the final state of the transaction, and write at most one `directory_changes` row per person per transaction. No row is written when nothing a system can see changed (a password change, a lock, a failed login, saving the same values). The type comes from comparing the snapshot with the person's previous row.

Things to know before you change anything here:

- **A new field systems should see, or a new role table:** change `directory_snapshot()` in a new migration (`CREATE OR REPLACE FUNCTION`), and update `DirectoryUser` in `directory-user.ts`. The trigger only notices what the snapshot holds.
- **If the trigger function fails, the user write fails.** That is on purpose: no change can commit without its feed row. A bug there blocks every user write, so run `npm run test:db` after any change to it.
- **Never use `TRUNCATE`, `COPY` or `session_replication_role = replica` on `users` or `user_roles`.** They skip the triggers, and systems would never hear about those changes.
- **Never write `directory_changes` or `directory_feed` from code.** The Prisma models exist only so `migrate dev` leaves the tables alone.
- **The seed saves everything in one transaction,** so a rerun that changes nothing writes no feed rows.

## Read order and the safe point

Rows are read in `(txid, seq)` order, where `txid` is the id Postgres gave the writing transaction. The feed serves only rows whose transaction is older than every transaction still running (the safe point), so a slow transaction that commits late is never skipped.

**A stuck feed means an open transaction.** Any long open transaction on the Postgres server holds the safe point back for every system until it ends. Look in `pg_stat_activity` for an old `xact_start`. The migration sets `idle_in_transaction_session_timeout` to 60 s on the auth database role to limit this; set it on a hosted database too (spec 0008).

## Cursors

A feed cursor carries the feed's `epoch` (`directory_feed`). A restored or rebuilt database gets a new epoch, so an old cursor answers 400 `INVALID_CURSOR`, which tells the system to read everything again from `/auth/directory/users`. Never copy `directory_feed` between databases.

## Rollback

`down.sql` next to the migration drops the triggers, functions and both tables (run it by hand, then remove the migration's row from `_prisma_migrations`).
