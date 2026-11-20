# Signing keys and client keys: runbook

welinc-auth is the only service that can sign tokens (spec 0002). It signs with a private ES256 key from `AUTH_SIGNING_KEYS` and publishes the public part at `/auth/.well-known/jwks.json`. Every other service checks tokens with those public keys. Each backend also holds its own client key, which proves who it is when it asks welinc-auth for a service token.

This runbook covers four jobs: local setup, a planned rotation, a leaked signing key and a leaked client key. Every script prints key ids (`kid`) and statuses only, never a key.

## The keys at a glance

| Value | Where it lives | Secret |
|---|---|---|
| `AUTH_SIGNING_KEYS` | welinc-auth only | yes |
| `CLIENT_<ID>_JWKS` (for example `CLIENT_VRMS_JWKS`) | welinc-auth, read by `npm run seed:clients` | no, public keys only |
| `AUTH_CLIENT_PRIVATE_KEY` | each backend, its own key only | yes |

Each signing key has a status: `current` (signs everything, exactly one), `next` (published, signs nothing yet) or `retired` (published so tokens it signed keep working, removed later). welinc-auth refuses to start with no `current` key, two of them, a public only key, or a key that fails its self test.

## Local setup

Run this once on a new machine, or after you reset your `.env` files:

1. In `welinc-auth`, run `npm run keys:dev`. It writes `AUTH_SIGNING_KEYS`, `CLIENT_VRMS_JWKS` and `AUTH_ISSUER` into `welinc-auth/.env`, and `AUTH_CLIENT_PRIVATE_KEY` and `AUTH_ISSUER` into `welinc-backend-vrms/.env`. It refuses to replace values already set; add `--force` to replace them (everyone signs in again).
2. Recreate the auth container so it reads the new values: `docker compose -f docker-compose.shared.yml up -d auth-service`.
3. Seed the client registry: `docker exec welinc_auth_service npm run seed:clients`. It updates the seven clients in place and never touches users. (`npm run seed` also seeds them, but it wipes every user first.)
4. Recreate the VRMS backend: `docker compose -f docker-compose.vrms.yml up -d vrms-backend`.

You'll see `signing key auth-… is current` in the auth log at startup.

## Running a step on a hosted environment

On staging (or production), the key set lives in the workspace's `infra/private/<env>.json` as `auth.signingKeys`, a JSON string, not in an env file. Run every step from the workspace root with:

```bash
PATH="$HOME/.local/bin:$PATH" bash infra/scripts/rotate-signing-keys.sh <staging|prod> <add|promote|remove> [--now] [<kid>]
```

It copies the key set into a temporary env file, runs `keys:rotate` there (a step that is too early is refused and nothing changes), writes the result back to the private file, and sets it with `rotate-secret.sh` on `auth-service-<env>` (restarted) and on the `auth-migrate-<env>` and `auth-seed-<env>` jobs. It prints key ids only. Then update the password manager copy of the private file. Locally, run `keys:rotate` on `welinc-auth/.env` and recreate the auth container.

## A planned rotation (nobody is logged out)

Apply each step straight away (the hosted script above does). The script times each wait from the moment it writes the file, so a step you apply late gives verifiers less time than the script assumes.

1. `add`. The new key is published as `next`; the old key still signs.
2. Wait, then `promote`. New tokens carry the new `kid`; the old key is `retired` and still published, so tokens it signed keep working.
3. Wait, then `remove`. The old key is gone.

If you run a step too early, the script refuses and prints when it becomes allowed. Each step also prints the next one with its earliest time.

**The waits.** The script's defaults are wide margins: 60 minutes before `promote`, and the longer token life (`ACCESS_TOKEN_MINUTES` or `SERVICE_TOKEN_MINUTES`) plus 30 minutes before `remove`. The real limits are smaller: every service caches the key set for at most 5 minutes (and VRMS refetches once on an unknown `kid`), and no token outlives its life. So `promote --now` 10 minutes after `add`, then `remove --now <old kid>` the longer token life plus 5 minutes after `promote`, is also safe. Staging was rotated that way on 2026-11-20 in 35 minutes.

To check a rotation, stay signed in to VRMS through all three steps; you should never be sent back to the login page.

## A new environment

There is no old key to protect, so you can skip the waits. Run steps 1 to 3 against temporary env files (a hosted private file is JSON):

1. `npm run keys:rotate -- <private file> add`
2. `npm run keys:rotate -- <private file> promote --now`
3. `npm run keys:client -- vrms <backend-vrms private file> <auth private file>`
4. Put the values in `infra/private/<env>.json` and run `apply.sh <env>` (workspace `infra/README.md`), then deploy welinc-auth first, run `npm run seed:clients` once, then deploy backend-vrms, then the portal. A backend deployed before welinc-auth fails every request.

## A leaked signing key

Act at once. Everyone signed by the leaked key has to sign in again; that is the price of killing it.

1. `add`
2. `promote --now`
3. `remove --now <leaked kid>`

On a hosted environment, run each through `rotate-signing-keys.sh` (above), which applies it and restarts welinc-auth. Locally, run them with `npm run keys:rotate -- .env <step>` and recreate the auth container.

The script warns you that live tokens signed by the removed key stop working, and that a service may keep accepting that key for up to 5 more minutes from its cache. If the leaked key was already `retired`, skip steps 1 and 2.

## A leaked client key

A client key can only ask welinc-auth for that client's own service token (for VRMS: reading its own system's users), and only for 5 minutes at a time. Either fix stops it:

- **Fastest:** switch the client off. Run `update oauth_clients set is_active = false where id = '<client id>';` against the auth database. Its next assertion is refused, and its service tokens stop working on welinc-auth's routes at once. `npm run seed:clients` never switches it back on; set `is_active = true` by hand when the new key is in place.
- **Replace the key:** run `npm run keys:client -- <client id> <client private file> <auth private file> --force`. It writes the new private key and keeps the previous public key beside the new one. On a hosted environment the private files are JSON, so run it against two temporary env files, then set the private half on the client's app and the public half on `auth-service-<env>` with the workspace's `infra/scripts/rotate-secret.sh`, and copy both into `infra/private/<env>.json` so the next apply keeps them. Then run `npm run seed:clients` and deploy the client. Once the client runs on the new key, remove the old public key from `CLIENT_<ID>_JWKS` (keep only the newest) and seed again.

## What each script refuses

| Command | Refuses when |
|---|---|
| `keys:dev` | a value is already set, unless `--force` |
| `keys:rotate … add` | a `next` key already exists |
| `keys:rotate … promote` | there is no `next` key, or it was added less than 60 minutes ago (unless `--now`) |
| `keys:rotate … remove` | no `retired` key has waited long enough |
| `keys:rotate … remove --now <kid>` | the kid isn't in the set, or it is the `current` key |
| `keys:client` | the client id is unknown, or the private file already has a key (unless `--force`) |

## Related

- Spec 0002 (`docs/specs/_root/0002-signing-keys-service-identity/` in the workspace): the decisions and the acceptance criteria.
- Spec 0008's `infra/RUNBOOK.md` links here once it is written.
- Copying the token check into another backend: `welinc-backend-vrms/src/auth/verify/README.md`.
