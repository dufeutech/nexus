## 1. Decide (gate before implementing)

- [x] 1.1 Run `/opsx:decide` for the `identity-data-residency` and
      `oidc-provider-independence` concerns; both recorded in design.md
      (`## Build-vs-Adopt Decisions`): Rent Postgres multi-database with
      create-empty-and-rebuild rollout; Adopt Envoy `jwt_authn` with static
      `remote_jwks` (discovery rejected as a Build).

## 2. Provision the nexus-owned database

- [x] 2.1 Added `postgres-init/10-create-nexus-databases.sql` (mounted at
      `/docker-entrypoint-initdb.d`) creating `identitydb` + `routing` alongside
      `zitadel`. Chose the prod-modeled TWO-database layout (not one `nexus` DB).
      **Runtime-verified:** fresh `docker compose up postgres` yields all three
      databases on the server.
- [x] 2.2 `init_schema()` unchanged (`CREATE SCHEMA IF NOT EXISTS`) — self-provisions
      the `identity`/`routing` schemas on first writer boot against the empty DB.

## 3. Repoint connection strings off the `zitadel` database

- [x] 3.1 `PROFILE_PG_URL` default → `/identitydb` in reconciler, sync-worker,
      membership-sync, AND sidecar (`main.rs:893`, missed by the plan). `cargo check`
      green on both workspaces.
- [x] 3.2 `ROUTING_PG_URL` default → `/routing` (tenant-router, control-plane);
      `ROUTING_PG_RO_URL` → `/routing` (membership-sync).
- [x] 3.3 Repointed all six compose connection strings + the `routing-verify-seed`
      `psql -d zitadel` → `-d routing`. `docker compose config` parses.
- [x] 3.4 `deploy/compose/.env.example` already modeled `identitydb`/`routing`
      (reconciled + header JWKS note generalized); helm values/secrets consistent.
- [x] 3.5 Session-mode `LISTEN/NOTIFY` constraint re-asserted in `deploy/README.md`
      and already documented per-URL in `.env.example`.

## 4. Neutralize the OIDC trust anchor

- [x] 4.1 `edge/envoy.yaml`: provider `zitadel` → `oidc`, cluster `zitadel_jwks` →
      `oidc_jwks`, `provider_name` updated.
- [x] 4.2 Mirrored in `deploy/compose/envoy/envoy.yaml` AND both Helm charts
      (`identity-plane` + `edge-platform` umbrella): values block `zitadel:` → `oidc:`,
      all `.Values.zitadel.*`/`$iv.zitadel.*` refs, provider-declaration key, cluster,
      `provider_name`, fail-messages, NOTES, `secret-pat`, `_helpers`. **Verified:**
      `scripts/helm-guards-test.sh` renders both charts green (34/34).
- [x] 4.3 Vendor-neutral single source realized as the Helm `oidc:` values block
      (`oidc.issuer`/`oidc.jwksPath`/…) + the rendered `oidc`/`oidc_jwks` identifiers.
      NOTE: no `OIDC_ISSUER`/`OIDC_JWKS_URL` **env vars** — compose Envoy reads
      `envoy.yaml` directly and Helm templates from values, so the neutral naming
      lives in the config/values, not env. OIDC discovery stays rejected (design D2).
- [x] 4.4 `ZITADEL_HOST` / `ZITADEL_INTERNAL_URL` / `PAT_FILE` env-var NAMES kept for
      the directory Management API (only the Helm VALUE key feeding them moved to
      `oidc.*`); reconciler/sync-worker directory wiring otherwise untouched (change 2).
- [x] 4.5 (added) Hardened `helm-guards-test.sh` with a provider-declaration/reference
      consistency assertion — caught and fixed a real mismatch where the Helm
      edge-configmaps declared `zitadel:` while `requires` referenced `oidc`.

## 5. Documentation

- [x] 5.1 `deploy/README.md` updated: `identitydb`/`routing` as nexus-owned separate
      databases (residency table row reworded), all `zitadel.*` Helm value keys →
      `oidc.*`, `zitadel_jwks` → `oidc_jwks`, issuer/JWKS-TLS operator instructions,
      session-mode constraint. `identity-rs/MIGRATION.md` reference updated.

## 6. Verify (behavior-identical acceptance)

- [x] 6.3 Grep sweep clean: no nexus connection string on `/zitadel` (healthcheck
      `pg_isready -d zitadel` intentionally kept — not a connection string); no
      `zitadel`-named JWT provider/cluster remains (service DNS `address: zitadel`
      intentional).
- [x] 6.1 Full-lab boot smoke — RUN (`docker compose up --build`, all 18 services
      healthy). **Residency proof:** `identity` schema in `identitydb`, `routing`
      schema in `routing`, and **zero** identity/routing schemas in the `zitadel` DB.
      Reconciler backfilled `identity.profiles` (2 rows) into `identitydb`.
- [x] 6.2 Auth-gate smoke — RUN via the edge (`:10000`, Host: localhost): no token
      on public route → **200**; invalid token → **401**; JWT-shaped bad-signature →
      **401** (proves the renamed `oidc` provider + `oidc_jwks` cluster fetch JWKS and
      verify — a broken rename would 503/pass-through); unknown host → **404**
      (tenant-first, before auth). Accepted/rejected set unchanged.
- [x] 6.4 Routing reachability + membership — RUN: `routing.domains` seeded/verified
      in the `routing` DB, `routing.memberships` present, membership-sync runs clean
      backstop passes (a transient pre-existing startup race — first pass before the
      control-plane creates the schema — self-heals on the 30s backstop).
