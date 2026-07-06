## Context

nexus reuses one Postgres server for three tenants: ZITADEL's own `zitadel`
database, the `routing` schema, and the `identity` schema. In the lab
(`docker-compose.yaml`) all three connection strings point at the **same physical
database** — `postgres://…/zitadel` — even though the schemas are already isolated
(`routing`, `identity`) and carry no SQL dependency on ZITADEL's tables. Production
(`deploy/compose/.env.example`) already models separate `identitydb` / `routing`
databases, so the lab is the drifted surface.

Credential verification is already pure OIDC: Envoy's `jwt_authn` filter defines a
provider `zitadel` (issuer `http://localhost:8080`, `remote_jwks` on cluster
`zitadel_jwks` → `zitadel:8080`, path `/oauth/v2/keys`) — `edge/envoy.yaml:282-337`
and the compose/helm mirrors. The only ZITADEL-ness is the *names*.

One env var carries a double meaning that shapes this change: `ZITADEL_HOST` /
`ZITADEL_INTERNAL_URL` feed **both** (a) the JWT issuer authority used for
verification and (b) the ZITADEL Management API / Actions calls made by the
`reconciler` and `sync-worker` binaries (`identity-rs/reconciler/src/main.rs:301-302`,
`sync-worker/src/main.rs:275-276`). Only usage (a) is in scope here; (b) is the IdP
*directory* coupling deferred to change 2.

This is change 1 of 2. The identity-source decision is already settled as **option A
(nexus-native)** — see `openspec/changes/oidc-agnostic-identity/EXPLORATION.md`. This
change deliberately changes nothing that behaves; it only relocates data ownership
and neutralizes vendor names, so change 2 lands against clean boundaries.

## Goals / Non-Goals

**Goals:**

- Point the `identity` and `routing` stores at a nexus-owned database on the same
  Postgres server, in every deployment surface, with **no schema, data-model, or
  data-access-code change** (`identity-data-residency`).
- Express the edge trust anchor with vendor-neutral configuration
  (`oidc`/`oidc_jwks`, `OIDC_ISSUER`, `OIDC_JWKS_URL`) so any conformant OIDC
  provider is a config swap (`oidc-provider-independence`).
- Keep the accepted/rejected credential set and every routing/identity outcome
  byte-for-byte identical.

**Non-Goals:**

- Deleting or abstracting `reconciler` / `sync-worker`, making
  roles/entitlements/suspension nexus-native, or removing ZITADEL wire-shape parsing
  from `core` — all deferred to `oidc-agnostic-identity-source` (change 2).
- Retiring the `ZITADEL_HOST` / `ZITADEL_INTERNAL_URL` / `PAT_FILE` env that feed the
  IdP **directory** API. They remain until change 2 removes their consumers.
- Changing the Postgres server, its topology, or the schema DDL in `init_schema()`.

## Decisions

Layering for this change: there is **no core change**. Both moving parts are
adapter/config boundaries — the store connection string (a config value consumed by
the existing `PgProfileStore`/routing store adapters) and the Envoy JWT provider (a
data-not-code YAML block loaded by Envoy). Dependency direction is unchanged; nothing
inward is touched.

### D1 — A separate database on the same server, created empty (not copied)

The `identity` and `routing` schemas move onto a nexus-owned database
(`nexus`, or the prod-modeled `identitydb`/`routing`) on the same Postgres server.
Because both stores are **rebuildable projections** (`identity-rs/MIGRATION.md`: the
reconciler reconstructs every profile from the IdP in one pass; the routing store is
authored via the control-plane admin API), the rollout is *create empty + let the
writers repopulate*, not a data copy. `init_schema()` already runs `CREATE SCHEMA IF
NOT EXISTS` on startup, so a fresh database self-provisions on first boot.

- **Alternative — `CREATE DATABASE` + `pg_dump`/restore of the two schemas:** moves
  live rows, needs a quiesce window, and buys nothing when the projection rebuilds
  itself. Rejected for the lab; noted as the path if a future non-rebuildable table
  ever lands.
- **Alternative — leave lab co-located, fix prod only:** rejected — the residency
  spec requires the boundary to hold on *every* surface, and a co-located lab is
  exactly what let this coupling hide.

> **`/opsx:decide` — `identity-data-residency` (reliability-critical, adopt):** the
> database boundary itself is provided by Postgres (multi-database on one server) —
> **Rent infra, do not build**. The one build-vs-adopt call to record at decide time
> is the rollout mechanic (create-empty-and-rebuild vs. dump/restore); recommendation
> **create-empty-and-rebuild**, justified by the rebuildable-projection invariant.

### D2 — Vendor-neutral trust anchor, defined once

Rename the Envoy provider `zitadel` → `oidc` and cluster `zitadel_jwks` →
`oidc_jwks`, and source the issuer and JWKS URL from `OIDC_ISSUER` / `OIDC_JWKS_URL`
so the anchor is defined once and referenced at every verification point (edge +
helm values), satisfying `oidc-provider-independence`'s single-source requirement.
The Envoy JWT config stays **data, not code** — it lives in `envoy.yaml` and the
helm `values.yaml`, loaded by Envoy, never inlined into a binary.

- The JWKS *path* (`/oauth/v2/keys`) is ZITADEL's spelling of a standard endpoint; it
  becomes part of the configured `OIDC_JWKS_URL` value, not a hard-coded literal.
- **Alternative — OIDC discovery (`/.well-known/openid-configuration`):** cleaner
  long-term (issuer alone yields the JWKS URL) but Envoy `jwt_authn` takes an explicit
  `remote_jwks`; discovery is a larger change. Deferred — out of scope for a
  rename-only step.

### D3 — Split the double-meaning env var by usage, not by rename-everything

Introduce `OIDC_ISSUER` (and `OIDC_JWKS_URL`) for the **verification** authority.
Leave `ZITADEL_HOST` / `ZITADEL_INTERNAL_URL` in place **only** where they feed the
directory Management API in `reconciler` / `sync-worker`. This avoids a churny rename
of code that change 2 deletes outright, and keeps each value single-sourced for its
one real consumer.

- **Alternative — rename all `ZITADEL_*` now:** rejected — it would rename env feeding
  the directory API that change 2 removes, doubling the edit and muddying that change's
  diff.

## Build-vs-Adopt Decisions

Recorded via `/opsx:decide` (2026-07-06). Both concerns resolve away from Build.

### Decision: identity-data-residency — Rent Postgres multi-database (rollout: create-empty-and-rebuild)

- **Status**: approved
- **Why**: The database boundary is infrastructure Postgres already provides (a
  separate database on the same server) — nothing to build. The rollout is
  create-empty-and-rebuild, not a data copy, justified by the rebuildable-projection
  invariant (`identity-rs/MIGRATION.md`): the reconciler reconstructs identity from
  the IdP in one pass and routing is authored via its admin API, so an empty database
  self-populates on first boot.
- **Considered**: `CREATE DATABASE` + `pg_dump`/restore of the two schemas — moves
  live rows and needs a quiesce window, buys nothing while the projections rebuild;
  kept only as the path if a future non-rebuildable table lands. Leave-lab-co-located
  — rejected, the residency spec requires the boundary on every surface.
- **Isolation**: the connection string (a config value consumed by the existing
  `PgProfileStore` / routing store adapters); no data-access code touched.

### Decision: oidc-provider-independence — Adopt Envoy jwt_authn (static remote_jwks)

- **Status**: approved
- **Why**: Edge JWT verification is security-critical and already handled by Envoy's
  mature `jwt_authn` filter — no new dependency, this change only makes the provider
  vendor-neutral (provider `oidc`, issuer + JWKS from `OIDC_ISSUER` / `OIDC_JWKS_URL`,
  the JWKS path carried as a config value). Multi-provider-by-config is a native
  `jwt_authn` capability, so any conformant OIDC provider is a config swap.
- **Considered**: build an OIDC-discovery layer (`.well-known/openid-configuration`)
  to derive the JWKS URL — rejected: `jwt_authn` does not support discovery
  (research-confirmed, Envoy docs), so it would require hand-rolled fetch + a dynamic
  cluster — a Build against a security-critical path, exactly what this gate blocks.
- **Isolation**: the Envoy JWT provider block — data, not code — in `envoy.yaml` and
  the helm `values.yaml`, loaded by Envoy; never inlined into a binary.

## Risks / Trade-offs

- **[Lab points at a database that does not exist yet]** → `init_schema()` creates the
  schema, but not the database. Mitigation: the nexus database is declared in compose
  Postgres init (add to the server's created databases) so it exists before the
  writers connect; document in `deploy/README.md`.
- **[Repointed URL lands on a transaction-mode pooler and silently swallows `LISTEN`]**
  → the identity change feed would connect but never wake. Mitigation: the repointed
  `PROFILE_PG_URL` MUST be a session-mode/direct URL — the same constraint
  `deploy/README.md` already documents for `ROUTING_PG_URL`; re-assert it for the new
  database name.
- **[Behavior drift hides in the rename]** → a fat-fingered issuer/JWKS value would
  change which tokens verify. Mitigation: `oidc-provider-independence` pins
  "accepted/rejected set identical"; verify with a smoke test (valid token still 200,
  tampered token still 401) before and after.
- **[Partial residency — one of the three URLs missed]** → a store silently stays on
  `zitadel`. Mitigation: grep the deploy surface for `/zitadel` in connection strings
  as an acceptance check; the residency spec's "every surface" scenario is the gate.
- **[Two-writer race unchanged]** → out of scope; carried as-is from today.

## Migration Plan

1. Create the nexus-owned database on the Postgres server (compose init + prod
   provisioning); no data copied.
2. Repoint `PROFILE_PG_URL` / `ROUTING_PG_URL` / `ROUTING_PG_RO_URL` defaults and
   compose env off `/zitadel` onto the nexus database.
3. Rename the Envoy provider/cluster and wire `OIDC_ISSUER` / `OIDC_JWKS_URL` across
   `edge/envoy.yaml`, `deploy/compose/envoy/envoy.yaml`, and
   `deploy/helm/identity-plane/values.yaml`.
4. Boot: writers run `init_schema()` on the empty database; the reconciler backfills
   identity from the IdP in one pass; routing is re-authored via its admin API (or
   restored from its own backup in prod).
5. Smoke-verify: profile resolves, protected route still 401s without a token and
   200s with one, `/zitadel` no longer appears in any nexus connection string.

**Rollback:** revert the config commit — the URLs point back at `/zitadel` and the
old provider names return. No data to unwind (nothing was copied); the projections
rebuild against whichever database the URL names.
