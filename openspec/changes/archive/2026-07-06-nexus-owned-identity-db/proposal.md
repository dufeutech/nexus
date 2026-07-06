## Why

nexus's authorization data currently defaults to living *inside* the identity
provider's own database (the `zitadel` DB in the lab), and its edge credential
verification is wired with vendor-named config (`zitadel`/`zitadel_jwks`,
`ZITADEL_HOST`, `ZITADEL_INTERNAL_URL`). Both are incidental couplings — there is
no SQL dependency on the IdP's tables and token verification is already pure OIDC —
but they make ZITADEL look load-bearing where it is not, and they block the goal of
running nexus against any OIDC provider. This change draws the two boundaries
explicitly, at zero behavior cost, as the safe first step of decoupling nexus from
ZITADEL (change 1 of 2; the identity-source rework is the sequenced follow-on).

## What Changes

- Repoint the identity and routing stores off the shared `zitadel` database onto a
  **nexus-owned database on the same Postgres server** — updating the
  `PROFILE_PG_URL` / `ROUTING_PG_URL` / `ROUTING_PG_RO_URL` defaults and the lab
  `docker-compose.yaml` (production `.env.example` already models separate
  `identitydb` / `routing` databases). No schema, data model, or data-access code
  changes — only which database the connection strings target.
- Generalize the edge OIDC configuration so any OIDC provider is selected by config:
  rename the Envoy JWT provider/cluster from `zitadel`/`zitadel_jwks` to
  `oidc`/`oidc_jwks`, make the issuer, JWKS URL, and key path plain configuration,
  and introduce `OIDC_ISSUER` / `OIDC_JWKS_URL` in place of the `ZITADEL_HOST` /
  `ZITADEL_INTERNAL_URL` env vars **where they only feed JWT verification**.
- Preserve all observable behavior: the same tokens verify, the same profiles
  resolve, the same routes gate. This is a boundary-drawing and renaming change, not
  a functional one.
- **Out of scope (deferred to change 2, `oidc-agnostic-identity-source`):** deleting
  the `reconciler` / `sync-worker` binaries, making roles/entitlements/suspension
  nexus-native, and removing the ZITADEL wire-shape parsing from `core`. Those env
  vars and code paths that feed the IdP *directory* (not JWT verification) are left
  untouched here.

## Capabilities

### New Capabilities

- `identity-data-residency`: nexus's authorization-relevant identity and routing
  data resides in a nexus-owned database that is administratively separate from any
  identity provider's database — its own database boundary, backup/HA scope, and
  lifecycle — with no cross-database SQL dependency on the IdP. Establishing this
  boundary is the load-bearing invariant of the change; where the physical database
  lives (same server, its own database) is a build-vs-adopt/rollout concern for
  `/opsx:decide` and `design.md`.
- `oidc-provider-independence`: the edge accepts and verifies credentials against a
  configured OIDC issuer and JWKS endpoint identified by vendor-neutral
  configuration, so nexus can run against any conformant OIDC provider without code
  change. No specific provider name appears in the trust contract.

### Modified Capabilities

<!-- None. edge-auth-gate and membership-projection-sync already state only
     provider-agnostic, observable behavior; this change alters configuration and
     data residency, not their requirements. -->

## Impact

- **Config / deploy:** `docker-compose.yaml` (identity + routing service env),
  `deploy/compose/.env.example` (already separated — reconciled), the binary
  connection-string defaults in `identity-rs/reconciler`, `identity-rs/sync-worker`,
  `identity-rs/membership-sync` `main.rs`, `deploy/helm/*` values/secrets, and the
  Envoy configs (`edge/envoy.yaml`, `deploy/compose/envoy/envoy.yaml`,
  `deploy/helm/identity-plane/values.yaml`).
- **Operators:** the connection URLs and OIDC env-var names change; captured in
  `deploy/README.md`. The session-mode `LISTEN/NOTIFY` pooler constraint continues
  to apply to the repointed URLs.
- **No impact:** application code paths, the `ProfileStore` / `Membership*` ports,
  the `identity` / `routing` schemas, and all runtime behavior. ZITADEL remains the
  configured IdP; this change only stops treating it as the data owner and the
  hard-coded vendor.
