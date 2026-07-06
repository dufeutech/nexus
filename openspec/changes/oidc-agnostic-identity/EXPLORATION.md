# Exploration — OIDC-agnostic identity + nexus-owned database

**Status:** exploration notes (pre-proposal). Seeds a future `/opsx:propose`.
**Date:** 2026-07-06.
**Goal (from the user):** nexus should work with **any OIDC provider** (Keycloak, Auth0,
Okta, Entra, ZITADEL, …), not depend on ZITADEL specifically. ZITADEL should provide only
what any OIDC provider provides (authentication). All membership/identity data the system
relies on for authorization should live in **nexus's own database** — the *same Postgres
server* is fine, but a **separate database**, not ZITADEL's `zitadel` database.

---

## 1. Where we are today (verified 2026-07-06, read-only)

Two layers, opposite answers:

### Already provider-agnostic
- **Token verification** is pure OIDC, done by Envoy `jwt_authn` (issuer + JWKS URL + `sub`
  claim). ZITADEL-isms are *names only*: the provider label `zitadel`, cluster `zitadel_jwks`,
  path `/oauth/v2/keys`. Evidence: `edge/envoy.yaml:278-310`,
  `deploy/compose/envoy/envoy.yaml:230-252`, `deploy/helm/identity-plane/values.yaml:56-66`.
  The Rust sidecar only reads the already-verified `sub` from Envoy metadata
  (`identity-rs/sidecar/src/main.rs:106,107,248`). **Swapping IdP here = config change.**
- **Membership is nexus-native.** Authored via control-plane admin API into
  `routing.memberships` (`routing-rs/control-plane/src/main.rs:1024`, store
  `routing-rs/store-postgres/src/lib.rs:828`, table `:280`), signalled via
  `pg_notify('routing_membership_changes')` (`:311-314`), projected into identity by
  `membership-sync` (`identity-rs/membership-sync/src/main.rs:49,228`, reader
  `identity-rs/store-postgres/src/source_memberships.rs:54-60`). The reconciler **explicitly
  refuses** to author membership from the IdP (`identity-rs/core/src/reconcile.rs:42-47`).
  Spec: `openspec/specs/membership-projection-sync/spec.md` (routing = source of record,
  identity = derived read-model). **So "membership in our own DB" is already true logically.**

### The actual ZITADEL coupling
- **No IdP port.** Unlike the clean `ProfileStore` port (`identity-rs/core/src/store.rs:47`)
  and `Membership*` ports (`core/src/membership.rs:79,94`), there is **no**
  `IdentityProvider`/`AuthoritativeUserSource` trait. ZITADEL is called **directly from the
  binaries**:
  - **Reconciler** — inline `struct Idp` (`identity-rs/reconciler/src/main.rs:113`), PAT +
    `Host` auth (`:127-132`), ZITADEL Management API: `POST /v2/users` (`:164`),
    `POST /management/v1/users/grants/_search` (`:172`). Pages the full user list.
  - **Sync-worker** — self-registers a ZITADEL **Actions v2** webhook:
    `POST /v2/actions/targets` + `PUT /v2/actions/executions`
    (`identity-rs/sync-worker/src/main.rs:210-247`); verifies the `zitadel-signature` header
    (`:92`) with an HMAC scheme (`:116-148`).
- **ZITADEL wire-shapes leak into two otherwise-pure core functions:**
  - `core/src/reconcile.rs:16-50` — `build_profile_from_user` parses ZITADEL v2 user JSON
    (`human.profile.*`, `human.email.email`, `details.resourceOwner`, `state ==
    "USER_STATE_INACTIVE"`, `userId`).
  - `core/src/sync.rs:11-18,54-86,143` — classifies ZITADEL Actions events
    (`aggregateType=="user"`, `resourceOwner`, `roleKeys`, camelCase `FIELD_MAP`,
    grant/removed/deactivated substrings).
  - `core/src/profile.rs` carries `org_id`/`home_org` but they are **informational only,
    explicitly excluded from authorization** (`:17-21`).

### Database layout (the physical-vs-logical gap)
| Store | Schema | Lab DB (code defaults + compose) | Prod DB (`.env.example`) |
| --- | --- | --- | --- |
| identity profiles | `identity` | **`zitadel`** (shared) | `identitydb` (separate) |
| routing (incl. memberships) | `routing` | **`zitadel`** (shared) | `routing` (separate) |
| ZITADEL itself | ZITADEL-owned | `zitadel` | its own instance |

Defaults point identity at ZITADEL's DB: reconciler `main.rs:289`, sync-worker `:274`,
membership-sync `:134` all default `PROFILE_PG_URL`/`ROUTING_PG_RO_URL` to
`postgres://…/zitadel`; lab compose `docker-compose.yaml:92,119,148,212,242,339`. **There is
no SQL-level dependency on ZITADEL's tables** — only the physical database name is shared.

### Full ZITADEL config surface to neutralize
`ZITADEL_INTERNAL_URL` (reconciler `:301`, sync-worker `:275`), `ZITADEL_HOST` (`:302`/`:276`,
must equal the JWT issuer authority), `WEBHOOK_SELF_URL` (`:277`), `PAT_FILE` +
`machinekey/zitadel-admin-sa.pat` (`:293`/`:278`, `docker-compose.yaml:61,101,123`, helm
`secret-pat.yaml`), and the edge JWT `issuer`/`remote_jwks` naming.

---

## 2. The design fork this forces

**Pure OIDC gives you authentication, not a directory.** It does NOT provide user
enumeration, role/grant listing, or change webhooks — which is exactly what the reconciler
and sync-worker use ZITADEL's Management API + Actions for. So demoting ZITADEL to "just an
OIDC provider" requires deciding **where profile attributes, roles, entitlements, and
suspension come from, and how they stay fresh.** Options:

- **(A) nexus-native authorship (recommended).** nexus becomes the source of record for all
  authz-relevant identity (roles, entitlements, suspension) in its own DB — exactly the model
  membership already uses. Profile display attributes (name, email) are materialized lazily
  from OIDC ID-token / `userinfo` claims on first sight. **Consequence: the reconciler and
  sync-worker can be DELETED, not just abstracted** — there is no IdP directory to mirror.
  This is the biggest simplification and the best fit for the stated goal.
- **(B) Optional standards-based sync adapter (SCIM).** For operators who *do* want the IdP to
  remain the user directory, add a **SCIM 2.0** adapter behind a new `AuthoritativeUserSource`
  port (SCIM is the vendor-neutral provisioning/sync standard most IdPs support). ZITADEL /
  Keycloak / Okta each become one adapter. More moving parts; keep it optional.
- **(C) Claims-only, no sync.** Enrich purely from token claims at request time. Simplest, but
  loses proactive revocation (a suspended user keeps working until token expiry) unless paired
  with short token TTLs + OIDC token introspection.

**Revocation is the sharp edge of any option:** ZITADEL Actions today gives near-real-time
suspension propagation. Pure OIDC has no push. If suspension becomes nexus-native (A), nexus
controls revocation directly (best). If it stays IdP-sourced (B/C), revocation latency is
bounded by token TTL + introspection or SCIM sync cadence — a `/opsx:decide` tradeoff.

---

## 3. Proposed target architecture

1. **OIDC = authentication only.** Keep the generic `jwt_authn` (issuer + JWKS + `sub`).
   De-ZITADEL the *names*: rename the Envoy provider/cluster to `oidc`/`oidc_jwks`, make the
   JWKS path + issuer plain config, drop the `ZITADEL_*` env vars in favor of
   `OIDC_ISSUER` / `OIDC_JWKS_URL`. Any OIDC provider works by config.
2. **nexus owns authz identity in its own DB.** Roles, entitlements, suspension, and
   membership are authored into nexus's database (extend the existing control-plane admin
   surface + `routing`/`identity` model). Profile display attributes come from OIDC claims,
   materialized on first sight.
3. **Separate physical database.** Repoint `PROFILE_PG_URL` / `ROUTING_PG_URL` /
   `ROUTING_PG_RO_URL` defaults and the lab compose off the `zitadel` database onto a
   nexus-owned DB (prod already models `identitydb` / `routing`). Same Postgres server, its own
   database, its own backup/HA boundary. No schema or data-model change.
4. **Delete or repurpose the ZITADEL mirroring.** Under option (A), remove `reconciler` +
   `sync-worker` and the ZITADEL wire-shape parsing in `core/reconcile.rs` + `core/sync.rs`.
   Under option (B), move that code behind an `AuthoritativeUserSource` adapter crate (mirror
   how `store-postgres` implements `ProfileStore`); ZITADEL becomes one optional adapter.

---

## 4. Work inventory

**Config / deploy only (low risk):**
- Repoint the three PG URLs + lab compose off `zitadel` DB → nexus DB. (`docker-compose.yaml`
  lines 92/119/148/212/242/339; reconciler/sync-worker/membership-sync `main.rs` defaults;
  `deploy/compose/.env.example` already correct.)
- Rename Envoy JWT provider/cluster and generalize issuer/JWKS config; introduce
  `OIDC_ISSUER`/`OIDC_JWKS_URL`, retire `ZITADEL_HOST`/`ZITADEL_INTERNAL_URL`.

**Code (the real work — scope depends on the §2 decision):**
- Introduce an IdP boundary. Either (A) delete `reconciler`+`sync-worker` and make
  roles/entitlements/suspension nexus-native + claims-materialized profiles; or (B) define
  `trait AuthoritativeUserSource` (+ change-event stream) in `core/`, move `struct Idp`
  (`reconciler/src/main.rs:113-197`) and `register_webhook`
  (`sync-worker/src/main.rs:210-247`) into a `source-zitadel` adapter crate, and lift the
  ZITADEL JSON parsing out of `core/reconcile.rs` + `core/sync.rs` into the adapter.
- Decide the revocation mechanism (§2 sharp edge).

**Already done (no work):** OIDC verification is generic; membership is nexus-native; the
`identity`/`routing` schemas have no SQL dependency on ZITADEL; `ProfileStore`/`Membership*`
ports are clean.

---

## 5. Open decisions (for `/opsx:decide` / `/opsx:explore`)

1. **Attribute/role/suspension source** — nexus-native (A) vs. SCIM adapter (B) vs. claims-only
   (C). Recommended: **A** (matches membership model, lets the mirroring binaries be deleted).
2. **Revocation latency** — nexus-native suspension (instant) vs. token-TTL + introspection vs.
   SCIM cadence.
3. **User provisioning / directory ownership** — if OIDC is auth-only, does nexus provision
   users (become the directory) or lazily materialize on first login? (Recommended: lazy
   materialize from claims; nexus is not a directory.)
4. **Keep an optional ZITADEL adapter?** (B) keeps ZITADEL as one of several IdP adapters; (A)
   removes ZITADEL-specific code entirely. Recommended: A first, add adapters only on demand.
5. **DB split rollout** — new database vs. `CREATE DATABASE` + move; connection/pooler
   implications (session-mode `LISTEN/NOTIFY` constraint still applies per `deploy/README.md`).

---

## 6. Suggested next steps

1. `/opsx:explore` this doc to pressure-test §2/§3 and settle the option-A-vs-B fork.
2. `/opsx:propose` a change — likely **two** changes, sequenced so risk is staged:
   - **`nexus-owned-identity-db`** — the DB separation + OIDC-config generalization
     (config/deploy, low risk, no behavior change). Do this first.
   - **`oidc-agnostic-identity-source`** — the port/adapter or delete-the-mirroring work
     (the real architectural change). Gate the attribute/role/suspension-source decision
     through `/opsx:decide`.
3. Note the cross-repo mirror: `nexus-upstream-requirements.md` is mirrored by the consumer
   repo; any header/identity-contract change from this work must be pinned in both.
