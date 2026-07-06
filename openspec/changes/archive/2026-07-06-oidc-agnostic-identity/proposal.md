## Why

Change 1 (`nexus-owned-identity-db`) moved nexus's data off the IdP and made OIDC
verification vendor-neutral — but the identity provider is still nexus's **source of
authorization**: the `reconciler` enumerates ZITADEL users and the `sync-worker`
consumes ZITADEL Actions to populate roles and suspension into the Profile, and the
edge even prefers a `roles` **claim from the token**. That inverts the boundary we
want. The rule is: **the OIDC provider answers "who am I" (authentication + basic
profile); nexus answers "what am I allowed to do here" (authorization).** This change
makes roles, entitlements, and suspension nexus-authored and authoritative, and
deletes the ZITADEL directory integration entirely — completing the decoupling so
nexus runs against any OIDC provider with zero authorization dependency on it.

## What Changes

- **Roles/entitlements/suspension become nexus-authored and authoritative.** A nexus
  administrative surface authors them; they are resolved **live** on the request path
  (a grant/revoke/suspend takes effect within seconds, no new token), exactly as
  membership already works. The identity provider SHALL NOT be a source of any
  authorization fact.
- **Authorization is deny-by-default.** A subject nexus holds no authorization facts
  about is authenticated but unprivileged — no roles, no entitlements, not suspended.
  Elevated access requires an explicit nexus grant. **BREAKING** (operational): an
  IdP grant no longer confers power in nexus; roles must be provisioned in nexus.
- **The token `roles` claim is no longer an authorization source.** `x-user-roles` is
  produced from nexus authorization only; the token-roles path is removed.
- **Entitlements get their first producer** (specced at the edge gate today, never
  populated) and **suspension gets a nexus-native home** (the only signal that
  actually breaks when the ZITADEL binaries are deleted).
- **The IdP directory integration is deleted**: the `reconciler` and `sync-worker`
  binaries, the ZITADEL wire-shape parsing in `core`, the admin-PAT + Actions webhook,
  and the `ZITADEL_HOST`/`ZITADEL_INTERNAL_URL`/`PAT_FILE` env + Helm wiring that
  change 1 deliberately left in place.
- **Authorization sits behind a swappable boundary.** Enforcement depends on an
  abstract authorization contract, not on a concrete store — so a future policy/ReBAC
  engine is an adapter swap, not a rewrite. (Engine choice deferred: see design.md.)
- Basic profile (name/email) continues to come from OIDC claims; it is display-only
  and unused on the enforcement path.

## Capabilities

### New Capabilities

- `nexus-native-authorization`: the system is the authoritative source of a subject's
  global authorization facts (roles, entitlements, suspension); they are authored only
  through the system's own administrative surface, resolved live (deny-by-default when
  absent, revocation within seconds), and the identity provider is never a source of
  any authorization fact. The authorization backend is a **critical (security)
  concern** whose realization is a build-vs-adopt decision (build nexus-native now vs.
  adopt a policy/ReBAC engine) — deferred to `/opsx:decide` and recorded in design.md;
  the spec stays engine-agnostic.

### Modified Capabilities

<!-- None. `identity-workspace-authz` already requires workspace-scoped authz to be
     resolved live from the nexus store (not the token); `edge-auth-gate` compares
     injected roles/entitlements but does not dictate their source; `membership-
     projection-sync` is the SoR→read-model pattern this reuses, unchanged. This
     change adds the GLOBAL-authz contract those specs don't cover, so it is additive. -->

## Impact

- **Deleted:** `identity-rs/reconciler/`, `identity-rs/sync-worker/`,
  `identity-rs/core/src/reconcile.rs`, `identity-rs/core/src/sync.rs`, the ZITADEL
  Management-API/Actions code, PAT handling, `deploy/helm/identity-plane` reconciler/
  sync-worker templates + `secret-pat.yaml`, `oidc.internalUrl`/`oidc.patSecret` Helm
  values, and `ZITADEL_HOST`/`ZITADEL_INTERNAL_URL`/`PAT_FILE` env across compose/helm.
- **New:** a nexus authorization store + authoring surface + resolver, behind an
  authorization port; a bootstrap path for the first administrator; a change-feed hook
  so authorization edits propagate within seconds (reusing the identity change feed).
- **Changed:** `identity-rs/sidecar` enrichment — `x-user-roles` sourced from nexus
  authorization via the resolver port, not the token; `entitlements`/`is_suspended`
  produced by nexus authoring. `identity-rs/core/profile.rs` may shed IdP-only fields
  (`org_id`; `home_org` stays informational per `identity-workspace-authz`).
- **Unaffected:** OIDC verification (Envoy), `sub`, the membership plane
  (`membership-sync`, `routing.memberships`), the `ProfileStore` port + `PgProfileStore`,
  the edge gate's compare-injected-to-required contract, `identity-data-residency`.
- **Cross-repo:** `nexus-upstream-requirements.md` — any identity-header contract change
  must be pinned in the consumer mirror.
