## 1. Authorization ports (core)

- [x] 1.1 Define `AuthzResolver` in `identity-rs/core` — resolve a subject's effective
      authorization facts (roles, entitlements, suspended) / answer authorization
      questions. Shape it as authorization *questions*, not a column read (§7.4 disc. 3).
- [x] 1.2 Define `AuthzAuthoring` in `core` — assign/revoke role, grant/revoke
      entitlement, suspend/reactivate. Domain-language, storage-agnostic.
- [x] 1.3 Define the `AuthzFacts` value type (roles/entitlements/is_suspended) with the
      deny-by-default zero value.

## 2. Nexus-native adapter (Model 1: identity store)

- [x] 2.1 Implement `AuthzAuthoring` over `PgProfileStore` as read-merge-write into
      `Profile.{roles,entitlements,is_suspended}`, preserving memberships + display
      (a `with_authz`-style no-clobber merge mirroring `with_memberships`), version-
      guarded, emitting the `LISTEN/NOTIFY` change-feed signal (instant revocation).
- [x] 2.2 Implement `AuthzResolver` over `PgProfileStore` (`get(sub)` → `AuthzFacts`);
      absent profile → deny-by-default zero value.
- [x] 2.3 Confirm the three writers (authz authoring + membership projection + any
      display materialization) converge via the version guard without clobbering.

## 3. Admin authoring surface + bootstrap

- [x] 3.1 New identity-plane admin API (auth-gated like control-plane `CONTROL_AUTH_TOKEN`:
      fail-closed, bearer from a Secret): endpoints to assign/revoke role,
      grant/revoke entitlement, suspend/reactivate a subject → `AuthzAuthoring`.
- [x] 3.2 Bootstrap: grant an admin role to a configured bootstrap-admin subject at
      startup iff no administrator exists (idempotent, break-glass, documented).

## 4. Enrichment sourced from nexus (sidecar)

- [x] 4.1 `sidecar extract_identity`: stop reading the token `roles` claim.
- [x] 4.2 `enrich_response`: source `x-user-roles`, `x-user-entitlements`,
      `x-user-suspended` from `AuthzResolver` (live Profile/feed) only; absent facts →
      strip headers (deny-by-default). Retire `x-user-roles-source` (always nexus now).
- [x] 4.3 Leave the edge gate untouched (still compares injected → required); confirm
      the compare contract holds against nexus-sourced headers.

## 5. Delete the ZITADEL directory integration

- [x] 5.1 Delete `identity-rs/reconciler/` and `identity-rs/sync-worker/` (binaries +
      workspace members + compose services + Helm templates).
- [x] 5.2 Delete `core/reconcile.rs` and `core/sync.rs` and the ZITADEL wire-shape
      parsing, PAT handling, and Actions-webhook registration.
- [x] 5.3 Remove `deploy/helm/identity-plane/templates/{reconciler,sync-worker}.yaml`,
      `secret-pat.yaml`, the `oidc.internalUrl`/`oidc.patSecret` values, and
      `ZITADEL_HOST`/`ZITADEL_INTERNAL_URL`/`PAT_FILE` env across compose + Helm + CI.
- [x] 5.4 `core/profile.rs`: shed `org_id` (IdP-only); keep `home_org` informational
      (`identity-workspace-authz`). Update the version-guard / `with_*` merges.

## 6. Provisioning migration

- [x] 6.1 Re-author the current ZITADEL-sourced grants as nexus authorization for
      existing users (pre-prod: re-provision via the admin API, not an ETL). Document
      the deny-by-default cutover as the operational BREAKING change.

## 7. Documentation

- [x] 7.1 `deploy/README.md` + `nexus-upstream-requirements.md`: the AuthN/AuthZ
      boundary, the admin authoring surface + bootstrap, deny-by-default, and the
      removal of the ZITADEL directory env. Pin any header-contract change in the
      consumer mirror.

## 8. Verify (behavior + spec scenarios)

- [x] 8.1 A role-claiming token confers nothing (deny-by-default; spec R1).
- [x] 8.2 Newly authenticated subject with no grants: auth-only route admits
      unprivileged, role/entitlement route 403 (spec R2).
- [x] 8.3 Suspend → subsequent requests denied within seconds, no re-auth; grant role →
      route passes within seconds; revoke → stops passing (spec R3).
- [x] 8.4 Bootstrap: from an empty store, the bootstrap admin can author the first
      grants (spec R4).
- [x] 8.5 Full-lab boot with reconciler + sync-worker deleted: edge gate green,
      enrichment sourced from nexus, no ZITADEL directory calls; `cargo` + helm-guards
      green.
