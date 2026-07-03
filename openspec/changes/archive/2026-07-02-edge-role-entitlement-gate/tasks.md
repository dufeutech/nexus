# Tasks: edge-role-entitlement-gate

## 1. Policy core (router-core + store)

- [x] 1.1 Add `requires_role: Option<String>`, `requires_entitlement: Option<String>`, `min_aal: Option<u8>` to the auth rule/policy types in `routing-rs/router-core/src/auth.rs`; resolved rule carries them through the existing longest-prefix `resolve` (no matching-logic change). Unit tests: requirements ride the matched rule; unset fields resolve to `None`; a rule with any requirement is interpreted as `auth_required = true` (fail-closed defense per design D3).
- [x] 1.2 Add the three nullable columns to `routing.auth_routes` in `routing-rs/store-postgres` following the existing idempotent bootstrap pattern (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS` beside the `CREATE TABLE IF NOT EXISTS`); extend `get_auth_policy` / `upsert_auth_route` to read/write them. Test: round-trip a rule with and without requirement fields.

## 2. Control-plane CRUD + validation

- [x] 2.1 Extend the auth-routes payload structs and handlers in `routing-rs/control-plane/src/main.rs` (`upsert_auth_route`, `list_auth_routes`) with the three optional fields, on both `/workspaces/{id}/auth-routes` and the legacy `/tenants/{id}/auth-routes` alias.
- [x] 2.2 Write-time validation: reject (structured 400) any rule combining a requirement field with `auth_required = false` (spec: "Inconsistent rule is rejected at write time"). Test both the rejection and that a valid requirement rule persists and invalidates via the existing NOTIFY.

## 3. Tenant-router emission

- [x] 3.1 In `routing-rs/tenant-router/src/main.rs` (beside the existing `x-auth-required` push), emit `x-auth-requires-role` / `x-auth-requires-entitlement` / `x-auth-min-aal` ONLY when the resolved rule sets them (absence = no requirement, design D5). Header names defined as constants next to `x-auth-required`'s.
- [x] 3.2 Tests: signals emitted for a gated rule; no signals for a Phase-1 rule; requirement change converges after `routing_invalidations` NOTIFY (spec scenario "Requirement change propagates like any policy change").

## 4. Sidecar enforcement (design D1)

- [x] 4.1 Add the method→AAL mapping to the identity sidecar's external config file behind its existing config adapter (design D4: data not code; default `none = 0`, `bearer = 1`).
- [x] 4.2 Implement the enforcement step in `identity-rs/sidecar`: after membership resolution, read the three requirement signals from the incoming request; compare against the in-process roles / entitlements / method-level; on any unsatisfied or uncomparable requirement return an immediate 403 via ext_proc (reuse the existing immediate-response path). Runs only for authenticated requests — anonymous requests on gated routes are already 401'd by jwt_authn upstream (spec: 401 owns the unauthenticated case).
- [x] 4.3 Strip the three requirement signals from the forwarded request so policy detail never reaches backends (design D5).
- [x] 4.4 Unit tests per spec scenario: satisfied role passes; missing role 403; missing entitlement 403; insufficient AAL 403; requirement present + enrichment absent 403 (fail-closed); no signals = no enforcement (Phase-1 parity).

## 5. Edge config

- [x] 5.1 Add `x-auth-requires-role`, `x-auth-requires-entitlement`, `x-auth-min-aal` to the C3 client-strip list in `edge/envoy.yaml`, adjacent to `x-auth-required`, with the same unforgeability comment discipline.

## 6. Verify + docs

- [x] 6.1 Run the affected test suites (`router-core`, `store-postgres`, `control-plane`, `tenant-router`, `identity-rs/sidecar`) and the repo's edge config check; exercise one end-to-end gated-route flow per the `verify` discipline.
- [x] 6.2 Update `nexus-upstream-requirements.md`: N4 → fully shipped (status table, N4 section, ownership table); note the deploy ordering (sidecar before tenant-router, design D6) where the deploy checklist lives.
