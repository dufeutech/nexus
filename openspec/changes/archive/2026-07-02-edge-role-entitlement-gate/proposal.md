# Proposal: edge-role-entitlement-gate

## Why

The per-route auth gate (N4 Phase 1) only answers "is a verified credential required?"
— it cannot express "this route needs role X / entitlement Y / a stronger login". The
identity plane already injects everything needed to decide (`x-user-roles`,
`x-user-entitlements`, `x-auth-method`), but nothing consumes them, so tenants cannot
gate members-only or plan-gated routes at the edge and backend boxes are tempted to
build redundant route gates (against the division of labor: route protection = edge,
resource ownership = box). This is N4 Phase 2 in `nexus-upstream-requirements.md` — the
membership/plan-upsell lever at the edge, and the last open edge feature in that
contract.

## What Changes

- A tenant's per-route auth policy gains three optional requirement fields per rule:
  a required role, a required entitlement, and a minimum authentication assurance
  level. Absent fields mean the Phase-1 behavior is unchanged (fully backward
  compatible; zero-config routes stay pass-through).
- The tenant-routing stage resolves these alongside `auth_required` (same
  longest-prefix policy, same cache, same invalidation NOTIFY) and emits them as
  trusted policy signals (`x-auth-requires-role`, `x-auth-requires-entitlement`,
  `x-auth-min-aal`) only when set.
- A thin edge authorization step rejects with **403** any request whose injected
  identity enrichment does not satisfy the resolved requirements; requirements on a
  route imply a verified credential (an anonymous request on such a route still gets
  the Phase-1 **401**, never a 403 leak of policy detail).
- The three new policy signals join the client-strip list (C3): clients cannot
  self-assert or clear them.
- Control-plane auth-routes CRUD accepts and returns the new optional fields.
- Policy CRUD validation: a rule carrying any requirement field with
  `auth_required = false` is rejected as inconsistent at write time.

## Capabilities

### New Capabilities

(none — this extends the existing edge authentication gate into authorization; same
behavior domain, same policy source, same enforcement point)

### Modified Capabilities

- `edge-auth-gate`: the per-route policy signal family grows from the boolean
  `x-auth-required` to include role / entitlement / minimum-AAL requirements; the edge
  SHALL enforce them (403 on unsatisfied, 401 still owns the unauthenticated case),
  fail closed when enrichment is missing, and strip the new signals from client input.

## Impact

- `routing-rs/router-core` (auth policy types + resolve), `routing-rs/store-postgres`
  (`routing.auth_routes` gains three nullable columns), `routing-rs/control-plane`
  (CRUD payload + validation), `routing-rs/tenant-router` (signal emission).
- `edge/envoy.yaml` — strip-list entries for the three new signals; enforcement wiring
  per the design decision (existing filter vs identity sidecar — deferred to
  /opsx:decide).
- `identity-rs/sidecar` — candidate enforcement point (it already holds the enrichment
  and sits after the credential check).
- Critical concern for /opsx:decide: **the 403 enforcement mechanism** (adopt an Envoy
  filter vs extend the first-party sidecar).
- Cross-repo: no jsbox change required; boxes keep resource-ownership checks only.
- `nexus-upstream-requirements.md` — N4 flips to fully shipped once merged.
