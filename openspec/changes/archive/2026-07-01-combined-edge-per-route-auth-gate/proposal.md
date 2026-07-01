## Why

The combined production edge (`deploy/compose/envoy/envoy.yaml` and the
`edge-platform` Helm configmap) hard-requires a valid JWT on `prefix:/` for every
route. But the product (N1/N2: on-demand TLS for arbitrary tenant **custom
domains**) is built to serve public tenant sites — so an anonymous visitor to a
tenant's public marketing page currently gets a **401**. Meanwhile the per-route
machinery to fix this already exists end-to-end (control-plane `auth_routes` CRUD,
the tenant-router emitting `x-auth-required`, the C3 client-copy strip) — only the
final consumer, the `jwt_authn` rules block, was never wired to branch on it. The
signal is computed, stripped for unforgeability, even documented in a comment, then
discarded.

## What Changes

- Replace the combined edge's blanket `jwt_authn` rule (`prefix:/ → requires:
  zitadel`) with the N4 per-route gate that branches on the `x-auth-required`
  header the tenant-router already emits. **BREAKING** (intended): a tenant with no
  `auth_routes` configured flips from default-deny (everything 401s) to
  default-allow (public), with protection opted in per path-prefix.
- Use an **inverted, fail-safe catch-all**: an explicit `x-auth-required: "false"`
  opens a route (`allow_missing`); `"true"` *or* an absent header falls through to
  `requires: zitadel`. This preserves the fail-closed posture the rest of nexus
  holds (sidecar fail-closed, control-plane fail-closed startup) even if
  `failureModeAllow` is ever flipped to `true`.
- Backport the same inverted catch-all to the canonical `edge/envoy.yaml`, which
  today uses an `allow_missing` catch-all (fail-open if the signal is ever absent).
- Fix the now-true-able comments in all three configs so documentation matches the
  rules.
- A *present-but-invalid* token must still be rejected on every route (public
  included) — `allow_missing`, never `allow_missing_or_failed`.

Out of scope (captured as a follow-up in design.md): the **identity-plane /
split-topology `x-auth-required` handoff**. identity-plane has no tenant-router and
strips `x-auth-required` at ingress, so per-route adoption there is a trust-boundary
design, not a rules swap. Also out of scope: N4 phase-2 (role/entitlement/AAL gate).

## Capabilities

### New Capabilities
- `edge-auth-gate` — the observable per-route authentication contract at the
  combined edge: how a request's required/optional/forbidden authentication is
  determined from the tenant's per-route policy, and what the edge does on each
  outcome (verify, allow-anonymous, reject-invalid) including the failure modes.

### Modified Capabilities
- None. (`openspec/specs/` has no synced specs yet — the routing/auth behavior was
  shipped ahead of the spec scaffold, so this is recorded as a new capability rather
  than a delta.)

## Impact

- **Config only, no Rust change.** `deploy/compose/envoy/envoy.yaml`,
  `deploy/helm/edge-platform/templates/edge-configmap.yaml`, and (backport)
  `edge/envoy.yaml` — the `jwt_authn.rules` block plus comment corrections.
- **No new dependencies.** The control-plane `auth_routes` API, the tenant-router
  emission, and the C3 strip are unchanged and already deployed.
- **Behavioral, security-sensitive:** default posture for unconfigured tenants flips
  to public. Requires the operator-facing note that protection is opt-in via
  `auth_routes` (a `/` rule protects the whole site; specific prefixes carve out).
- Depends on the invariant that `x-auth-required` is stripped from client input
  before `jwt_authn` (already true in all affected configs) — the inverted catch-all
  makes the strip load-bearing, so it is re-asserted as a spec requirement.
