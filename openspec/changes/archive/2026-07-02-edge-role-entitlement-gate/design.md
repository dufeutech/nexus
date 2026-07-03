# Design: edge-role-entitlement-gate

## Context

Phase 1 shipped the boolean gate: `router-core::auth` resolves a per-tenant
longest-prefix `AuthPolicy` from `routing.auth_routes`, the tenant-router ext_proc
emits `x-auth-required`, and Envoy's `jwt_authn` branches on it (`allow_missing` vs
`provider`), with the signal in the C3 client-strip list. The identity sidecar (a
second ext_proc, after `jwt_authn`) already computes and injects `x-user-roles`,
`x-user-entitlements`, `x-auth-method` from the live membership store. Filter order
today: header_mutation (C3 strip) → tenant-router ext_proc → jwt_authn → identity
sidecar ext_proc. Phase 2 adds the authorization half: per-route role / entitlement /
minimum-AAL requirements, enforced at the edge with 403.

## Goals / Non-Goals

**Goals:**
- Extend the per-route policy with three optional requirement fields, end to end
  (store → resolve → emit → enforce), reusing every Phase-1 mechanism (same table,
  same cache, same `routing_invalidations` NOTIFY, same CRUD surface, same strip
  list).
- Enforce at the edge with 403, fail-closed, after the 401 authentication step.
- Zero behavior change for rules that set no requirement fields.

**Non-Goals:**
- Authentication METHOD selection (stays in ZITADEL per-org login policy).
- Resource ownership (stays in backend boxes).
- Multi-valued requirements (role lists, any-of/all-of expressions) — single value
  per field now; the header contract leaves room to extend.
- A generic policy language (OPA/Cedar territory — out of scope at this scale).

## Decisions

### D1 — Enforcement point: extend the identity sidecar (not an Envoy RBAC filter, not a new service)

The requirement is a dynamic-vs-dynamic comparison: per-tenant, per-route required
values (resolved at request time by the tenant-router) against per-user enrichment
(resolved at request time from the membership store). Envoy's RBAC filter can
technically reach request headers through CEL `condition` clauses, but cannot model
this **robustly**: the richer `HttpAttributesCelMatchInput` is not allowlisted for
RBAC matchers, list-membership against a comma-joined header degrades to substring
matching (`admin` matches inside `superadmin`), and the AAL method→level mapping
would live as CEL strings embedded in YAML — outside any unit-test harness. The identity sidecar is already
in the chain **after** `jwt_authn`, already holds the user's roles/entitlements/
method **in process** (no header re-parsing; it authored them), and ext_proc
supports immediate responses (it already 403s on suspension). Enforcement there is
~a comparison function plus an immediate-403 branch, unit-testable in
`identity-rs`. Recorded for /opsx:decide: **Extend** (first-party sidecar) over
Adopt (Envoy RBAC — cannot express it) over Build (new ext_authz service — a third
hop and a new deployable for a comparison).

Consequence of the position: the sidecar reads the requirement signals emitted by
the tenant-router from the request headers it receives (same hop-internal channel
as `x-auth-required` → jwt_authn today).

### D2 — Data model: three nullable columns on `routing.auth_routes`

`requires_role text NULL`, `requires_entitlement text NULL`, `min_aal smallint
NULL` on the existing table, following the store's existing schema-bootstrap
pattern (idempotent `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` next to the
existing `CREATE TABLE IF NOT EXISTS`). NULL = requirement absent = Phase-1
behavior; no second table, no policy blob. `AuthPolicy`/`AuthRule` in
`router-core::auth` gain the three `Option` fields; the longest-prefix `resolve`
is untouched (the whole matched rule already wins — requirements ride it).

### D3 — Write-time validation in the control-plane, not the router

`auth_required = false` + any requirement field is rejected at CRUD time
(structured 400), so inconsistent rules never enter the store and the router never
needs a runtime reconciliation rule. Defense in depth at the router: if an
inconsistent row is ever read (manual SQL), the router treats any requirement as
implying `auth_required = true` (fail-closed interpretation, matching the spec's
"requirements imply authentication").

### D4 — AAL mapping is edge config data, defined once

The method→level mapping (`none = 0`, `bearer = 1` today; MFA/passkey levels slot
in when the method signal carries them) is data-driven through the sidecar's
existing config surface — env-based, like every other sidecar knob and the
control-plane's `ROUTING_PLAN_LIMITS` precedent: `SIDECAR_AAL_LEVELS`
(`method=level,…`) with the default pinned in one constant. Not hardcoded logic,
not duplicated in the router. The router emits the tenant's *demand* (`x-auth-min-aal: 2`); only the
sidecar maps the request's method to a level and compares. One owner for the
ordering; tenants never see method names, only levels.

### D5 — Signal semantics: absent means no requirement; present is authoritative

The tenant-router emits each of the three signals only when the resolved rule sets
the field (no `"false"`/empty sentinel values — absence IS the no-requirement
state, mirroring how zero-config tenants work in Phase 1). All three names join the
C3 strip list in `edge/envoy.yaml`, adjacent to `x-auth-required`. The sidecar
strips the three signals from the request it forwards upstream (policy detail does
not leak to backends; parity with what backends actually need — none of it).

### D6 — Deploy ordering: sidecar (enforcer) before tenant-router (emitter)

A router that emits signals to a sidecar that ignores them = silently open gate
for the new fields. Reverse order is safe: a sidecar that enforces signals nobody
emits enforces nothing. So ship/roll the sidecar first, router second, in the same
release. Pre-users, single-release concern only.

### Decision: per-route 403 enforcement mechanism — Extend identity sidecar

- **Status**: approved (2026-07-02)
- **Why**: the enforcer needs the request-time policy signals AND the request-time
  enrichment; the sidecar already holds both in process, sits after the 401 stage,
  and has an immediate-403 path — enforcement becomes a unit-testable comparison
  function instead of logic embedded in edge YAML.
- **Considered**: Adopt Envoy RBAC + CEL (expressible but fragile: substring-level
  list matching, no home for the AAL mapping, untestable CEL-in-YAML); Adopt OPA via
  ext_authz (mature, but a new deployable + policy language for three single-valued
  fields — revisit if policy grows into expressions/any-of/tenant-authored rules).
- **Isolation**: enforcement lives in `identity-rs/sidecar` behind its ext_proc
  boundary; the AAL method→level mapping is external config behind the sidecar's
  config adapter; the header contract (`x-auth-requires-*`) is the only coupling to
  the routing plane.

## Risks / Trade-offs

- [Degraded enrichment turns into 403s on gated routes] → intended fail-closed
  behavior per spec; only routes that opted into requirements are affected, public
  and boolean-gated routes are untouched.
- [Single-valued requirements may prove too coarse (any-of roles)] → the header
  contract can grow a delimiter later behind a contract-version bump; the column
  can widen to an array — deferred until a tenant needs it.
- [Sidecar becomes both enricher and enforcer] → acceptable coupling: enforcement
  consumes exactly the values the enricher just computed; splitting it would
  re-introduce a parsing boundary and a deploy-ordering hazard inside one hop.
- [Hop-internal signal tampering between router and sidecar] → same trust model as
  `x-auth-required` → jwt_authn today (single Envoy process; C3 strips client
  input); no new boundary is created.

## Migration Plan

1. Store: additive nullable columns (idempotent bootstrap; no data migration).
2. Deploy sidecar (enforcer), then tenant-router (emitter), then envoy.yaml strip
   additions — one release, ordered within it (D6).
3. Rollback = revert deploys; rules with requirement fields simply stop being
   enforced (columns are inert to Phase-1 binaries, which neither read nor emit
   them).
4. Flip N4 to shipped in `nexus-upstream-requirements.md`; notify jsbox (FYI only —
   no box-side change).

## Open Questions

- None blocking. AAL levels beyond `bearer = 1` activate only when the
  authentication-method signal starts distinguishing MFA/passkey (ZITADEL AMR) —
  tracked as a follow-up, not part of this change.
