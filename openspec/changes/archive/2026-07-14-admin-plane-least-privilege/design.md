## Context

The control plane (`routing-rs/control-plane`) fronts every admin mutation for the
platform. `admin-action-audit` gave it authentication with individually identifiable
actors (`require_auth` → `resolve_actor` in `app.rs`: named peppered-HMAC tokens in
`routing.admin_tokens`, plus the reserved `legacy-shared` / `auth-disabled` actors) and
an append-only ledger. Authorization does not exist: every accepted actor can call
every route on `:9400`, including `POST /admin-tokens` (mint) and
`/admin-tokens/{id}/revoke` — so any leaked token escalates to full control-plane
takeover with self-persistence.

The platform's L2 decision layer already exists and is deliberately
enforcement-surface-agnostic: the `authorization-policy-engine` spec (deny-by-default,
fail-closed, auditable reason, policy-as-data) is implemented by
`identity-rs/policy-cedar` — a thin Cedar adapter behind the vendor-agnostic
`PolicyDecisionPoint` port in `identity-rs/core/src/policy.rs`, with policy + schema as
validated data files and a `DenyAllPdp` installed on load failure. The edge gate is its
first consumer; this change adds the second.

Structural constraint: `routing-rs` and `identity-rs` are **separate Cargo
workspaces** with no dependency between them today.

## Goals / Non-Goals

**Goals:**

- Post-authentication, per-actor authorization of every admin action on `:9400`,
  deny-by-default and fail-closed, satisfying the `authorization-policy-engine`
  contract at a second enforcement surface.
- Credential administration (mint/revoke/list admin tokens) as a distinguished
  privilege that no ordinary grant includes.
- Grants provisioned with the credential, visible in the audit trail; authorization
  denials recorded on the existing ledger, attributed to the actor, with the decision
  reason.
- Parity cutover: existing tokens keep full power at deploy; narrowing is an explicit
  operator act.

**Non-Goals:**

- Per-tenant/workspace-scoped admin grants ("may only manage workspace X") — the grant
  model must not preclude it, but this change ships surface-level scopes only.
- Any change to the edge gate, the identity sidecar, or the `:9401` ops surface
  (health-only, stays open).
- A policy-authoring UI or grant self-service; provisioning stays an admin API call.
- Merging the two Cargo workspaces or extracting a shared platform crate (revisit if a
  third policy consumer appears).

## Decisions

### Decision: admin authorization decision evaluation — Adopt `cedar-policy`

- **Status**: approved (ratified at `/opsx:decide`, 2026-07-14)
- **Why**: reuse the engine already vetted and in-tree for the edge gate — one policy
  language platform-wide, zero new supply-chain surface, validated policy-as-data,
  and per-tenant grants later become a data change, not a rewrite.
- **Considered**: `regorus` (Microsoft's Rust Rego engine — mature, but a second
  policy language on a platform standardized on Cedar for L2); hand-rolled
  `scopes.contains(class)` check (smallest diff, but a second bespoke
  security-critical evaluator — the anti-pattern the authz strategy forbids).
- **Isolation**: the vendor-agnostic decision port in `router-core`; `cedar-policy`
  types confined to the new `routing-rs/policy-cedar` adapter crate; policy + schema
  as data files validated at construction, deny-all installed on load failure.

### D1 — Decision mechanism: reuse the adopted Cedar engine via a routing-side adapter crate (Adopt)

Build-vs-adopt (ratify at `/opsx:decide`): the evaluation of "may this actor perform
this action" is security-critical; hand-rolling a second rule evaluator would repeat
exactly what `adopt-cedar-policy-gate` removed from the edge. **Adopt `cedar-policy`
(already vetted, already in-tree at the same major version) via a new thin adapter
crate `routing-rs/policy-cedar`**, mirroring the identity-side adapter: engine types
confined to the crate, policy + schema as data files validated at construction,
construction failure → deny-all.

Alternatives rejected:

- *Cross-workspace path dependency on `identity-rs/policy-cedar`*: drags identity
  domain types (`AuthzFacts`, identity `PolicyRequest` — shaped for the edge PARC:
  roles/entitlements/AAL) into the routing workspace; the admin plane's PARC is
  different, so almost nothing reuses cleanly except the engine itself.
- *Hand-rolled scope check (`scopes.contains(action)`)*: cheap today, but it is a
  second bespoke authorization evaluator for a security-critical decision — the exact
  anti-pattern the strategy forbids — and it forecloses per-tenant grants (D6) without
  a rewrite.

### D2 — Port and dependency direction

A vendor-agnostic decision port lives in `router-core` (mirroring
`identity_core::PolicyDecisionPoint`: request in → `Decision { effect, reason }` out,
deny-by-default). `control-plane` (the entry point) sees only the port;
`routing-rs/policy-cedar` implements it; composition wiring in `main.rs` constructs the
Cedar PDP and installs deny-all on load failure. Inward-only: core defines the port,
adapters implement, the surface consumes.

### D3 — Grant model: surface scopes as principal attributes

Three scopes, mirroring the admin surface's natural action classes:

```
  read        GETs: accounts/workspaces/memberships/domains/auth-routes reads,
              audit query/export
  provision   mutations of platform data: accounts, workspaces, memberships,
              domains, auth-route rules, challenges
  token-admin admin-credential administration: mint, revoke, list admin tokens
```

`full` is not a stored scope — it is the set of all three (stored explicitly at
backfill, so the ledger shows real grants, not a magic alias). The Cedar model:
principal `AdminToken` with a `scopes` set attribute; actions grouped into the three
classes in `admin.cedarschema`; `admin.cedar` permits an action iff the principal's
scopes contain the action's class. No forbid rules in the parity set — deny-by-default
does the work.

The grant lives as a column on `routing.admin_tokens` (native SQL migration file under
`routing-rs/store-postgres/migrations/`, loaded by the existing migration adapter).
Minting requires an explicit non-empty scope set (fail-closed: an unscoped mint is a
400, not an implicit `full`).

### D4 — Enforcement point: declarative route-class table + a decision layer after `resolve_actor`

**As-built refinement (2026-07-14):** the sub-router tagging sketched at propose time
does not survive contact with axum's layering — a per-sub-router `Extension` tag is
applied *inside* the merged router's shared middleware, so a shared authorization
layer can never see it; only per-group middleware could, and then a route registered
outside every group would bypass the gate entirely (fail-OPEN). What a shared
`route_layer` middleware *can* see is `MatchedPath` — the exact route template axum
matched (never prefix parsing). So the classification is a declarative
`(method, route template) → class` table (`authz_gate::ROUTE_CLASSES`, the single
source of classification, kept beside the gate) consulted by ONE authorization
middleware running immediately after `require_auth` resolved the actor. This is
strictly stronger than the tagging sketch: a route absent from the table is DENIED
for every actor at runtime — a newly added endpoint cannot ship unclassified and
open — where an untagged sub-route would have been silently ungated.

The middleware loads the actor's scopes (rode along with `resolve_actor`'s token
lookup — no second store query), asks the PDP, threads the permitting reason into the
request's audit context on permit, and 403s with the decision reason on deny. A
completeness test pins the table's properties (`token-admin` is exactly the
`/admin-tokens` surface; no mutating method hides in `read`). `/healthz` stays
outside the gate as today.

Reserved actors: `auth-disabled` bypasses authorization exactly as it bypasses
authentication (the whole gate is explicitly off — trusted-network/dev only).
`legacy-shared` is treated as holding all scopes for as long as
`ADMIN_LEGACY_TOKEN_OK` keeps it alive — the migration crutch keeps its
deprecation-warned full power and dies on schedule.

### D5 — Audit: authorization denials join the ledger; decisions carry reasons

Extend the existing denial recording (admin-action-audit "Denied admin access is
recorded") with an authorization-denial event kind: actor id, surface, action class,
and the PDP's machine-readable reason — never the credential. Permitted mutations are
already recorded as action events; they additionally carry the permitting decision
reason so an audit review can see *why* an action was allowed without re-deriving it.
The existing invariant holds: a failed denial write never converts a deny into an
allow (and never converts a permit into a deny — the ledger write for the *denial
event* is best-effort exactly like today's authn denials).

### D6 — Forward-compatibility seam for per-tenant grants (deferred)

The PDP request shape includes a resource (today: the admin surface / the workspace id
already present in most route paths), even though the parity policy ignores it. When a
per-tenant admin grant is needed, it becomes a policy + schema change (data), not a
port or middleware change. Deliberately unexercised in this change.

## Risks / Trade-offs

- **[Operator lockout]** — narrowing or revoking the last `token-admin` grant locks the
  admin plane's credential administration. → The store refuses to revoke or de-scope
  the *last* remaining `token-admin`-scoped active token (same class of guard as a
  "last admin" rule); bootstrap/break-glass path documented in the runbook (the
  existing bootstrap grant flow already exists and is audited).
- **[Route misclassification]** — a mutating route registered in the `read` sub-router
  would be under-protected. → Deny-on-untagged default plus a test that walks the
  registered route table asserting every route carries a class and that
  `/admin-tokens*` routes are exactly the `token-admin` set; review checklist note in
  the runbook for future routes.
- **[Policy/schema drift between environments]** — admin policy is data deployed per
  environment. → Same posture as the edge policy: canonical parity set lives in the
  adapter crate, deploy overlays under `deploy/`; validated at startup, deny-all on
  failure (fails loud, not open).
- **[Migration foot-gun]** — backfill misses a token → that caller starts 403ing at
  cutover. → Backfill is one UPDATE setting all three scopes on every existing active
  token in the same migration that adds the column (atomic); parity verified in e2e
  before narrowing anything.
- **[Second Cedar adapter to maintain]** — some structural duplication with
  `identity-rs/policy-cedar`. → Accepted: the duplicated part is thin translation
  glue; the alternative (cross-workspace coupling) costs more. Revisit extraction on a
  third consumer.

## Migration Plan

1. Ship migration (scopes column + full backfill) and the tagged sub-routers with the
   PDP wired — behavior at this point is parity (every existing token holds all
   scopes; every route permits as before).
2. Verify parity e2e (existing admin flows unchanged; denial path exercised with a
   deliberately narrowed test token).
3. Mint narrowed named tokens for real callers (provisioning automation → `provision` +
   `read`; dashboards/review → `read`); flip callers over one at a time (ledger shows
   which token does what, so narrowing is observable, not guessed).
4. De-scope or revoke over-broad tokens; `token-admin` retained by the operator
   credential(s) only.
5. Rollback: revert to the previous image — the scopes column is additive and ignored
   by the old binary; no data rollback needed.

## Open Questions

- Should audit *query/export* (`read` today) be its own scope (`audit-read`) so a
  provisioning token can't trawl the ledger? Leaning no for the first slice (three
  scopes stay legible); the policy file makes it a data change later.
- Exact shape of the "last token-admin" guard (refuse vs warn-and-require-force) — pick
  during implementation; refuse is the fail-closed default.
