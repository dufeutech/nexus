# Nexus upstream integration requirements

Requirements that downstream consumers — **toolify** (infra/entry), **jsbox/runlet** (the
first backend box), and every future box on the internal network — place on **nexus**, plus
the header contract nexus publishes back to them. nexus is the authoritative core: routing,
domain lifecycle, identity enrichment, and edge policy live here; boxes stay thin and trust
the headers the edge injects.

**This file is canonical in the nexus repo.** Consumers (jsbox today) keep a mirror of the
sections that concern them; any change here must be reflected there ("pin any rename in
both repos").

---

## Status (2026-07-03 — verified against source)

| Req    | State                        | Where                                                                                                      |
| ------ | ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **N1** | ✅ SHIPPED                   | `routing-rs/tenant-router/src/main.rs` — `GET /authorize` on `:9300` (`api::authorize`)                    |
| **N2** | ✅ SHIPPED                   | `routing-rs/control-plane/src/main.rs` — `/domains/declare`, `/domains/{d}/verify`, leader-elected TXT poll |
| **N3** | finding only                 | no work — kept below in case wildcard tiers are ever wanted                                                |
| **N4** | ✅ SHIPPED (both phases)     | phase 1 auth gate + phase 2 role/entitlement/AAL gate (change `edge-role-entitlement-gate`, 2026-07-02)    |
| **N5** | ✅ SHIPPED (superseded form) | acting-org semantics + tripwire shipped as `x-identity-contract: v1` (NO standalone scope header — spec decision 2026-07-01); **open action is jsbox-side** |
| **N6** | ✅ SHIPPED                   | edge-rooted W3C tracing (change `edge-rooted-tracing`, 2026-07-03): Envoy OTel tracer → collector → Tempo; client trace context stripped at C3 |

---

## Shipped — contract lives in code and docs, not restated here

### N1 — tenant-router `/authorize` (the on-demand TLS gate)

`GET /authorize?domain=<sni>` on the tenant-router's `:9300` API. Resolves with the SAME
`resolve()` path as routing and fails closed (`403`) on empty/unknown/pending/not-ready —
a domain that authorizes a cert is, by construction, a domain the router will route.
Consumer-side contract (Caddy `ask` wiring, fail-closed semantics): `docs/on-demand-tls.md`.
Emits `router_authorize_total{result=allow|deny}`.

### N2 — control-plane domain lifecycle (declare + TXT-verify + quota)

`POST /domains/declare` — plan-quota gate via data-driven `ROUTING_PLAN_LIMITS`, structured
`402 quota_exceeded {plan, limit, used}`, idempotent challenge
(`_nexus-challenge.<domain>` TXT), pending-TTL sweep (`ROUTING_PENDING_TTL`).
`POST /domains/{domain}/verify` + a leader-elected background TXT poll: on token match set
`verified` and `pg_notify('routing_invalidations', domain)` — the single invalidation path;
routers and the cert gate converge in seconds. Once `verified`, everything downstream
(authorize → issue → share to all balancers → route) is automatic, zero operator touch.

Product model (decided, unchanged): tenants declare each (sub)domain explicitly; the
per-tenant domain count is plan-gated (the upsell lever).

**toolify follow-up: ✅ done 2026-06-30** — `authz.py` + `Dockerfile.authz` + `pg_read_db`
deleted; Caddy `on_demand_tls { ask }` → `http://tenant-router:9300/authorize`;
tenant-router joined the `edge` network. Deploy order: `nexus-edge` then `entry`.

### N4 — per-route auth gate, both phases

**Phase 1** (anonymous pass-through): `router-core::auth` (policy types +
longest-prefix `resolve`), `routing.auth_routes` (per-tenant path-prefix rules),
control-plane CRUD at `PUT/GET/DELETE /workspaces/{id}/auth-routes` (legacy
`/tenants/{id}/auth-routes` alias), tenant-router emits `x-auth-required`, and
`edge/envoy.yaml` branches jwt_authn on it — `allow_missing` (NOT
`allow_missing_or_failed`: missing token → anonymous pass-through,
present-but-invalid still 401s) — with `x-auth-required` in the C3 strip list.

**Phase 2** (role / entitlement / min-AAL — shipped 2026-07-02, change
`edge-role-entitlement-gate`): a rule may additionally carry `requires_role`,
`requires_entitlement`, `min_aal` (same table, same NOTIFY invalidation, same
CRUD; a requirement combined with `auth_required=false` is rejected 400 at write
time). The tenant-router emits `x-auth-requires-role` /
`x-auth-requires-entitlement` / `x-auth-min-aal` only when the resolved rule sets
them; the identity sidecar enforces them **403** fail-closed against its
in-process enrichment (roles token-then-profile, entitlements from the live
Profile, method→AAL ordering via `SIDECAR_AAL_LEVELS`, default `none=0,bearer=1`)
and strips the signals before the backend — policy detail never leaves the edge.
All three names are in the C3 strip list. An anonymous caller on a gated route
still gets the Phase-1 **401** (requirements imply authentication), so
authorization policy is never disclosed to anonymous callers. Rollout order:
sidecar (enforcer) before tenant-router (emitter) — pinned in `deploy/README.md`'s
production checklist. Backends like jsbox keep only resource-ownership checks;
role/plan route gates are the edge's job now, both phases.

Default = pass-through: **no rows for a workspace means `auth: none`** (the `/` row is an
operator-set default, not auto-seeded), so any customer site works with zero URL
constraints; gating is opt-in.

---

## Open work in nexus

### N5 — acting-org assurance — ✅ shipped in nexus (superseded form); **open action is jsbox-side**

Both halves of N5 are live in nexus, but the tripwire shipped in a different (better)
form than the original ask, and jsbox must adapt to it (decided 2026-07-02):

- **Semantics (shipped):** the identity sidecar authors the acting workspace from a
  **live membership check** of the resolved workspace (`identity-rs/sidecar/src/main.rs`,
  header-authoring block), never from the token's `resourceowner` — the home org is
  retired as an authz input (`x-user-org` is never authored and always stripped;
  `resourceowner` only populates `Profile.home_org` in the projection). The injected
  `x-workspace-id` IS the authorized acting org.
- **Tripwire (shipped, superseded form):** the spec `identity-workspace-authz` (synced
  2026-07-01) folds the acting-scope guarantee into the **versioned contract stamp**:
  the sidecar emits `x-identity-contract: v1` on every enriched request, a valid `vN`
  request by definition carries the acting `x-workspace-id` + `x-user-type`, and there
  is **NO standalone acting-scope marker header** (`x-tenant-scope` was deliberately
  retired — one coordination gate, not two sentinels to keep in sync). The edge strips
  client-supplied `x-identity-contract` (C3), and header-shape drift is a version bump
  that fails closed on partial rollout.

**jsbox action (the remaining N5 work, box-side):** replace runlet's
`x-tenant-scope == acting` check with the contract check — reject a tenant-scoped
request unless `x-identity-contract` is an accepted version (`v1` today) AND the acting
`x-workspace-id` + `x-user-type` are present; else `403`. Equivalent strength (both are
trusted-boundary tripwires, not cryptographic proof). Bring-up ordering concern
disappears: nexus already emits the stamp, so jsbox can switch enforcement any time.
Bump `v1` → `v2` in BOTH repos together on any future header-shape change.

**Naming pin (part of the same jsbox action):** nexus injects `x-workspace-id`;
`x-tenant-id` survives only as a legacy read-fallback inside the sidecar. Boxes read
`x-workspace-id` (their trusted-header names are configurable box-side).

### N6 — W3C `traceparent` propagation

**Shipped 2026-07-03** (change `edge-rooted-tracing`). The edge is the sole root of trace
context on the internal network: client `traceparent`/`tracestate` are stripped BEFORE
Envoy's join-vs-root tracing decision (early header mutation) and again in the C3 filter
strip, the edge makes the head-sampling decision (env/values knob; unsampled requests
carry a not-sampled `traceparent` to the box), and injects W3C trace context toward the
pools. Export is OTLP/gRPC to an OTel Collector — the single telemetry egress; only the
collector's config knows the trace store (Tempo, queryable in Grafana by trace ID).
Tracing config lives in all edge topologies: `edge/envoy.yaml` +
`deploy/compose/envoy/envoy.yaml` (compose) and the helm charts (`edge.tracing.*`
values). Fail-open verified: a down collector never affects requests. Boxes continue the
trace and do no tail sampling; bring-up order stays flexible (boxes tolerate either
order). Span attributes observe the access-log PII hygiene (no credentials, no
`x-user-*`, no bodies).

---

## N3 — finding: wildcard apex coexistence (no work planned)

Verified live 2026-06-21, kept in case wildcard tiers are ever wanted: one row per
`domain` string; `is_wildcard=true` routes subdomains but NOT the apex, `false` routes
only the apex, and a literal `*.x.com` row never matches (the router strips the left
label). So apex + wildcard-subdomains cannot coexist for one domain. If wildcard tiers are
wanted: key by `(domain, is_wildcard)` or let a wildcard cover its own apex — and publish
ONE canonical matching spec that the router and any other gate implement identically.

---

## Downstream header contract (what boxes like jsbox may rely on)

The edge strips all client-supplied `x-*` before the identity sidecar injects trusted
headers. Boxes treat these as authoritative and pre-authorized; they add only
resource-ownership checks.

| Header                                             | Meaning                                                            | Status                        |
| -------------------------------------------------- | ------------------------------------------------------------------ | ----------------------------- |
| `x-workspace-id`                                   | the **authorized acting workspace** (live membership check)        | shipped (`x-tenant-id` = legacy fallback only — pin the rename) |
| `x-user-id`                                        | the user, for audit                                                | shipped                       |
| `x-user-roles`, `x-user-entitlements`, `x-auth-method` | enrichment inputs (also enforced at the edge per-route, N4 Phase 2) | shipped (injected + enforced) |
| `x-auth-required`, `x-auth-requires-*`, `x-auth-min-aal` | edge-internal policy signals (jwt_authn branch + sidecar 403 gate); stripped, never reach boxes | shipped                       |
| `x-identity-contract: v1`                          | versioned contract stamp = the acting-org tripwire (a valid `vN` carries acting `x-workspace-id` + `x-user-type`); boxes reject unknown/absent versions on enriched routes | shipped (jsbox must switch its check to this — N5) |
| `traceparent`                                      | W3C trace context, **always edge-rooted** (client copies stripped; sampled flag = the edge's head decision) | shipped (boxes still fail open when absent) |

---

## Ownership

| Concern                                                                               | Owner                                                                        |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| declare, quota, TXT verify, invalidation NOTIFY                                       | **nexus control-plane**                                                      |
| routing match + per-host `/authorize` (N1)                                            | **nexus tenant-router**                                                      |
| per-route auth policy resolve + `x-auth-*` emit (N4)                                  | **nexus tenant-router** (resolve/emit) + **control-plane** (policy CRUD)     |
| per-route 403 gate: role / entitlement / min-AAL enforcement (N4 Phase 2)             | **nexus identity sidecar**                                                   |
| acting-org authorization + trusted header injection + contract stamp (N5)             | **nexus identity sidecar**                                                   |
| contract-stamp enforcement (`x-identity-contract` version check)                      | **backend boxes** (jsbox/runlet, …)                                          |
| trace rooting + `traceparent` injection (N6)                                          | **nexus edge (Envoy)** + monitoring collector                                |
| authentication method (password/passkey/MFA/social/SSO)                               | **ZITADEL** (per-org login policy)                                           |
| ingress `edge.<base_domain>`, shared cert store, Caddy on-demand wiring, `plan→limit` | **toolify / infra**                                                          |
| `CNAME <domain> → edge.<base_domain>` + the `_nexus-challenge` TXT                    | **tenant**                                                                   |
| resource ownership ("does this user own THIS order"), scope-header enforcement       | **backend boxes** (jsbox/runlet, …)                                          |
