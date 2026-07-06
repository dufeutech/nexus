# Nexus upstream integration requirements

Requirements that downstream consumers — the **ingress/infra layer** (TLS/entry) and the
**backend services** ("boxes") on the internal network — place on **nexus**, plus the header contract
nexus publishes back to them. nexus is the authoritative core: routing, domain lifecycle,
identity enrichment, and edge policy live here; boxes stay thin and trust the headers the
edge injects. The contract is service-agnostic — any backend in any language is a box.

**This file is canonical in the nexus repo.** Consumers keep a mirror of the sections that
concern them; any change here must be reflected there ("pin any rename in both repos").

---

## Status (2026-07-03 — verified against source)

| Req    | State                        | Where                                                                                                      |
| ------ | ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **N1** | ✅ SHIPPED                   | `routing-rs/tenant-router/src/main.rs` — `GET /authorize` on `:9300` (`api::authorize`)                    |
| **N2** | ✅ SHIPPED                   | `routing-rs/control-plane/src/main.rs` — `/domains/declare`, `/domains/{d}/verify`, leader-elected TXT poll |
| **N3** | finding only                 | no work — kept below in case wildcard tiers are ever wanted                                                |
| **N4** | ✅ SHIPPED (both phases)     | phase 1 auth gate + phase 2 role/entitlement/AAL gate (change `edge-role-entitlement-gate`, 2026-07-02)    |
| **N5** | ✅ SHIPPED (superseded form) | acting-org semantics + tripwire shipped as `x-identity-contract: v1` (NO standalone scope header — spec decision 2026-07-01); **open action is backend-side** |
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

**Ingress-layer follow-up: ✅ done 2026-06-30** — `authz.py` + `Dockerfile.authz` + `pg_read_db`
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
production checklist. Backends keep only resource-ownership checks;
role/plan route gates are the edge's job now, both phases.

Default = pass-through: **no rows for a workspace means `auth: none`** (the `/` row is an
operator-set default, not auto-seeded), so any customer site works with zero URL
constraints; gating is opt-in.

---

## Open work in nexus

### N5 — acting-org assurance — ✅ shipped in nexus (superseded form); **open action is backend-side**

Both halves of N5 are live in nexus, but the tripwire shipped in a different (better)
form than the original ask, and the consuming backend must adapt to it (decided 2026-07-02):

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

**Backend action (the remaining N5 work, box-side):** replace the legacy
`x-tenant-scope == acting` check with the contract check — reject a tenant-scoped
request unless `x-identity-contract` is an accepted version (`v1` today) AND the acting
`x-workspace-id` + `x-user-type` are present; else `403`. Equivalent strength (both are
trusted-boundary tripwires, not cryptographic proof). Bring-up ordering concern
disappears: nexus already emits the stamp, so a backend can switch enforcement any time.
Bump `v1` → `v2` in BOTH repos together on any future header-shape change.

**Naming pin (part of the same backend action):** nexus injects `x-workspace-id`;
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

## Downstream header contract (what any box may rely on)

The edge strips all client-supplied `x-*` before the identity sidecar injects trusted
headers. Boxes treat these as authoritative and pre-authorized; they add only
resource-ownership checks.

> The table below is the identity subset. For the **complete** injected-header reference
> (every header with its exact format — including the `x-geo-*`, request-context, and
> provenance families — plus the origin-trust prerequisite and box responsibilities), see
> [`docs/box-consumer-contract.md`](docs/box-consumer-contract.md).

| Header                                             | Meaning                                                            | Status                        |
| -------------------------------------------------- | ------------------------------------------------------------------ | ----------------------------- |
| `x-workspace-id`                                   | the **authorized acting workspace** (live membership check)        | shipped (`x-tenant-id` = legacy fallback only — pin the rename) |
| `x-user-id`                                        | the user, for audit                                                | shipped                       |
| `x-user-roles`, `x-user-entitlements`, `x-auth-method` | enrichment inputs (also enforced at the edge per-route, N4 Phase 2) | shipped (injected + enforced) |
| `x-auth-required`, `x-auth-requires-*`, `x-auth-min-aal` | edge-internal policy signals (jwt_authn branch + sidecar 403 gate); stripped, never reach boxes | shipped                       |
| `x-identity-contract: v1`                          | versioned contract stamp = the acting-org tripwire (a valid `vN` carries acting `x-workspace-id` + `x-user-type`); boxes reject unknown/absent versions on enriched routes | shipped (the backend must switch its check to this — N5) |
| `traceparent`                                      | W3C trace context, **always edge-rooted** (client copies stripped; sampled flag = the edge's head decision) | shipped (boxes still fail open when absent) |

---

## Box telemetry contract (the observability twin of the header contract)

**Published 2026-07-03** (change `box-telemetry-contract`). What any box on the internal
network — any backend service, in any language — can rely on nexus for,
and what it must emit to be observable. Anchored on OTLP + the OTel semantic conventions
so a box in ANY language complies with off-the-shelf instrumentation and zero nexus-side
integration work.

**What nexus provides:**

- **ONE collection endpoint** (the OTel Collector) accepting **traces, metrics, and
  logs** over OTLP (gRPC `:4317` / HTTP `:4318`). A box knows this endpoint and nothing
  else; only the collector's config knows the stores (traces → Tempo, pushed metrics →
  Prometheus, logs → Loki — one Grafana, logs↔traces pivot in both directions). Store
  changes never touch a box.
- **Edge-rooted W3C trace context** on every request (N6 above; sampled flag = the
  edge's head decision).
- **Fail-open, both ways:** a collector/store outage never affects request handling
  (verified: requests keep serving, telemetry resumes on its own), and one box's
  telemetry volume cannot block another producer's request path.

**What a compliant box emits (all through that one endpoint):**

- **Resource identity on every signal:** `service.name`, `service.version`,
  `deployment.environment.name` — identical values across traces, metrics, and logs, so
  one identity selects the service in every signal and two versions are distinguishable
  during a rollout.
- **Traces:** continue the edge-rooted `traceparent` when present (root only when
  absent); no tail sampling box-side.
- **Logs:** structured and severity-tagged, stamped with the active `trace_id`/`span_id`
  while handling a traced request — that's what makes the two-way pivot work.
- **RED metrics (request-driven boxes):** request rate, error count/ratio, and duration
  as an aggregatable **histogram** — fleet-wide p50/p95/p99 must be computable across
  replicas (pre-computed per-replica percentiles are NOT the canonical latency signal).
  RED metrics are first-class: deriving them from sampled traces is a defect — turning
  the edge sampling knob down must not move any metric (verified).
- **PII hygiene — the edge access-log rule applies to every signal:** no credential
  material, no request/response bodies, no user identifiers beyond the permitted
  trusted-header set, in any span attribute, metric label, or log field. The structured
  form keeps this mechanically checkable (e.g. a LogQL sweep like
  `` {service_name=~".+"} |~ `(?i)(bearer\s+[a-z0-9._-]+|authorization:|password|set-cookie)` ``);
  the collector is the future enforcement/redaction point.

**Onboarding a new box in any language = one env var:** run the standard OTel SDK /
auto-instrumentation and set `OTEL_EXPORTER_OTLP_ENDPOINT=<collector>`. Verified
2026-07-03 with a throwaway auto-instrumented Python box: identity, trace continuation +
log correlation, hygiene detectability, sampling independence, and fail-open all pass
with no custom telemetry code.

**First-party services are compliant boxes too (Change B — `first-party-telemetry`,
2026-07-05).** The nexus Rust planes — tenant-router, control-plane, identity sidecar,
sync-worker, reconciler, membership-sync — now emit all three signals through the same
one endpoint: they continue the edge-rooted trace on the ext_proc hot path (the routing
and enrichment spans sit inside the edge trace, no first-party hole), stamp `trace_id`
on their logs, and push RED + operational metrics to the collector (their Prometheus
scrape endpoints retired; metric names unchanged). The single knob is the same
`OTEL_EXPORTER_OTLP_ENDPOINT` (unset ⇒ telemetry off, fail-open). This makes the
first-party RED baseline contract-shaped, which is the prerequisite for the policy layer
(Change C: SLO targets, burn-rate alerts, keep policy) to build on.

**Cardinality and volume are bounded at the collector — a box cannot blow up the shared
bill (change `telemetry-cost-controls`, 2026-07-06).** The cost of any one producer is
now capped at the single egress and the stores, downstream of every box: high-cardinality
**metric attributes** are collapsed to an identity + RED allow-list at the collector
(a box that stamps a `user_id`/raw-path/request-id label on a metric has that dimension
dropped before it reaches the store — its series stay within budget), and **log volume**
is per-stream rate-limited store-side (a chatty box has its own excess refused, reported
via `loki_discarded_samples_total`). A misbehaving box degrades **its own** telemetry
fidelity, never another producer's signals, the shared store, or the request path (the
guards sit downstream of the fail-open emission contract — nothing here changes what a box
emits). The stores also run on an **object-storage tier** with explicit, owned per-signal
retention (traces 48h, logs 7d, metrics 15d — config values, not defaults). Successor work
is recorded in the change's `design.md` roadmap, not here: long-term/downsampled metric
retention (Mimir/Thanos), the SLO + burn-rate policy layer on the RED baseline, and
signal-quality (error-biased) trace retention — the last explicitly a signal feature, not
a cost lever (tail sampling is a ruled-out non-goal: the edge head decision stays the trace
cost ceiling).

---

## Ownership

| Concern                                                                               | Owner                                                                        |
| -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| declare, quota, TXT verify, invalidation NOTIFY                                       | **nexus control-plane**                                                      |
| routing match + per-host `/authorize` (N1)                                            | **nexus tenant-router**                                                      |
| per-route auth policy resolve + `x-auth-*` emit (N4)                                  | **nexus tenant-router** (resolve/emit) + **control-plane** (policy CRUD)     |
| per-route 403 gate: role / entitlement / min-AAL enforcement (N4 Phase 2)             | **nexus identity sidecar**                                                   |
| acting-org authorization + trusted header injection + contract stamp (N5)             | **nexus identity sidecar**                                                   |
| contract-stamp enforcement (`x-identity-contract` version check)                      | **backend boxes** (any downstream service)                                   |
| trace rooting + `traceparent` injection (N6)                                          | **nexus edge (Envoy)** + monitoring collector                                |
| telemetry collection endpoint + stores + Grafana pivot (box telemetry contract)       | **nexus monitoring stack** (collector/Tempo/Prometheus/Loki)                 |
| contract-compliant emission (identity attrs, RED histograms, correlated logs, hygiene) | **backend boxes** (any downstream service) **+ the nexus first-party planes** (Change B) |
| authentication method (password/passkey/MFA/social/SSO)                               | **ZITADEL** (per-org login policy)                                           |
| ingress `edge.<base_domain>`, shared cert store, Caddy on-demand wiring, `plan→limit` | **ingress / infra layer**                                                    |
| `CNAME <domain> → edge.<base_domain>` + the `_nexus-challenge` TXT                    | **tenant**                                                                   |
| resource ownership ("does this user own THIS order"), scope-header enforcement       | **backend boxes** (any downstream service)                                   |
