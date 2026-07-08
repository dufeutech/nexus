## Context

nexus ships a RED baseline but cannot express an SLO. Verified current state (from the
`platform-ha-and-hardening` exploration, checked against source 2026-07-08):

- The only true duration histograms are the two hot-path ext_proc planes —
  `router_ext_proc_duration_seconds` (`tenant-router/src/main.rs:81-117`) and
  `sidecar_ext_proc_duration_seconds` (`identity-rs/sidecar/src/main.rs:95-117`),
  buckets `[0.00005 … 5.0]`. Both are recorded with an **empty attribute set**
  (`.record(elapsed, &[])` at `main.rs:605` / `:1173`), so latency slices only by
  service/env — never by outcome. The availability SLO is un-expressible today.
- The collector cardinality allow-list (`monitoring/otel-collector/otel-collector.yaml`,
  `transform/cardinality` keep_keys) **already admits `result`** as a low-card RED
  dimension — so outcome attribution needs no cost-control change.
- An alert scaffold exists but is single-window threshold only: Helm `PrometheusRule`
  CRs (`deploy/helm/*/templates/prometheusrule.yaml`, default-off). No recording rules,
  no error budget, no burn rate. The lab Prometheus (`monitoring/prometheus/
  prometheus.yml`) has no `rule_files:` at all.
- `deployment.environment.name` is operator-supplied via `OTEL_RESOURCE_ATTRIBUTES`,
  not guaranteed — a per-environment SLO layer cannot rely on it as-is.

This change (frontier **A** in the exploration) is the always-ship instrument. B
(trust hardening) and D (multi-region/HA, driver = failure-survival → CNPG) are parked
and out of scope.

## Goals / Non-Goals

**Goals:**
- Make hot-path latency outcome-aware so availability/latency SLOs are expressible.
- Turn `deployment.environment` into a required, deploy-time-verified invariant.
- Add a service SLO layer: objectives + error budgets + multi-window burn-rate alerts,
  expressed as data, runnable on a clean checkout.
- Keep the telemetry fail-open guarantee intact — no new request-path failure mode.

**Non-Goals:**
- No change to the collector cardinality allow-list or storage/retention.
- No trace/tail-sampling change; burn is computed from metrics, not traces.
- No B (mTLS, signing, key rotation) or D (NATS transport, CNPG, global uniqueness)
  behavior. No new alerting *product* — reuse the existing rule scaffold.
- No new duration histograms for the counter-only planes (control-plane, authz-admin,
  membership-sync); this change fixes and exploits the two that exist.

## Decisions

**Core vs. adapters / dependency direction.** The SLO policy is *data, not code*:
objectives, recording rules, and multi-window burn-rate alert rules live in
native-format files (rule YAML + an objectives data file) and are loaded by the
existing metrics stack (Prometheus rule evaluation) as the adapter. No business logic
enters application code. The only code-side change is the outcome attribution at the
emit point, which stays inside each service's telemetry adapter boundary. Dependency
direction is inward-only: services emit; the SLO layer is a downstream read-only
consumer that no service depends on.

**Decision 1 — Outcome attribution at record time.** Replace the empty attribute set on
the two duration histograms with a single low-cardinality `result` attribute
(success vs. error), computed from the outcome the handler already determines, recorded
at the existing `.record()` call site. Alternative considered: derive availability from
the separate `*_requests_total{result=…}` counters and leave latency fused — rejected
because it leaves latency-by-outcome (the "slow errors vs. slow successes" question)
permanently un-answerable and the defect unfixed.

**Decision 2 — Deployment environment as a deploy-time invariant.** Enforce a valid
`deployment.environment.name` at deploy/startup admission (chart render / service
startup fails closed on absence), NOT at request time. Alternative considered:
request-time validation — rejected outright as it would violate the
telemetry-never-affects-resolution invariant. The value stays configuration supplied
once via environment; enforcement just moves from "hope an operator set it" to
"deployment refuses without it."

**Decision 3 (critical concern — build-vs-adopt).** The error-budget / burn-rate
evaluation is the reliability-critical concern. **Ratified via `/opsx:decide`: Adopt
Sloth** (CLI generator mode) to turn SLOs-as-data into the multi-window,
multi-burn-rate (MWMB) recording + alert rules, rendered into the existing
`PrometheusRule` scaffold. See the ADR block below for the full rationale and
alternatives.

**Decision 4 — One canonical objectives definition.** SLO targets and windows are
defined once in an objectives data file and referenced by the generated rules — never
duplicated as magic literals across alert expressions. Lab and prod load the same
policy, differing only by config, satisfying the clean-checkout requirement (add
`rule_files:` to the lab Prometheus; reuse the Helm scaffold in prod).

### Decision: burn-rate/error-budget engine — Adopt Sloth

- **Status**: approved
- **Why**: SLOs declared as data are compiled by Sloth's CLI into correct Google-SRE
  MWMB recording + alert rules at build time; the error-prone burn-rate math is
  generated, not hand-written, and it renders into the existing `PrometheusRule`
  scaffold with **zero new runtime service** — which is what lets the SLO layer stay
  read-only and never load-bearing on the request path (spec requirement), and run on a
  clean checkout. Sloth v0.16.0 (Apr 2026), Apache-2.0, actively maintained; no hard
  rejects.
- **Considered**: *Pyrra* (Adopt) — same generation plus a runtime operator + web UI +
  budget API, rejected for now as an unneeded always-on failure surface while B/D are
  parked; fallback only if a budget UI becomes a hard requirement. *Hand-written PromQL*
  (Build) — rejected: self-writing the solved, error-prone MWMB math is the anti-pattern
  this gate prevents.
- **Isolation**: Sloth is a build-time codegen step, not a runtime dependency. Its input
  is the canonical objectives data file (Decision 4); its output is generated rule YAML
  committed/rendered into the `PrometheusRule` scaffold and the lab `rule_files:`.
  Prometheus (already present) evaluates the generated rules — nothing in nexus imports
  or calls Sloth at runtime, so the choice is fully reversible by regenerating or
  hand-forking the emitted rules.

## Risks / Trade-offs

- **[Recording `result` widens the hot-path record call slightly]** → attribute is a
  static low-card enum computed from an outcome already in hand; negligible cost,
  stays within the allow-list. Verify series count post-change.
- **[Deploy-time env enforcement could block a deploy that previously "worked"]** →
  intended: fail-closed is the point. Mitigate with a clear render/startup error naming
  the missing attribute, and document in the deploy runbook.
- **[Multi-window burn-rate rules are easy to get subtly wrong]** → the reason for
  Adopt over Build; use the established window/threshold pairs and cover them with the
  clean-checkout synthetic-burn scenario as an executable check.
- **[Counter-only planes still lack latency SLOs]** → accepted non-goal; they get
  rate/error SLOs from their existing labeled counters, latency SLOs only if a duration
  signal is added later.
- **[`deployment.environment.name` promoted to a hard dependency of the SLO layer]** →
  acceptable; it is already a promoted resource label, this change only guarantees its
  presence.

## Migration Plan

1. Add `result` to the two duration-histogram record sites; confirm the collector
   passes it and series stay within the allow-list.
2. Add deploy/startup admission for a valid `deployment.environment.name`
   (fail-closed), with a clear diagnostic; update the deploy runbook.
3. Land recording rules (budget + burn expressions) and fast/slow burn alerts on the
   `PrometheusRule` scaffold, keyed off an objectives data file; wire `rule_files:` into
   the lab Prometheus so a clean checkout evaluates them.
4. Verify: synthesize a fast-burn and a slow-burn locally; confirm page vs. ticket
   severities and that a brief spike does not page.
5. Rollback: rules are additive and default-off in prod — disabling the ruleset reverts
   with no producer change; the `result` attribute and env invariant are backward-safe.

## Open Questions

- Which exact window/threshold pairs and objective targets per service (availability,
  latency) — set in the objectives data file during apply, ratified with SRE input.
- Whether latency SLOs are in scope for both hot-path planes at launch or availability
  first, latency second.
- (Resolved via `/opsx:decide` — Adopt Sloth, see the Decision block above.)
- Pin the Sloth version and decide where generation runs (CI step vs. `make`-time) so
  generated rules are reproducible and reviewable in the diff.
