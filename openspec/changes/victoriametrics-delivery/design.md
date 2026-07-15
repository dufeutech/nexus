## Context

Nexus telemetry already flows through a store-agnostic seam: services push OTLP to
a collector, and no producer knows a store address (`box-telemetry-contract`,
`first-party-telemetry`). The metrics/traces/logs **data path** therefore already
works on the first production target, `infra-v1`, whose collector fans out to a
lean, **operator-less** VictoriaMetrics / VictoriaLogs / Tempo stack (hand-rolled
static manifests; no Prometheus or VictoriaMetrics Operator, ~50m CPU / 128Mi per
obs pod, obs is `platform-low` / first-evicted).

What does **not** work there is nexus's monitoring **artifacts**. The SLO
burn-rate rules and Grafana dashboards are packaged only as Prometheus-Operator
custom resources (`PrometheusRule`, `PodMonitor`, sidecar-labelled dashboard
ConfigMaps), all default-off. With no operator present they render to silent
no-ops — nexus would ship its SLO alerting and dashboards dark on the first real
infra. The SLO content itself is already single-sourced from Sloth specs
(`monitoring/slo/*.slo.yaml` → `generate.sh` → Prometheus rules + Helm
`files/slo/*.rules.yaml`) and is plain PromQL, which VictoriaMetrics evaluates
unchanged.

## Goals / Non-Goals

**Goals:**
- Deliver SLO rules + dashboards to an operator-less PromQL backend **without**
  losing the operator-based path (portability preserved).
- Keep one SLO source of truth; new forms are renderings, not copies.
- Dogfood the production backend family in the local reference stack so a clean
  checkout exercises SLO burn on the same backend as production.
- Zero first-party service change; the OTLP exposition contract is untouched.

**Non-Goals:**
- No changes to Rust services, `/metrics` exposition, or SLO objective/burn
  semantics (`service-slo-policy` stays as-is).
- No `infra-v1`-side wiring (vmagent scrape job, dropping nexus files into
  infra-v1's `files/`) — separate change in that repo.
- No traces/logs backend change; only the metrics store + rule/dashboard delivery.

## Decisions

### Core vs adapters, dependency direction

The **core** is the SLO policy source (`monitoring/slo/*.slo.yaml`) plus the
existing store-agnostic telemetry contract. It knows nothing of any backend. Every
backend/packaging concern is an **outer adapter**; dependencies point inward only:

- **Rendering adapter** — `monitoring/slo/generate.sh`: one source → N delivery
  forms. Extended to emit the operator-independent form in addition to the
  existing controller form. The generator is the *only* place that knows the
  delivery forms; charts and lab consume its output.
- **Packaging adapters** — Helm templates: a `monitoring.delivery` selector
  (`operator | files | otlp-only`) chooses which rendered form is applied. The
  operator form (existing `PrometheusRule`/`PodMonitor`/sidecar ConfigMaps) is
  retained unchanged; the files form adds plain rule-file + file-provider
  dashboard ConfigMaps. No business logic in templates — pure selection.
- **Backend adapter** — the collector's metrics exporter + the lab backend
  container. Swapping the store is a change here only; it never reaches a producer.

Native-format content stays in native files loaded through adapters: rule-files
are YAML under `files/`, dashboards are JSON, both rendered/mounted — never inlined
as string literals.

### Build-vs-adopt decisions (recorded via /opsx:decide)

The critical concerns — the metrics store/rule-evaluator, and rule
correctness/portability validation — are settled below. Both are realized only in
adapters (lab container + collector exporter; a CI/generator step); the core stays
backend-neutral.

### Decision: Metrics store + rule evaluator — Adopt VictoriaMetrics (vmsingle + vmalert)

- **Status**: approved
- **Why**: PromQL-compatible so our rule/dashboard content ports unchanged; ~½ the
  RAM and up to 7× less disk than Prometheus; it is the exact stack infra-v1 runs,
  so the lab dogfoods production.
- **Considered**: keep Prometheus (heavier, and diverges from the production
  backend so the lab would not exercise it); managed TSDB / Rent (off-table — the
  fleet self-hosts with no cloud dependency and must stay locally exercisable).
- **Isolation**: enters only through the lab backend container and the collector's
  metrics-exporter config; never referenced by any first-party service.

### Decision: Rule correctness + portability validation — Adopt promtool

- **Status**: approved
- **Why**: `promtool check rules` + `test rules` unit-tests rules against synthetic
  series, and its PromQL parser doubles as the portability guard (valid PromQL ⇒
  portable; a backend-only MetricsQL construct fails the parse). No new heavy
  dependency; directly backs the "same rules evaluate on both backends"
  verification.
- **Considered**: also adopt Cloudflare `pint` for deeper PR-time linting (deferred
  — needs config + a live backend, more than needed now); hand-written regex guard
  (Build — brittle, reinvents a parser; rejected).
- **Isolation**: a CI/generator validation step; never runs at request time.

### The prior SLO source-of-truth stands

Rule content is still single-sourced from the already-adopted Sloth objective specs
(`monitoring/slo/*.slo.yaml`); this change adds a rendering of that source, not a
second author. No re-decision needed.

### Delivery-form selection default (resolved)

Backward compatibility is explicitly **not** required. `monitoring.delivery` is the
single selector (`otlp-only | files | operator`) and **defaults to `files`** — the
operator-less form that works on the first real target (infra-v1) and the
portable-by-default stance; defaulting to `operator` would ship dark no-op CRDs
there, which is the bug this change fixes. The three legacy toggles
(`metrics.serviceMonitor.enabled`, `metrics.prometheusRule.enabled`,
`dashboards.enabled`) are **collapsed into this one selector** — one knob, three
values. `operator` remains opt-in so operator clusters keep the CRD form (the spec
forbids any single form being mandatory).

### Lab reference stack

Swap the compose `prometheus` service for a single-node VictoriaMetrics plus a
standalone rule evaluator loading the rendered rule-files; retarget the collector's
metrics exporter to VM's ingestion; repoint Grafana's **Prometheus-typed**
datasource URL to VM (kept prometheus-type so datasource-templated dashboards
still bind). The one genuine scrape target (Envoy admin `/stats/prometheus`) is
collected into VM via the collector's scrape input, keeping the lab operator-less
and lean.

## Risks / Trade-offs

- **OTLP metrics ingestion parity** (VM vs Prometheus `/api/v1/otlp`): temporality
  and resource-attribute handling can differ → pin cumulative temporality, keep the
  collector cardinality allow-list, and validate the burn scenario end-to-end in the
  lab before relying on it.
- **Query-dialect drift** (someone writes a VM-only MetricsQL function) → breaks the
  portability requirement → add a generator/CI guard restricting rendered content to
  the portable PromQL subset; document the constraint.
- **Dual-delivery divergence** (two forms drift) → mitigated by single source +
  generator; add a CI check that regeneration leaves a clean diff (no hand edits).
- **Lab ≠ prod delivery shape** → lab uses the same operator-independent form
  (rule-files + file-provider dashboards) and same backend family as infra-v1, so
  the lab genuinely exercises the production path.
- **Grafana datasource picker** filters dashboards to Prometheus-type datasources →
  keep VM registered as a prometheus-type datasource (not the VM-native plugin) so
  existing dashboards resolve.

## Migration Plan

1. Extend `generate.sh` to also render the operator-independent form; both forms
   produced from the one source (no deploy behavior change yet).
2. Add the `monitoring.delivery` selector + operator-independent templates to the
   three charts; operator form unchanged.
3. Swap the lab backend + retarget collector/datasource; verify the clean-checkout
   burn scenario fires through the operator-independent form.
4. **Rollback:** set `monitoring.delivery` back to `operator`/`otlp-only`; the lab
   swap is a self-contained compose revert. No producer or contract touched, so
   rollback is config-only.

## Open Questions

- Default value of `monitoring.delivery` — `operator` (backward-compatible for
  existing clusters) vs `otlp-only` (safest, artifacts stay off until chosen)?
- Does the lab need a minimal alert router to assert the burn scenario *fires*, or
  is asserting the rule evaluates/`ALERTS` series sufficient for the local test?
- Confirm the collector's scrape input for Envoy `/stats/prometheus` is the leanest
  option vs a tiny standalone agent in the lab.
