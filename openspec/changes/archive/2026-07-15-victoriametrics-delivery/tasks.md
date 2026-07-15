## 1. Build-vs-adopt gate

- [x] 1.1 Run `/opsx:decide` for the metrics-backend concern; record the
  VictoriaMetrics adoption (store + standalone rule evaluator) and the rejected
  alternatives into `design.md`. (Also recorded: Adopt promtool for rule
  correctness/portability validation.)
- [x] 1.2 Resolve the `monitoring.delivery` default open question and record it in
  `design.md` (resolved: default `files`; backward-compat not required, so the three
  legacy toggles collapse into the one selector).

## 2. Single-source rendering (the rendering adapter)

- [x] 2.1 The operator-independent rule-file form reuses the SAME Sloth output
  `generate.sh` already produces (`monitoring/prometheus/rules/*` + staged
  `files/slo/*`); the files-form ConfigMap renders it, and the hand-authored threshold
  alerts are single-sourced via each chart's `_monitoring.tpl` `appSloGroups` helper —
  so no new generation step was needed, only a new rendering.
- [x] 2.2 Portability guard: `monitoring/slo/check.sh` runs `promtool check rules` (valid
  portable PromQL — a VM-only MetricsQL construct fails the parse) + `promtool test
  rules`; wired into the CI `monitoring-delivery` job.
- [x] 2.3 CI (`monitoring-delivery` job) regenerates via `generate.sh` and
  `git diff --exit-code`s the rules dir + chart staging (single-source determinism).

## 3. Chart delivery selector + operator-independent templates

- [x] 3.1 `monitoring.delivery` selector (`otlp-only | files | operator`, default
  `files`) added to `identity-plane`, `routing-plane`, `edge-platform`; the three legacy
  toggles removed; documented in each chart's values + `deploy/README.md`.
- [x] 3.2 Operator-independent rule-file ConfigMap (`monitoring-rules-files.yaml`,
  `delivery == files`) added; existing `PrometheusRule` templates re-gated to
  `delivery == operator`, both rendering the shared `appSloGroups` helper.
- [x] 3.3 File-provider dashboard ConfigMaps (`monitoring-dashboards-files.yaml`,
  `delivery == files`) added alongside the retained sidecar dashboard ConfigMaps
  (`delivery == operator`).
- [x] 3.4 `otlp-only` renders neither rules nor dashboards (verified: 0 monitoring
  artifacts); selection is pure config, no form mandatory.
- [x] 3.5 CI renders every chart under all three `monitoring.delivery` values
  (`monitoring-delivery` job) + operator-form render in the helm-lint job.

## 4. Lab reference stack → production backend family

- [x] 4.1 Replaced the `prometheus` service in `docker-compose.yaml` with single-node
  `victoria-metrics` (lean limits, 30d retention); removed `prometheus.yml`.
- [x] 4.2 Added the standalone `vmalert` service loading the operator-independent rule
  files, notifier blackholed (firing observable via `/api/v1/alerts` + `ALERTS`).
- [x] 4.3 Retargeted the collector metrics exporter to VictoriaMetrics OTLP ingestion;
  kept the cardinality allow-list (push pipeline only).
- [x] 4.4 Envoy admin `/stats/prometheus` (+ collector self + Loki) folded into VM via a
  collector `prometheus` receiver on a SEPARATE `metrics/scrape` pipeline (no cardinality
  collapse, so Envoy edge labels survive) — lab stays operator-less.
- [x] 4.5 Repointed the Grafana datasource to VictoriaMetrics (kept Prometheus-typed so
  templated dashboards bind); lab already loads dashboards via a file provider.

## 5. Verification

- [x] 5.1 Booted VictoriaMetrics + vmalert from a clean checkout: vmalert loaded all 12
  rule groups (68 rules) from the file mount and evaluated them against VM with 0 errors
  — the operator-independent form works at runtime with no operator.
- [x] 5.2 Burn condition raises its alert: `promtool test rules` (the
  `tests/*.slo_test.yaml` synthetic-burn suite) passes — page + ticket alerts fire for
  the burning environment only, no cloud dependency.
- [x] 5.3 `monitoring.delivery=operator` renders the controller-based artifacts
  (PrometheusRule ×N + PodMonitor + sidecar dashboards) unchanged from today.
- [x] 5.4 No first-party service / exposition change: the diff touches only charts,
  compose, `monitoring/`, docs, and CI — no Rust edits; OTLP contract intact.
- [x] 5.5 Same rendered rules validate under promtool (Prometheus's PromQL engine) AND
  evaluate cleanly at runtime on VictoriaMetrics — portable-query check.
