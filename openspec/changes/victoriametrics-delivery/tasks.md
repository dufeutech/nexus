## 1. Build-vs-adopt gate

- [ ] 1.1 Run `/opsx:decide` for the metrics-backend concern; record the
  VictoriaMetrics adoption (store + standalone rule evaluator) and the rejected
  alternatives into `design.md`.
- [ ] 1.2 Resolve the `monitoring.delivery` default open question and record it in
  `design.md` (operator vs otlp-only).

## 2. Single-source rendering (the rendering adapter)

- [ ] 2.1 Extend `monitoring/slo/generate.sh` to emit the operator-independent
  rule-file form (plain rule YAML) from the same Sloth `*.slo.yaml` source, in
  addition to the existing controller-form outputs.
- [ ] 2.2 Add a portability guard to the generator/CI that rejects any rendered
  query using a non-portable (backend-proprietary) function, keeping content to the
  portable PromQL subset.
- [ ] 2.3 Add a CI check asserting `generate.sh` is deterministic — regeneration
  leaves a clean git diff (no hand-edited delivery forms).

## 3. Chart delivery selector + operator-independent templates

- [ ] 3.1 Add a `monitoring.delivery` selector (`operator | files | otlp-only`) to
  `deploy/helm/{identity-plane,routing-plane,edge-platform}` values, defaulting per
  task 1.2; document it in each chart's values.
- [ ] 3.2 Add operator-independent rule-file ConfigMap templates (rendered SLO
  rules) gated by `delivery == files`, alongside the retained `PrometheusRule`
  templates (gated by `delivery == operator`).
- [ ] 3.3 Add file-provider dashboard ConfigMap templates gated by
  `delivery == files`, alongside the retained sidecar-labelled dashboard
  ConfigMaps (`delivery == operator`).
- [ ] 3.4 Ensure `otlp-only` renders neither rule nor dashboard artifacts (metrics
  path only), and that no delivery form is required — selection is pure config.
- [ ] 3.5 Extend the CI helm lint/template matrix to render each chart under all
  three `monitoring.delivery` values and assert the expected artifacts appear.

## 4. Lab reference stack → production backend family

- [ ] 4.1 Replace the `prometheus` service in root `docker-compose.yaml` with a
  single-node VictoriaMetrics service (lean resource limits); remove the
  Prometheus-specific config.
- [ ] 4.2 Add a standalone rule-evaluator service loading the operator-independent
  rendered rule-files (task 2.1); wire its alert output to a minimal local target
  sufficient to observe firing.
- [ ] 4.3 Retarget `monitoring/otel-collector/otel-collector.yaml` metrics exporter
  from the Prometheus endpoint to VictoriaMetrics ingestion; keep the cardinality
  allow-list; pin metric temporality to cumulative.
- [ ] 4.4 Collect the Envoy admin `/stats/prometheus` target into VictoriaMetrics
  via the collector's scrape input (keep the lab operator-less).
- [ ] 4.5 Repoint the Grafana datasource to VictoriaMetrics, kept as a
  Prometheus-typed datasource so datasource-templated dashboards still bind; load
  dashboards via the file provider (operator-independent form).

## 5. Verification

- [ ] 5.1 Bring up the reference stack from a clean checkout; confirm the
  operator-independent rules load and evaluate and dashboards are available
  (spec: local reference exercises the production delivery form).
- [ ] 5.2 Synthesize a burn condition and confirm the corresponding alert fires
  through the operator-independent form, with no cloud dependency.
- [ ] 5.3 Render the charts under `delivery == operator` and confirm the
  controller-based artifacts are unchanged from today (portability preserved).
- [ ] 5.4 Confirm no first-party service or `/metrics`/OTLP exposition behavior
  changed (diff shows no Rust/service edits; exposition contract intact).
- [ ] 5.5 Confirm the same rendered rules evaluate equivalently against a Prometheus
  and a VictoriaMetrics backend over the same input series (portable-query check).
