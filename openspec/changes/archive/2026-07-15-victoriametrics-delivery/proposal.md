## Why

Nexus's first real deployment target (`infra-v1`) runs a deliberately lean,
**operator-less** VictoriaMetrics stack — no Prometheus Operator and no
VictoriaMetrics Operator. Nexus's telemetry **data path** already works there:
services push OTLP to a collector and know no store address (the ratified
`box-telemetry-contract`). But nexus's **SLO alert rules and Grafana dashboards**
are packaged only as Prometheus-Operator CRDs (`PrometheusRule`, `PodMonitor`,
sidecar-labelled dashboard ConfigMaps). On any cluster without that operator those
CRDs render to **silent no-ops** — so on the first real infrastructure nexus would
ship with its SLO alerting and dashboards dark. We need monitoring artifacts that
deliver to an operator-less PromQL backend **without** giving up portability to
operator-based clusters, plus a local lab that dogfoods the same backend family.

## What Changes

- Introduce a **backend- and operator-neutral delivery path** for nexus's
  monitoring artifacts (SLO burn-rate rules + Grafana dashboards): an
  operator-independent form (plain rule-file and dashboard ConfigMaps, consumable
  by a standalone rule evaluator and a file-provisioned Grafana) selectable
  **alongside** the existing Prometheus-Operator CRD form. No single delivery form
  is the sole path; selecting one is configuration.
- Keep a **single SLO source of truth** (the Sloth objective specs). Additional
  delivery forms are *renderings* of that source, never hand-copied duplicates.
- Constrain rule and dashboard **query content to portable PromQL**, so artifacts
  evaluate unchanged on any PromQL-compatible backend (Prometheus or
  VictoriaMetrics) — no backend-only query extension may be required.
- Swap the local **reference stack's** metrics backend to the production backend
  family (VictoriaMetrics + a rule evaluator), retargeting the collector's metrics
  exporter and Grafana's (Prometheus-typed) datasource, so a clean checkout
  exercises SLO burn on the same backend as production.
- **No first-party service code changes.** The OTLP exposition contract is
  unchanged; VictoriaMetrics never appears in service code. Not breaking for any
  consumer of the exposition contract.

## Capabilities

### New Capabilities
- `portable-monitoring-delivery`: monitoring artifacts (SLO rules and dashboards)
  derive from one source of truth, can be delivered to both operator-based and
  operator-less PromQL backends, restrict their query content to portable PromQL,
  and treat backend/delivery selection as pure configuration that changes no
  telemetry producer.

### Modified Capabilities
<!-- None. box-telemetry-contract and first-party-telemetry (exposition) and
     service-slo-policy (objective/burn semantics) keep their existing
     requirements; this change adds a delivery concern rather than altering how
     telemetry is exposed or how SLOs are defined/evaluated. The new capability
     cross-references service-slo-policy's local-exercisability requirement. -->

## Impact

- **Helm charts** — `deploy/helm/{identity-plane,routing-plane,edge-platform}`:
  add operator-less rule-file + dashboard ConfigMap templates behind a delivery
  selector value; retain the existing `PrometheusRule`/`PodMonitor`/dashboard
  templates for operator clusters.
- **SLO generator** — `monitoring/slo/*.slo.yaml` + `monitoring/slo/generate.sh`:
  emit the additional operator-less rule-file rendering from the same source.
- **Lab reference stack** — root `docker-compose.yaml` (metrics backend swap +
  rule evaluator), `monitoring/otel-collector/otel-collector.yaml` (metrics
  exporter retarget), Grafana datasource + rules directory.
- **No Rust / service changes.** OTLP exposition and SLO semantics untouched.
- **Out of scope:** `infra-v1`-side wiring (vmagent scrape job for Envoy
  `/stats/prometheus`, placing nexus rule-files/dashboards into infra-v1's
  `files/`) — a separate change in the `infra-v1` repo.
- **Build-vs-adopt:** adopting VictoriaMetrics (mature TSDB, lean footprint) as
  the metrics backend is the critical concern to record at `/opsx:decide`.
