## Why

The hand-authored threshold SLO alerts fire on statistically insignificant traffic: a ratio or a rate-based p99 computed over a near-idle service turns a handful of requests into a "40% error rate" or "the p99 is the one cold-path request." Downstream (the infra fleet that vendors these rules) this has already latched alerts firing on an idle, pre-public-cutover edge — and a local band-aid was applied *in the vendored copy* of `NexusRoutingLatencyHigh` that this repo's `generate.sh` would silently revert on the next re-vendor. The guard has to live here, at the source of truth, so it survives regeneration and protects every consumer.

## What Changes

- **Add a minimum-sample (traffic-volume) floor to the hand-authored threshold alerts** that are ratio- or quantile-over-rate based, so they cannot fire below a configured request rate:
  - `NexusEdge5xxHigh` — floor on the in-expr denominator (total edge responses).
  - `NexusEdgeLatencyHigh` — floor on `envoy_http_downstream_rq_time_count{...edge}`.
  - `NexusIdentityEnrichLatencyHigh` — floor on `sidecar_ext_proc_duration_seconds_count`.
  - `NexusRoutingLatencyHigh` — floor on `router_ext_proc_duration_seconds_count`. **This reconciles the drift**: infra's vendored copy already carries this guard locally; adding it upstream makes the vendored copy re-vendorable again without loss.
- **Introduce a per-threshold `*MinRps` knob** under `.Values.monitoring.thresholds` (each of the three subcharts) so the floor is a single-sourced, tunable value, not a magic literal.
- **Handle the edge-alert duplication:** `NexusEdge5xxHigh` / `NexusEdgeLatencyHigh` are emitted in all three `_monitoring.tpl` helpers (edge-platform, identity-plane, routing-plane) behind `{{- if .Values.edge.enabled }}`. The guard must be applied to every copy (or the duplication removed) so the rendered rule is identical wherever it comes from.
- **Decide the burn-rate SLI treatment:** the Sloth multi-window burn-rate alerts (identity + routing, availability + latency) are error/total ratios with no sample floor, but the MWMB short-AND-long-window logic already dampens single-sample spikes. Decide whether they need an explicit floor at all, and if so, the mechanism — this is a `/opsx:decide` point, not a foregone edit.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `service-slo-policy`: add a **minimum-sample-volume** requirement — an alert derived from a ratio or a rate-based quantile MUST NOT fire when the underlying request volume over its window is too low to be statistically meaningful. This is a new normative property layered onto the existing burn-rate and threshold alerting behavior; it does not change the objectives or the outcome-attributed-traffic requirement.

## Impact

- **Rules (behavior):**
  - `deploy/helm/edge-platform/templates/_monitoring.tpl` (`edgeSloGroups`, L13+), `deploy/helm/identity-plane/templates/_monitoring.tpl` (`appSloGroups`, L13+), `deploy/helm/routing-plane/templates/_monitoring.tpl` (`appSloGroups`, L13+) — add the `and sum(rate(<count>[5m])) > {{ $t.<x>MinRps }}` floor.
  - `deploy/helm/{edge-platform,identity-plane,routing-plane}/values.yaml` (`monitoring.thresholds`, ~L305/352/444) — add the `*MinRps` defaults.
  - `monitoring/slo/{identity-sidecar,tenant-router}.slo.yaml` — only if the decide step says the burn-rate SLIs need a floor; then regenerate.
- **Regeneration:** `./monitoring/slo/generate.sh` (Docker + Sloth v0.16.0) re-renders `monitoring/prometheus/rules/*.rules.yaml` and stages into `deploy/helm/*/files/slo/`. Only needed if the SLO specs change.
- **Downstream:** the infra repo re-vendors these rules (its `files/nexus-rules/*.yml`). After this lands, infra drops its local `NexusRoutingLatencyHigh` patch and re-vendors — see the infra-side change `alert-noise-retune`.
- **No breaking changes**, no new runtime dependencies, no metric/telemetry changes (all count series already emitted).
