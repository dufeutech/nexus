## 1. Decide burn-rate treatment

- [x] 1.1 Run `/opsx:decide` on D3 (do the Sloth burn-rate alerts need an explicit floor?); record the outcome in `design.md`. **Decided (a)** — rely on MWMB dampening, no explicit floor; recorded in `design.md` (D3).
- [x] 1.2 Confirm the `*MinRps` default per objective (default 0.2 rps ≈ 60 req/5m); note any per-plane override in `design.md`. **Confirmed 0.2 uniform, no per-plane override** (recorded in `design.md`, D3 block).

## 2. Add the `*MinRps` threshold knobs

- [x] 2.1 `deploy/helm/edge-platform/values.yaml` (`monitoring.thresholds`, ~L305): add `edgeMinRps: 0.2`.
- [x] 2.2 `deploy/helm/identity-plane/values.yaml` (~L444): add `edgeMinRps: 0.2` and `enrichMinRps: 0.2`.
- [x] 2.3 `deploy/helm/routing-plane/values.yaml` (~L352): add `edgeMinRps: 0.2` and `routingMinRps: 0.2`.
- [x] 2.4 Keep `edgeMinRps` identical across all three charts (all three `edgeMinRps: 0.2`; rendered floors verified byte-identical in 6.2).

## 3. Add the floor to the hand-authored threshold alerts

- [x] 3.1 `edge-platform/templates/_monitoring.tpl` `NexusEdge5xxHigh`: appended `and sum(rate(envoy_http_downstream_rq_xx{envoy_http_conn_manager_prefix="edge"}[5m])) > {{ $t.edgeMinRps }}`.
- [x] 3.2 `edge-platform/templates/_monitoring.tpl` `NexusEdgeLatencyHigh`: appended `and sum(rate(envoy_http_downstream_rq_time_count{envoy_http_conn_manager_prefix="edge"}[5m])) > {{ $t.edgeMinRps }}`.
- [x] 3.3 `identity-plane/templates/_monitoring.tpl` `NexusIdentityEnrichLatencyHigh`: appended `and sum(rate(sidecar_ext_proc_duration_seconds_count[5m])) > {{ $t.enrichMinRps }}`.
- [x] 3.4 `routing-plane/templates/_monitoring.tpl` `NexusRoutingLatencyHigh`: appended `and sum(rate(router_ext_proc_duration_seconds_count[5m])) > {{ $t.routingMinRps }}` (drift-reconciliation with infra's local patch).
- [x] 3.5 Applied the SAME edge guards (3.1, 3.2) to the **duplicated** `nexus-edge.slo` copies in `identity-plane/templates/_monitoring.tpl` and `routing-plane/templates/_monitoring.tpl`.

## 4. Optional: burn-rate floor (only if 1.1 chose D3(c))

- [x] 4.1 N/A — D3 decided (a); no post-generate wrap. Skipped.
- [x] 4.2 N/A — SLO specs untouched, so no Sloth regeneration is needed. Skipped.

## 5. Optional follow-up: de-duplicate the edge alerts

- [ ] 5.1 (Deferred) Extract the `nexus-edge.slo` group into a single shared helper so it is authored once instead of triplicated. Out of scope for the floor itself; file as a separate change if pursued.

## 6. Validate + hand off

- [x] 6.1 `helm template` each of the three subcharts (operator + files form); every guarded `expr` renders with a balanced `and` and the correct `0.2` floor.
- [x] 6.2 Diffed the rendered `nexus-edge.slo` group across all three charts: the two edge `expr`s (incl. the floor) are **byte-identical** in all three. (The only cross-chart difference is the pre-existing `description` wording — "combined-edge" vs "edge" — which predates this change and is out of scope; the spec requires the *floor* to be identical, which holds.)
- [x] 6.3 `promtool check rules` (prom/prometheus:v2.53.0 via Docker) against all three rendered rule files: SUCCESS (2 + 9 + 6 rules); the guarded exprs parse.
- [x] 6.4 `/opsx:sync`ed the `service-slo-policy` delta into the main spec (all 37 specs validate) and `/opsx:archive`d the change.
- [ ] 6.5 **Hand-off (downstream, not this repo):** infra's `alert-noise-retune` change owns dropping the local `NexusRoutingLatencyHigh` patch in `files/nexus-rules/*.yml` and re-vendoring from this repo now that the upstream guards have landed.
