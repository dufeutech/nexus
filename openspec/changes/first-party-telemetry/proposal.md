# Proposal: first-party-telemetry

## Why

The box telemetry contract shipped (archived 2026-07-03) and any off-the-shelf box now
complies with one env var — which makes nexus's OWN Rust services the only
non-compliant workloads on the internal network. Today an edge-rooted trace shows the
edge's spans and a compliant box's spans with a hole in the middle where the
tenant-router and identity-sidecar hot paths did the actual work; their logs carry no
trace identifiers, so the logs↔traces pivot dead-ends exactly where an operator
investigating a routing or enrichment failure needs it; and their metrics live in a
separate scrape-based world from the contract's push path. This is Change B recorded
in the archived `box-telemetry-contract` roadmap — the natural successor now that the
plumbing exists, and the prerequisite for Change C (SLO/burn-rate policy needs the
first-party RED baseline to be contract-shaped).

## What Changes

- **The six first-party Rust services become compliant boxes** under the existing
  `box-telemetry-contract`: tenant-router, control-plane (routing plane); identity
  sidecar, sync-worker, reconciler, membership-sync (identity plane). Compliance means
  the same four things it means for any box: standard resource identity on every
  signal, continued edge-rooted traces, trace-correlated structured logs, RED metrics
  as aggregatable distributions — all emitted to the one collection endpoint.
- **The trace hole closes:** the ext_proc hot-path services (tenant-router, identity
  sidecar) continue the edge's trace context and record internal spans for their
  processing stages, so one trace shows edge → routing decision → enrichment →
  backend, and their log records during a traced request pivot both ways by trace ID.
- **The off-request services** (sync-worker, reconciler, membership-sync,
  control-plane admin API) join for identity + correlated logs + their existing
  operational metrics; they root their own traces for background work (no edge trace
  to continue).
- **The two metrics worlds converge:** first-party metrics move to the contract's push
  path. Existing scrape endpoints and the Grafana dashboard keep working during the
  migration; the retirement of per-service scrape jobs is the exit criterion, not the
  entry step. Metric continuity (names/queries that dashboards rely on) is an explicit
  design concern, not an accident.
- **Hot-path guardrail (non-negotiable):** telemetry emission must not add measurable
  latency or a new failure mode to the ext_proc request path — the fail-open property
  the contract promises boxes applies doubly to the services that sit inside every
  request.
- **Docs:** deploy README observability guidance (first-party knobs), the
  "coexistence" note in `nexus-upstream-requirements.md` ownership table updated when
  scrape jobs retire.

## Capabilities

### New Capabilities

- `first-party-telemetry`: the observable guarantee that nexus's own planes are
  contract-compliant boxes — their spans appear inside the edge-rooted trace (no
  first-party hole between edge and backend), their logs carry trace identifiers,
  their RED/operational metrics are queryable through the contract path with one
  identity per service, and telemetry never affects request handling or resolution
  latency. Critical concerns for the build-vs-adopt gate (tool choice deferred to
  `/opsx:decide`): **Rust trace-context propagation + span SDK** (correctness-critical
  — hand-rolling W3C context or span lifecycle is a defect), **log↔trace correlation
  bridge** (the mechanism that stamps active trace/span ids onto structured log
  records), **metrics emission path** (push pipeline vs existing exposition — a
  reliability-sensitive migration with dashboard continuity at stake), and
  **hot-path export isolation** (buffering/batching so a slow collector can never
  back-pressure an ext_proc response).

### Modified Capabilities

<!-- none: box-telemetry-contract already states what ANY compliant box emits; this
     change makes the first-party services instances of it rather than widening it.
     edge-request-tracing stays as-is — the edge's rooting/stripping behavior is
     unchanged; ext_proc trace continuation is the new capability's requirement. -->

## Impact

- **Code:** `routing-rs` (tenant-router, control-plane) and `identity-rs` (sidecar,
  sync-worker, reconciler, membership-sync) workspaces — telemetry initialization in
  each binary's entry point, span instrumentation in the two ext_proc hot paths, new
  shared telemetry setup in each workspace's core crate (behavior once, thin per-binary
  wiring). New workspace dependencies (the decide gate picks them).
- **Config surface:** each service gains the contract's standard endpoint env var;
  compose (lab + deploy) and helm values pass the collector address; existing
  `RUST_LOG`/`LOG_FORMAT` conventions stay.
- **Monitoring stack:** no collector/store changes expected (the pipelines shipped);
  `monitoring/prometheus/prometheus.yml` scrape jobs retire at the end of the
  migration; `monitoring/grafana/dashboards/identity-plane.json` queries reviewed for
  metric-name continuity.
- **No tenant/end-user behavior change;** request handling untouched (fail-open
  everywhere). No edge/Envoy config change expected.
