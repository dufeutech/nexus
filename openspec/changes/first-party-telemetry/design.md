# Design: first-party-telemetry

## Context

The box telemetry contract shipped (archived 2026-07-03): one OTLP collection
endpoint, Tempo/Prometheus/Loki behind it, two-way logs↔traces pivot in Grafana,
verified with a synthetic box. The six first-party Rust services predate it:

- **Logging** is `tracing` 0.1 + `tracing-subscriber` 0.3 (`json` + `env-filter`),
  initialized by a copy-pasted `init_tracing()` in each binary, honoring
  `RUST_LOG`/`LOG_FORMAT`. **No trace/span ids on any record.**
- **Metrics** are the `metrics` 0.24 facade + `metrics-exporter-prometheus` 0.18,
  scrape-exposed (tenant-router `:9302`, sidecar `:9202` with native-histogram
  protobuf exposition, control-plane `:9401`, sync-worker `:8080`,
  reconciler/membership-sync `:9000`). Good RED instrumentation already exists at
  the hot paths (`router_ext_proc_duration_seconds` + result counters;
  `sidecar_ext_proc_duration_seconds` + result counters; cache/feed gauges).
- **Tracing:** no OpenTelemetry anywhere in either workspace (confirmed in both
  lockfiles). The edge injects W3C `traceparent` toward the boxes, and it arrives
  in the ext_proc `RequestHeaders` both hot paths already iterate
  (`extract_host` in tenant-router, `find_header` in the sidecar) — **nothing
  reads it**, which is exactly the trace hole.

Workspaces: `routing-rs` (shared crate `router-core`) and `identity-rs` (shared
crate `identity_core`), edition 2024, tokio 1. `tracing`/`metrics` are currently
declared per-binary, not on the core crates.

## Goals / Non-Goals

**Goals:**

- Close the trace hole: routing-resolution and identity-enrichment spans inside the
  edge-rooted trace; edge's head decision respected (no export for not-sampled).
- Trace-correlated logs from all six services, landing in the contract's log path.
- First-party metrics reach the contract path with **name continuity** (existing
  dashboards keep working); scrape retires only after verified parity.
- One shared telemetry-init per workspace core crate; per-binary wiring is thin.
- Fail-open hot path: telemetry can never add latency or a failure mode to ext_proc
  processing (bounded buffers, shed-don't-block, no panic on init failure).
- `RUST_LOG`/`LOG_FORMAT` semantics unchanged; the only new knob is the contract's
  standard endpoint env var (unset ⇒ telemetry export off, service runs as today).

**Non-Goals (successor / explicitly out):**

- SLO targets, burn-rate alerts, keep-policy, retention economics — Change C.
- Envoy/edge changes (the edge already does its half; none expected).
- Deep span trees inside the services (one span per processing stage is the
  baseline; finer spans are future work if investigations demand them).
- Replacing container stdout logging (the fmt layer stays for `docker logs`).

## Architecture

```
 six binaries (thin wiring: one telemetry::init(cfg) call in main)
      │
      ▼
 core crates: router-core::telemetry / identity_core::telemetry   ← the ONE place
      │  subscriber stack = EnvFilter (RUST_LOG)                    that knows how
      │                   + fmt layer (LOG_FORMAT json|plain, stdout, as today)     telemetry is
      │                   + trace bridge layer (spans → OTLP traces)                assembled
      │                   + log appender     (events → OTLP logs, trace_id stamped)
      │  + meter provider (instruments → OTLP metrics, existing metric names)
      │  + resource identity: service.name / service.version (crate version) /
      │    deployment.environment.name (env)
      ▼
 OTEL_EXPORTER_OTLP_ENDPOINT ──► OTel Collector (shipped) ──► Tempo / Prometheus / Loki
 (unset ⇒ no-op providers; scrape endpoints keep serving during migration)
```

Dependency direction stays inward-only: binaries → core telemetry module → OTel
SDK/exporter (the adapter boundary). No service knows a store; hot-path code gains
one `traceparent` read + span around the existing `handle()` stage, nothing else.

ext_proc continuation detail: both hot paths receive the same edge-injected
`traceparent`, so their spans become **siblings under the edge span**, ordered by
time — acceptable and honest (Envoy doesn't re-inject between ext_proc filters);
verified at apply.

## Decisions

<!-- Critical concerns from the proposal; final call is /opsx:decide. Each carries
     a research-grounded recommendation so the gate is fast. -->

### Decision: Rust trace-context propagation + span SDK — PENDING /opsx:decide

- **Recommendation (Adopt):** the OpenTelemetry Rust stack (`opentelemetry`,
  `opentelemetry_sdk`, OTLP exporter) with the `tracing-opentelemetry` bridge, so
  spans are authored with the `tracing` macros the codebase already uses and W3C
  context extraction/propagation is library code, never hand-rolled.
- **Considered:** raw OTel API without the bridge (loses the existing `tracing`
  idiom and the free log correlation); hand-parsing `traceparent` (correctness
  defect by policy).

### Decision: log↔trace correlation bridge — PENDING /opsx:decide

- **Recommendation (Adopt):** the OTel log appender for `tracing`
  (`opentelemetry-appender-tracing`): events flow to the contract's OTLP logs
  pipeline with active trace/span ids attached from context; the existing stdout
  fmt layer stays for container-local debugging. No custom JSON schema invented.
- **Considered:** stamping trace_id into the stdout JSON and scraping it (bypasses
  the contract's push path — rejected by the shipped design); custom fmt layer
  (build where adopt exists).

### Decision: metrics emission path — PENDING /opsx:decide

- **Recommendation (Adopt + migrate call sites):** move the ~20 instrument call
  sites from the `metrics` facade to the OTel meter API in the core crates,
  keeping **the exact metric names** (`router_ext_proc_duration_seconds`,
  `sidecar_ext_proc_duration_seconds`, counters/gauges) so dashboard queries
  survive; the sidecar's exponential native histogram maps to OTel exponential
  histograms (Prometheus's OTLP receiver converts them to native histograms — the
  `native-histograms` feature is already on). Scrape exposition runs in parallel
  until parity is verified, then retires.
- **Considered:** a `metrics`-facade→OTel recorder bridge (immature ecosystem —
  re-check at decide time; would win if mature since it's zero call-site churn);
  keeping scrape permanently for first-party (leaves the two-worlds split the
  contract set out to end); collector-side prometheus scraping (receiver is not in
  the core collector distribution; violates the push-generic story).

### Decision: hot-path export isolation — PENDING /opsx:decide

- **Recommendation (Adopt, config-level):** batch span/log processors with bounded
  queues and short export timeouts (drop-on-full, never block), providers built as
  no-ops when the endpoint env is unset, init failures log-and-continue. This is
  exporter configuration of the adopted SDK, not custom machinery.
- **Considered:** synchronous/simple exporters (block the hot path — rejected);
  custom buffering layer (build where the SDK already provides it).

## Risks / Trade-offs

- [OpenTelemetry-Rust API churn (pre-1.0 SDK surface)] → pin one workspace-level
  version set; ALL OTel types stay inside the two core telemetry modules
  (adapter), so a version bump is a two-file change.
- [Twin telemetry modules in two workspaces drift] → same trade-off the codebase
  already accepts for `init_tracing()`; the twins carry a header comment pointing
  at each other, and the delta spec's scenarios test behavior, not code identity.
- [Metric rename breakage despite name-keeping (OTLP translation suffixes/labels)]
  → parity task compares dashboard queries against both paths in the lab BEFORE
  any scrape job or ServiceMonitor is removed (spec: verified, not assumed).
- [Hot-path overhead from span creation per ext_proc message] → measure with the
  existing `*_ext_proc_duration_seconds` histograms before/after in the lab; the
  budget is no visible p99 shift; not-sampled requests must skip span export
  entirely (parent-based decision).
- [Log volume doubles temporarily (stdout + OTLP)] → acceptable in the lab;
  production topologies choose via the existing `LOG_FORMAT` and the new endpoint
  var; a "fmt off" knob is future work if volume bites.
- [Background services rooting a trace per pass could spam Tempo] → passes are
  infrequent (30–600s intervals); acceptable; revisit under Change C keep-policy.

## Migration Plan

1. **Phase A (additive):** telemetry modules + per-binary init + ext_proc span
   continuation + OTLP logs. Scrape metrics untouched. Verify trace hole closed,
   log pivot, sampling respect, fail-open under load in the lab.
2. **Phase B (parallel metrics):** OTel instruments emit push metrics beside the
   scrape exposition; verify dashboard-query parity on the push path.
3. **Phase C (retire, gated on B's verification):** remove first-party scrape jobs
   from `monitoring/prometheus/prometheus.yml` and the helm ServiceMonitors;
   update docs (`deploy/README.md`, ownership row in
   `nexus-upstream-requirements.md`).
4. **Rollback:** unset the endpoint env (providers no-op) or revert Phase C config
   — the scrape path is intact until C, and C is config-only.

## Open Questions

- Does the `metrics`-facade→OTel bridge ecosystem clear the maturity bar at decide
  time? (If yes, Phase B becomes a recorder swap instead of call-site migration.)
- Are the two hot-path spans as siblings under the edge span acceptable to
  operators, or is nesting (router → sidecar) worth synthesizing? (Lean siblings —
  it reflects reality.)
- Sampling for background-service self-rooted traces: always-on (low volume) or
  ratio? (Lean always-on until Change C.)
