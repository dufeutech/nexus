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

ext_proc continuation detail (**corrected at apply, verified in the lab**): the edge
injects `traceparent` into the request headers toward the **backend**, which is
*after* the ext_proc filters run — so the tenant-router / sidecar do NOT see it in
the ext_proc `RequestHeaders` payload. Envoy does, however, trace the ext_proc gRPC
call itself (the `async ExternalProcessor.Process egress` span) and propagates that
context as **gRPC call metadata**. So the correct continuation source is the tonic
`Request` metadata (one ext_proc stream per HTTP request ⇒ per-request context), not
the HTTP header payload. The router/sidecar spans then parent under the edge's
ext_proc egress span — closing the hole. (First implementation read the payload and
produced separate root traces; the metadata read fixes it.)

## Decisions

<!-- Resolved via /opsx:decide 2026-07-05; options researched against current
     (July 2026) crate state. opentelemetry-rust is pre-1.0 (SDK 0.30, appender
     0.31) but the traces/logs specs are stable and the metrics-SDK graduated to
     stable at 0.30 — the churn is contained by the adapter boundary below. -->

### Decision: Rust trace-context propagation + span SDK — Adopt opentelemetry-rust + tracing-opentelemetry

- **Status**: approved
- **Why**: W3C context extraction/propagation and span lifecycle are library code,
  never hand-rolled (hand-parsing `traceparent` is a correctness defect by policy);
  the `tracing-opentelemetry` bridge lets spans be authored with the `tracing`
  macros the codebase already uses everywhere.
- **Considered**: raw OTel tracing API without the bridge (loses the existing
  `tracing` idiom and the free log correlation for no gain); hand-parsed W3C
  context (rejected — correctness-critical build).
- **Isolation**: `opentelemetry` + `opentelemetry_sdk` + `opentelemetry-otlp` and
  all OTel types live only inside `router-core::telemetry` / `identity_core::telemetry`;
  a pre-1.0 version bump is a two-file change.

### Decision: log↔trace correlation bridge — Adopt opentelemetry-appender-tracing

- **Status**: approved
- **Why**: the appender routes `tracing` events into the contract's OTLP logs
  pipeline with the active trace/span ids attached from context (v0.31 attaches
  TraceId/SpanId/TraceFlags automatically) — no custom JSON schema invented; the
  existing stdout fmt layer stays for `docker logs` debugging.
- **Considered**: stamping trace_id into stdout JSON and scraping it (bypasses the
  contract's push path — rejected by the shipped `box-telemetry-contract` design);
  a custom fmt correlation layer (build where adopt exists).
- **Isolation**: a subscriber layer assembled inside the core telemetry module,
  behind the same adapter boundary as the tracer.

### Decision: metrics emission path — Adopt OTel meter, migrate call sites (no metrics-facade bridge)

- **Status**: approved
- **Why**: moving the ~20 instrument call sites from the `metrics` facade to the
  OTel meter API keeps the whole telemetry surface on ONE pinned opentelemetry-rust
  version, rather than adding a second, less-maintained dependency on the metrics
  path. Exact metric names are preserved (`router_ext_proc_duration_seconds`,
  `sidecar_ext_proc_duration_seconds`, counters/gauges) so dashboard queries
  survive; the sidecar's exponential histogram maps losslessly to an OTel
  exponential histogram, which Prometheus's OTLP receiver converts to a native
  histogram (feature already on). Scrape exposition runs in parallel until parity
  is verified, then retires.
- **Considered**: the `metrics`→OTel recorder bridge `metrics-exporter-opentelemetry`
  (near-zero call-site churn, but ~12k downloads / single maintainer / competes
  with two other half-baked crates — a fragile second version-coupling point on
  the metrics path); keeping scrape permanently for first-party (leaves the
  two-worlds split the contract set out to end); collector-side Prometheus scraping
  (receiver not in the core collector distribution; violates the push-generic story).
- **Isolation**: instruments are created and held by the core telemetry module's
  meter; call sites reference them, no OTel meter types leak into business logic.

### Decision: hot-path export isolation — Adopt SDK batch processors (config-level)

- **Status**: approved
- **Why**: batch span/log processors with bounded queues, short export timeouts,
  and drop-on-full are exporter *configuration* of the adopted SDK — not custom
  machinery — and give the fail-open, never-block guarantee the ext_proc path
  requires; providers build as no-ops when the endpoint env is unset, and init
  failures log-and-continue.
- **Considered**: synchronous/simple exporters (block the hot path — rejected); a
  hand-written buffering layer (build where the SDK already provides it).
- **Isolation**: processor/exporter construction is confined to the core telemetry
  module's `init`; the hot path only opens spans and records instruments.

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

- ~~Does the `metrics`-facade→OTel bridge clear the maturity bar?~~ **Resolved
  (/opsx:decide 2026-07-05):** no — the bridge is a single-maintainer ~12k-download
  crate; Phase B is a call-site migration to the OTel meter, keeping the whole
  surface on one pinned OTel version.
- Are the two hot-path spans as siblings under the edge span acceptable to
  operators, or is nesting (router → sidecar) worth synthesizing? (Lean siblings —
  it reflects reality.)
- Sampling for background-service self-rooted traces: always-on (low volume) or
  ratio? (Lean always-on until Change C.)
