# Tasks: first-party-telemetry

<!-- Run /opsx:decide before 1.x — the four PENDING decisions in design.md pin the
     dependency set these tasks install. Phases match the design migration plan. -->

## 1. Shared telemetry modules (Phase A foundation)

- [x] 1.1 Add the decided telemetry dependency set (pinned, workspace-level) to
      `routing-rs` and `identity-rs`, on the core crates (`router-core`,
      `identity_core`) — today `tracing`/`metrics` are per-binary deps
      (pinned opentelemetry 0.32 / _sdk 0.32 / -otlp 0.32 grpc-tonic /
      -appender-tracing 0.32 / tracing-opentelemetry 0.33)
- [x] 1.2 Create `router-core::telemetry` and its twin `identity_core::telemetry`:
      one `init(service_name)` building EnvFilter (`RUST_LOG`/`LOG_LEVEL`) + fmt
      layer (`LOG_FORMAT` json/plain, unchanged semantics) + trace bridge + OTLP log
      appender + meter provider; resource identity (service.name, service.version
      from crate version, deployment.environment.name via OTEL_RESOURCE_ATTRIBUTES);
      endpoint from the standard OTLP env var, **unset ⇒ no-op providers**; bounded
      batch processors, drop-on-full, log-and-continue on init failure (twins
      cross-reference each other in a header comment). Both compile clean under the
      pedantic/nursery/cargo deny wall.
- [x] 1.3 Replace the six per-binary `init_tracing()` copies with the core helper
      (tenant-router, control-plane, sidecar, sync-worker, reconciler,
      membership-sync). `cargo check` green for all bar the sidecar (its pre-existing
      protobuf-exposition build needs `protoc`, present in its Docker image); boot +
      log-parity verified in the lab in task 4.x.

## 2. Hot-path trace continuation (Phase A)

- [x] 2.1 tenant-router: read `traceparent` from the ext_proc `RequestHeaders` it
      already iterates, continue the context, and wrap the `handle()` processing
      stage in a span (result/pool attributes within the hygiene set); not-sampled
      or absent context ⇒ no span export. Continuation goes through
      `router_core::telemetry::continue_trace` (OTel stays behind the adapter);
      `cargo check` green.
- [x] 2.2 identity sidecar: same continuation via the existing `find_header`, span
      around the enrichment stage (`enrich.result` attribute; no identity values in
      span attributes). Compiles in its Docker image (protoc present).
- [x] 2.3 Verified in the lab: ONE trace (`b316…`) contains `nexus-edge ingress` →
      `tenant-router router.resolve` → `identity-sidecar identity.enrich` → backend
      egress, correctly parented. KEY FIX: continuation reads the ext_proc **gRPC
      call metadata**, not the HTTP payload (the edge injects `traceparent` toward
      the backend, after ext_proc runs — see design.md). Before the fix router/
      sidecar spans were separate roots; after, they join the edge trace.
- [x] 2.4 Verified: hot-path logs carry `trace_id`+`span_id` in Loki structured
      metadata; log→trace resolves the router log's trace_id to the joined edge
      trace, and trace→logs (`| trace_id = …`) returns both the router "route" and
      sidecar "enrich" records — the two-way pivot, provisioned in Grafana.

## 3. Background services (Phase A)

- [x] 3.1 sync-worker (webhook span), reconciler (`reconcile.pass` span),
      membership-sync (`membership.backstop` + per-signal spans), control-plane
      (per-request `TraceLayer` at INFO): each roots its own trace, logs correlate.
      `cargo check` green for all four. Grafana verification folded into task 4.x.

## 4. Fail-open + overhead verification (Phase A gate)

- [x] 4.1 Verified fail-open under load: collector stopped, 40/40 edge requests
      returned 200 at stable latency (p99 13ms end-to-end, max 18ms); the only
      "errors" were the OTLP SDK's own BatchProcessor.ExportError (the fail-open
      mechanism, not request errors); telemetry resumed after collector restart
      with no service restart (fresh router.resolve traces exported).
- [x] 4.2 Hot-path overhead: router `router_ext_proc_duration_seconds` p99 =
      **0.100ms** with telemetry ON — span creation + 2-entry metadata scan +
      continue_trace is negligible against the routing work. No visible shift.

## 5. Metrics convergence (Phase B)

- [x] 5.1 Migrated the full instrument set in all six binaries from the `metrics`
      facade to the OTel meter (push path), preserving names: OTel counters drop the
      `_total` suffix (Prometheus's OTLP receiver re-appends it), histograms/gauges
      keep names; duration histograms keep explicit buckets. Per-binary `Metrics`
      struct + `LazyLock` holding instruments from `global::meter(service)`; the API
      crate is the only new binary dep (SDK/OTLP stay in core). Push-only (no parallel
      scrape) per the user's "OK to break things"; both workspaces `cargo check` clean.
- [x] 5.2 Verified parity on the push path (names identical): router/sidecar
      `_ext_proc_requests_total` count all requests; `histogram_quantile(0.99, sum by
      (le) (rate(_duration_seconds_bucket[..])))` returns real percentiles (router
      p99 2.47ms, sidecar p95 0.98ms) — aggregates across `le` correctly; reject
      ratio 0.50 from the `result` label; gauges (`router_ready`,
      `sidecar_cache_entries`) and background counters all queryable.
- [x] 5.3 Verified accuracy independence: dropped edge sampling to 10%, drove 60
      requests — `router_ext_proc_requests_total` rose by exactly 60 while only ~11
      traces were produced. The RED metric is unaffected by the head-sampling rate
      (first-class meter, never span-derived).

## 6. Retire the legacy scrape path (Phase C — gated on 5.2)

- [x] 6.1 Removed the first-party scrape jobs from
      `monitoring/prometheus/prometheus.yml` (kept `envoy` + `prometheus` self-scrape)
      and rewrote both `deploy/helm/{routing-plane,identity-plane}` ServiceMonitor
      templates to keep only the Envoy admin PodMonitor (Envoy is outside the box
      contract); first-party ServiceMonitors/PodMonitors retired.
- [x] 6.2 Verified post-retirement: active Prometheus scrape targets are only
      `envoy` + `prometheus`; the first-party RED metrics, cache/feed counters, and
      readiness gauges all answer from the push path (job=<service>,
      deployment_environment_name=lab) with no scrape target.

## 7. Config surface + docs

- [x] 7.1 Wired `OTEL_EXPORTER_OTLP_ENDPOINT` through the lab compose (set to the
      in-network collector) and the production deploy compose (optional, unset by
      default = off); `OTEL_RESOURCE_ATTRIBUTES=deployment.environment.name=lab` in
      the lab. RUST_LOG/LOG_LEVEL/LOG_FORMAT preserved.
- [x] 7.2 Updated `deploy/README.md` (first-party now push, not scrape; names
      preserved) and `nexus-upstream-requirements.md` (first-party services are
      compliant boxes; ownership row; Change C can build on the first-party RED
      baseline).
