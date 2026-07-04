# Tasks: first-party-telemetry

<!-- Run /opsx:decide before 1.x — the four PENDING decisions in design.md pin the
     dependency set these tasks install. Phases match the design migration plan. -->

## 1. Shared telemetry modules (Phase A foundation)

- [ ] 1.1 Add the decided telemetry dependency set (pinned, workspace-level) to
      `routing-rs` and `identity-rs`, on the core crates (`router-core`,
      `identity_core`) — today `tracing`/`metrics` are per-binary deps
- [ ] 1.2 Create `router-core::telemetry` and its twin `identity_core::telemetry`:
      one `init(service_name)` building EnvFilter (`RUST_LOG`) + fmt layer
      (`LOG_FORMAT` json/plain, unchanged semantics) + trace bridge + OTLP log
      appender + meter provider; resource identity (service.name, service.version
      from crate version, deployment.environment.name from env); endpoint from the
      standard OTLP env var, **unset ⇒ no-op providers**; bounded batch processors,
      drop-on-full, log-and-continue on init failure (twins cross-reference each
      other in a header comment)
- [ ] 1.3 Replace the six per-binary `init_tracing()` copies with the core helper
      (tenant-router, control-plane, sidecar, sync-worker, reconciler,
      membership-sync); verify each binary still boots with no OTLP endpoint set
      and logs exactly as before (`LOG_FORMAT` both modes)

## 2. Hot-path trace continuation (Phase A)

- [ ] 2.1 tenant-router: read `traceparent` from the ext_proc `RequestHeaders` it
      already iterates, continue the context, and wrap the `handle()` processing
      stage in a span (result/pool attributes within the hygiene set); not-sampled
      or absent context ⇒ no span export
- [ ] 2.2 identity sidecar: same continuation via the existing `find_header`, span
      around the enrichment stage (result attribute; no identity values beyond the
      permitted set)
- [ ] 2.3 Verify in the lab: a sampled edge request produces ONE trace containing
      edge spans + routing span + enrichment span (correctly parented; siblings
      acceptable per design) + backend continuation; a not-sampled request exports
      no first-party spans
- [ ] 2.4 Verify log correlation: hot-path log records during a sampled request
      carry the trace id; the Grafana pivot works log→trace and trace→log for a
      routing/enrichment error (force one via an unknown host / missing profile)

## 3. Background services (Phase A)

- [ ] 3.1 sync-worker, reconciler, membership-sync, control-plane: root a trace per
      pass/administrative operation (always-on per design), logs correlated to it;
      verify a reconcile pass is investigable by service identity in Grafana

## 4. Fail-open + overhead verification (Phase A gate)

- [ ] 4.1 Verify fail-open under load: stop the collector while requests flow
      through the edge; `*_ext_proc_duration_seconds` p99 unchanged, zero request
      errors, telemetry resumes on collector restart without service restarts
- [ ] 4.2 Measure hot-path overhead: before/after p99 of both ext_proc histograms
      under the same load; budget = no visible shift (record numbers in this
      change's notes)

## 5. Metrics convergence (Phase B)

- [ ] 5.1 Emit the existing instrument set through the decided push path with the
      SAME metric names (router_*/sidecar_* histograms, counters, gauges; sidecar's
      exponential histogram maps to an OTel exponential histogram), scrape
      exposition still running in parallel
- [ ] 5.2 Verify parity: every query in
      `monitoring/grafana/dashboards/identity-plane.json` (and any router panels)
      answers identically from the push path; record the query-by-query comparison
- [ ] 5.3 Verify accuracy independence: lower the edge sampling knob; push-path
      request-rate/error metrics unchanged (contract scenario, now first-party)

## 6. Retire the legacy scrape path (Phase C — gated on 5.2)

- [ ] 6.1 Remove the six first-party scrape jobs from
      `monitoring/prometheus/prometheus.yml` and the ServiceMonitor templates in
      `deploy/helm/{routing-plane,identity-plane}`; keep the `envoy` and
      `prometheus` self-scrape jobs
- [ ] 6.2 Verify post-retirement: the operational questions (RED, cache/feed
      health, readiness gauges) remain answerable via the contract path only

## 7. Config surface + docs

- [ ] 7.1 Wire the OTLP endpoint env var through the lab compose (set, pointing at
      the in-network collector) and deploy compose + helm values (optional, unset
      by default = telemetry off); existing RUST_LOG/LOG_FORMAT untouched
- [ ] 7.2 Update `deploy/README.md` (first-party services now comply; knobs) and
      the `nexus-upstream-requirements.md` ownership/coexistence notes (two metrics
      worlds converged); point Change C at the now-complete first-party RED baseline
