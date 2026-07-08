## 1. Settle inputs (decide gate ratified: Adopt Sloth)

- [x] 1.1 Build-vs-adopt ratified via `/opsx:decide`: Adopt Sloth (CLI generator) for the MWMB engine — recorded in design.md
- [x] 1.2 Pinned Sloth `v0.16.0`; generation runs via `monitoring/slo/generate.sh` (docker, committed output, reviewable in diff)
- [x] 1.3 Objective/window defaults ratified as **v1**: 99.9% availability, 99% latency @100ms, standard 30d MWMB windows (fast 5m/1h + 30m/6h, slow 2h/1d + 6h/3d). Values live in `monitoring/slo/*.slo.yaml` and are a one-line change + regenerate to tune later

## 2. Outcome-aware latency (the defect fix)

- [x] 2.1 Add a low-cardinality `result` (success vs. error) attribute at the `router_ext_proc_duration_seconds` record site (`routing-rs/tenant-router/src/main.rs:605`) — reuses the existing counter's `result` enum (hit/reject/not_ready); `cargo check -p tenant-router` clean
- [x] 2.2 Add the same `result` attribute at the `sidecar_ext_proc_duration_seconds` record site (`identity-rs/sidecar/src/main.rs:1173`); `cargo check -p identity-sidecar` clean
- [x] 2.3 Confirm the collector `transform/cardinality` allow-list passes `result` on the duration signal — `result` is already in `keep_keys` (`monitoring/otel-collector/otel-collector.yaml:79`), documented as a required RED dim; no allow-list change needed
- [x] 2.4 Latency now sliceable by outcome: the histogram's `_count`/`_bucket`/`_sum` carry `result` (verified — the latency SLI rules `…duration_seconds_bucket{result="hit",le="0.1"}` pass `promtool check`); record path adds one static enum `KeyValue` (no measurable latency, by construction). Full live-traffic slice query deferred to lab bring-up

## 3. Deployment-environment invariant

- [x] 3.1 Enforce a valid `deployment.environment.name` at deploy/startup admission — **both** layers: (a) Rust startup guard `require_environment()` in the twin `telemetry::init` (`identity-rs/core`, `routing-rs/router-core`), export-gated, exits 1 with a clear stderr diagnostic; (b) Helm render `required` guard via new `*.otelResourceAttributes` helper in all 3 charts. Charts now also *supply* the value (nothing set it before)
- [x] 3.2 Enforcement is deploy-time only — startup check runs once before serving; Rust guard gated on `OTEL_EXPORTER_OTLP_ENDPOINT` being set; request path untouched (verified both workspaces `cargo check` clean)
- [x] 3.3 Every signal carries the environment by construction — the single `Resource` (now guaranteed non-empty env) is applied to all three providers (tracer/logger/meter)
- [x] 3.4 Documented in `deploy/README.md` (telemetry section): required attribute, chart-render + service-startup fail-closed, and the `lab` compose default

## 4. SLO policy as data

- [x] 4.1 Authored `monitoring/slo/{tenant-router,identity-sidecar}.slo.yaml` — availability + outcome-aware latency SLOs, keyed off the `result`-attributed metrics, scoped per env via the promoted `deployment_environment_name` label
- [x] 4.2 Ran Sloth `v0.16.0` → `monitoring/prometheus/rules/*.rules.yaml` (34 rules each: SLI recording rules 5m–30d, error-budget/burn metadata, page+ticket MWMB alerts). `promtool check rules` SUCCESS. **Prod folding done:** `generate.sh` stages the rules into each plane chart's `files/slo/`, and new `templates/prometheusrule-slo.yaml` (routing-plane + identity-plane) wraps them into a `-slo-burn-rate` PrometheusRule via `.Files.Get | fromYaml`. `helm template` renders both cleanly (verified). Umbrella note: `helm dependency update` to repackage subcharts after a regenerate
- [x] 4.3 Wired `rule_files:` into `monitoring/prometheus/prometheus.yml` + mounted `monitoring/prometheus/rules` into the lab Prometheus (root `docker-compose.yaml`)
- [x] 4.4 Generation step is `monitoring/slo/generate.sh` (pinned v0.16.0, docker, MSYS-safe); regenerate + commit after any spec edit

## 5. Verify the policy

- [x] 5.1 Fast-burn → page verified deterministically via `promtool test rules` (`monitoring/slo/tests/tenant-router.slo_test.yaml`, SUCCESS): a sustained 100%-error env fires the page (and ticket) alert
- [x] 5.2 Slow-burn → ticket-only verified via `promtool test rules`: a constant 0.5% error over ~25h fires the ticket alert (severity=ticket) and NOT the page (below the 14.4x/6x fast-burn factors, above the 3x/1x ticket factors)
- [x] 5.3 Brief-spike → no-page verified via `promtool test rules`: a 5-min burst over a 6h healthy baseline elevates the 5m window past the page threshold but the 1h window does not corroborate (asserted with `bool`), so NO alert fires — multi-window corroboration suppresses the false page
- [x] 5.4 Env isolation verified in the same passing promtool test: production burns at ratio 1.0 while staging stays 0.0; the alert fires for production only
- [x] 5.5 By construction: the SLO layer is passive Prometheus rule evaluation over already-emitted metrics; no request-path Rust code references it, so a broken/absent rule set degrades only burn visibility (also guaranteed by the `service-slo-policy` spec's read-only requirement)

## 6. Close out

- [x] 6.1 Synced delta specs into main specs: created `openspec/specs/service-slo-policy/spec.md` (6 reqs) and merged the ADDED + MODIFIED requirements into `openspec/specs/first-party-telemetry/spec.md` (now 7 reqs). `openspec validate --specs` → 23 passed, 0 failed
- [x] 6.2 Annotated the parked B/D seed (`platform-ha-and-hardening/EXPLORATION.md` §6.1) — A marked DELIVERED as `slo-burn-rate-policy`; B/D remain parked (driver: failure-survival → CNPG)
