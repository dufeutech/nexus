# Proposal: box-telemetry-contract

## Why

N6 shipped edge-rooted tracing, but the observability story for backends is still
implicit and box-specific: jsbox/runlet happen to continue traces, logs live in
per-container stdout archaeology, and there is no stated baseline for what a service
on the internal network should emit. Every future box (a Python service, a Node
service, a third-party tool) would re-negotiate this from scratch. Publishing one
standards-based telemetry contract now — the observability twin of the trusted-header
contract — makes any current or future box observable by construction, before there
is production pain to react to.

## What Changes

- **A published telemetry contract for any box** (not just jsbox/runlet): what nexus
  provides (edge-rooted W3C trace context — already shipped; ONE collection endpoint
  accepting traces, metrics, and logs; fail-open guarantee) and what a compliant box
  emits (continued traces, RED metrics as percentile-queryable histograms, structured
  trace-correlated logs, standard resource identity attributes). Anchored on the
  industry-converged wire protocol and semantic conventions so a new service in any
  language complies via off-the-shelf instrumentation, with zero per-language
  integration work on our side.
- **The single-egress principle extends from traces to ALL telemetry signals:** the
  collection layer (shipped in N6 for traces) gains logs and metrics pipelines;
  producers still know exactly one endpoint; only the collection layer knows the
  stores.
- **A log store joins the monitoring stack** (visualization in the existing Grafana),
  with logs↔traces pivot by trace ID and the same PII-hygiene constraint as the edge
  access log.
- **A metrics-accuracy guarantee:** RED metrics are first-class signals, never derived
  from sampled traces, so turning the trace-sampling knob down can never silently skew
  error rates or percentiles.
- **Docs:** `nexus-upstream-requirements.md` gains a "Box telemetry contract" section
  (the consumer-facing half); deploy README observability guidance updated.
- **Out of scope (successor changes, recorded in design):** first-party Rust services
  adopting the contract themselves (trace continuation, trace_id-stamped logs,
  internal spans), and the policy layer (SLO targets, burn-rate alerting, error-biased
  sampling, retention economics).

## Capabilities

### New Capabilities

- `box-telemetry-contract`: the telemetry contract between nexus and any box on the
  internal network — single collection endpoint for all signals, required emission
  baseline (traces continued, RED metrics, correlated structured logs, resource
  identity), signal-accuracy independence from trace sampling, PII hygiene, and
  operator-facing queryability (logs↔traces pivot). Critical concerns for the
  build-vs-adopt gate: **log storage/query backend**, **log transport/ingestion
  path**, **metrics ingestion path (push vs scrape at the collection layer)** — all
  reliability-sensitive; none are hand-build candidates.

### Modified Capabilities

<!-- none: edge-request-tracing stays trace-scoped; the generalized single-egress
     requirement lives in the new capability rather than widening the shipped one -->

## Impact

- **Monitoring stack (lab compose + helm guidance):** one new adopt-tier service (log
  store), new logs/metrics pipelines in the existing collection layer config, one new
  Grafana datasource. No edge/Envoy changes.
- **Collection layer config** (`monitoring/otel-collector/otel-collector.yaml`): gains
  logs and metrics pipelines; may force a collector distribution choice (recorded at
  decide time).
- **Boxes (jsbox/runlet and future services):** no required code change to keep
  working; the contract states what compliant boxes SHOULD emit and gives them a
  stable endpoint to emit it to. jsbox becomes the reference consumer, not the design
  target.
- **First-party Rust services:** unchanged in this change (they already expose
  scrape-based metrics; joining the contract is the successor change).
- **Docs:** `nexus-upstream-requirements.md`, `deploy/README.md`.
- **No behavior change for tenants or end users;** request handling is untouched
  (telemetry stays fail-open).
