# Tasks: box-telemetry-contract

## 1. Collection layer — all-signal pipelines (lab compose)

- [x] 1.1 Add `logs` and `metrics` pipelines to
      `monitoring/otel-collector/otel-collector.yaml` (OTLP receiver shared with
      traces; exporters per the decided stores; endpoints via env, not literals;
      collector stays on the core distribution per design)
- [x] 1.2 Verify: a synthetic OTLP log record and metric data point POSTed to the
      one collector endpoint are accepted (no producer knows a store address)

## 2. Log store + pivot

- [x] 2.1 Add the log store service to the lab compose monitoring stack — local-disk
      storage, retention as a config value (decide default at apply); config in its
      own native-format file under `monitoring/`; pin the image version (native OTLP
      ingestion is version-gated)
- [x] 2.2 Add the log store as a provisioned Grafana datasource with the two-way
      logs↔traces pivot wired (log → trace by trace_id derived field; trace → logs
      via the trace datasource's logs link)
- [x] 2.3 Verify: a log record carrying a trace_id pivots to the trace in Grafana,
      and the trace pivots back to the log records (spec: one investigation surface)

## 3. Metrics ingestion (push path)

- [x] 3.1 Enable native OTLP ingestion on the metrics store (config flag; pin the
      version) and wire the collector's metrics pipeline to it; existing first-party
      scrape jobs untouched
- [x] 3.2 Verify: a synthetic histogram pushed via the collector is queryable with
      correct percentile aggregation across two synthetic "replicas" (spec:
      fleet-wide p99), and a counter yields an error-ratio query

## 4. Contract compliance verification (synthetic box)

- [x] 4.1 Stand up a throwaway synthetic compliant box (off-the-shelf OTLP traffic
      generator or minimal auto-instrumented container; scratch/dev-only, not
      committed as a service) emitting all three signals with the required resource
      attributes (service name/version/environment)
- [x] 4.2 Verify identity: one service name selects the box's traces, metrics, and
      logs; two synthetic versions are distinguishable by the version attribute
- [x] 4.3 Verify correlation: the synthetic box, given an edge-style `traceparent`,
      emits logs whose trace_id matches the continued trace
- [x] 4.4 Verify hygiene mechanically: telemetry containing a fake credential/body
      field is detectable by inspection query (documents the check pattern for real
      boxes; the collector is the future redaction point)
- [x] 4.5 Verify sampling independence: lower the edge trace-sampling knob; the
      synthetic box's request-rate/error metrics are unchanged
- [x] 4.6 Verify fail-open: stop the collector; the synthetic box keeps serving and
      telemetry resumes on collector restart without box-side intervention

## 5. Cluster topology guidance

- [x] 5.1 Document the cluster (helm) pattern matching how tracing shipped: stores
      and collector are external, boxes get the one collector endpoint; add/extend
      values or README guidance — no chart code changes expected

## 6. Docs + contract publication

- [x] 6.1 Add the "Box telemetry contract" section to
      `nexus-upstream-requirements.md`: what nexus provides (endpoint, edge-rooted
      trace context, fail-open) and the compliance baseline (RED histograms,
      correlated structured logs, resource identity, PII hygiene), with the
      one-env-var onboarding story for a new-language box
- [x] 6.2 Update `deploy/README.md` observability guidance: logs/metrics knobs and
      bring-up (order stays flexible; everything fail-open)
- [x] 6.3 Record the successor-change pointers (Change B: first-party services join
      the contract; Change C: SLO/burn-rate/keep-policy) where the roadmap lives in
      this change's design.md
