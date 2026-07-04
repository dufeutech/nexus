# Design: box-telemetry-contract

## Context

N6 (`edge-rooted-tracing`, archived 2026-07-03) shipped the trace half of
observability: the edge roots W3C trace context, exports OTLP/gRPC through an OTel
Collector (the single telemetry egress) into Tempo, queryable in Grafana. The
collector currently runs the **core** distribution with a traces-only pipeline
(`monitoring/otel-collector/otel-collector.yaml`). Logs are still per-container
stdout; metrics are Prometheus scrape-based for first-party services only. The
boxes' obligations are implicit (jsbox/runlet happen to continue traces) and
nothing states what a future box — in any language — should emit.

This change publishes the generic contract and stands up the missing signal
pipelines. It is contract-first by intent: the first-party Rust services adopt the
same contract in a successor change, so the contract is designed for *any* box, not
around nexus internals.

## Goals / Non-Goals

**Goals:**

- One collection endpoint, all three signals (traces / metrics / logs), OTLP.
- The single-egress property generalizes: producers know the collector, only the
  collector knows the stores.
- Logs land in a store beside Tempo with a two-way logs↔traces pivot in Grafana.
- Push-based metrics ingestion for boxes (no scrape-config coordination per box),
  with RED accuracy independent of trace sampling.
- The contract is satisfiable with off-the-shelf language SDK auto-instrumentation
  (the compliance bar for a hypothetical Python box: standard SDK + one endpoint
  env var, zero nexus-side integration work).
- Consumer-facing contract published in `nexus-upstream-requirements.md`.

**Non-Goals (successor changes):**

- First-party Rust services joining the contract (trace continuation from ext_proc
  headers, trace_id-stamped logs, internal spans) — Change B.
- SLO targets, burn-rate alerting, error-biased/tail sampling, retention economics
  — Change C (old phase 4).
- Scraping legacy container stdout into the log store (a compat adapter for
  non-compliant workloads) — explicitly out; the canonical path is push.
- Dashboard curation beyond the pivot wiring.

## Architecture

```
 any box (Rust / Python / Node / …)          Envoy edge (shipped, N6)
   │ traces + metrics + logs                   │ traces
   │        OTLP (one endpoint)                │ OTLP/gRPC
   └────────────────┬──────────────────────────┘
                    ▼
             OTel Collector            ← single egress; ONLY component
              │        │        │        that knows any store address
       traces ▼ metrics▼   logs ▼
            Tempo   Prometheus  log store
              └───────┬────────────┘
                   Grafana  (pivot: logs ↔ traces by trace_id;
                             metrics beside them)
```

Dependency direction is unchanged from N6 and inward-only: producers → collector →
stores → Grafana. All wiring lives in native-format config files under
`monitoring/` (collector yaml, store yamls, provisioned datasources) — no code.

## Decisions

<!-- Recorded via /opsx:decide 2026-07-03; the three critical concerns approved by
     the user, options researched against current (July 2026) state of the tools. -->

### Decision: log storage & query — Adopt Grafana Loki

- **Status**: approved
- **Why**: fits the committed Grafana/Tempo investment — native datasource with
  first-class logs↔traces pivot (derived fields / tracesToLogs), which the spec
  requires as one investigation surface; same local-disk-now / object-storage-later
  shape as Tempo. Research note: trace_id lands in Loki 3.x *structured metadata*
  (requires `allow_structured_metadata: true`), NOT as a label — Loki's
  high-cardinality label weakness doesn't apply on this path.
- **Considered**: VictoriaLogs (strong runner-up, decision re-tested 2026-07-03:
  it ALSO ingests OTLP natively via plain `otlphttp` — that argument is a wash —
  and its Grafana datasource now does log→trace derived fields with an OTel
  preset; the remaining differentiator is the REVERSE pivot: the Tempo trace→logs
  integration targets first-class datasource types, and a third-party plugin
  being selectable there is unverified. Loki is the only option with both pivot
  directions guaranteed. Revisit if log volume/query performance ever bites —
  the single-egress design makes the swap one exporter block + one datasource
  file, invisible to producers); OpenSearch (battle-tested full-text, heaviest
  ops by far, a second query language/UI — overkill at this scale).
- **Isolation**: reachable only by the collector (sole writer) and Grafana (sole
  reader); producers never know it exists (single-egress rule).

### Decision: log ingestion path — Adopt native OTLP ingestion into the log store

- **Status**: approved
- **Why**: Loki 3.x's native OTLP endpoint is Grafana's recommended ingestion path
  and takes the collector's plain `otlphttp` exporter — the collector stays on the
  **core** distribution, no second transport format, and the single-egress rule
  stays clean (boxes push OTLP logs; nothing scrapes container stdout on the
  canonical path).
- **Considered**: contrib-distribution Loki exporter (forces the contrib image now
  for no functional gain; Grafana itself steers to the native endpoint);
  stdout-scraping agents (Alloy/promtail — bypass the single egress, ingest
  unstructured legacy logs; belongs, if ever, to a legacy-compat change).
- **Isolation**: an exporter block in the collector's config file — the one
  component allowed to know the store address.

### Decision: metrics ingestion path — Adopt push OTLP to the collector → Prometheus native OTLP receiver

- **Status**: approved
- **Why**: push is what makes the contract generic — a new box needs zero scrape
  coordination. Prometheus 3's OTLP receiver is stable (`--web.enable-otlp-receiver`,
  `/api/v1/otlp`, metrics-only, off by default; enable a small
  `out_of_order_time_window` since pushed samples arrive unordered across
  producers). Collector forwards with core components. Existing first-party scrape
  jobs are untouched; both paths coexist until Change B converges them.
- **Considered**: collector-exposed scrape endpoint (pull semantics preserved but
  adds staleness/interval coupling and a moving joint for no benefit); per-box
  scrape jobs (exactly the per-box coordination the contract eliminates).
- **Isolation**: an exporter block in the collector's config file plus one
  Prometheus flag; producers see only the collector endpoint.

### Decision: RED metrics are first-class, never span-derived

- **Status**: approved (pinned by spec)
- **Why**: span-derived metrics (span-metrics connectors / trace-store metrics
  generators) are only accurate at 100% sampling; the sampling knob must never
  silently skew error rates or percentiles (spec: "Metric accuracy is independent
  of trace sampling"). Recorded so a future "free RED from traces" shortcut is
  recognized as a defect, not an optimization.
- **Considered**: span-metrics as the canonical RED source (couples metric truth to
  sampling policy); span-metrics generated before sampling in the collector
  (workable but makes the collector a mandatory metrics computer; revisit only if
  box-side metrics prove burdensome).
- **Isolation**: a contract requirement, not a component — enforced by spec review.

### Decision: collector stays on the core distribution

- **Status**: approved (consequence of the two approved ingestion paths)
- **Why**: with native-OTLP store paths for both logs and metrics, no contrib-only
  component is needed. The contrib switch is deliberately deferred to Change C
  (tail sampling is contrib-only) so image provenance changes ride a change that
  needs them.
- **Considered**: switch to contrib now (larger image/surface for no current
  functional gain).
- **Isolation**: the collector image tag in the compose file; swapping
  distributions is a one-line change invisible to every producer.

## Risks / Trade-offs

- [Log volume/cardinality explosion from unconstrained box labels] → the contract
  pins the identity attribute set (service name/version/environment); collector can
  enforce attribute allow-listing later without producer changes (single egress).
- [PII leakage via box logs — nexus can't code-review every box] → hygiene is a
  contract requirement with a verification scenario; the collection layer is the
  future enforcement point (processor-level redaction lives in one place if ever
  needed).
- [Two metrics worlds during transition (scrape for first-party, push for boxes)]
  → explicitly temporary; Change B converges first-party services. The stores are
  the same, so dashboards don't fork.
- [Native OTLP ingestion features are version-gated in the stores] → pin store
  versions at apply time (same discipline as the Envoy pin in N6); smoke-test each
  signal end-to-end in the lab before helm guidance.
- [Collector becomes a busier single point] → still fail-open by contract (verified
  scenario); pipelines are independent, and the collector is horizontally scalable
  later without producer changes.

## Migration Plan

1. Lab compose first: log store + collector logs/metrics pipelines + Grafana
   datasource with two-way pivot; verify each signal with a synthetic compliant
   emitter.
2. Docs: contract section in `nexus-upstream-requirements.md` (consumer-facing),
   deploy README observability guidance (cluster topology = external stores,
   matching the tracing pattern).
3. Rollback: remove the new pipelines/services; the traces path (N6) is untouched
   and unaffected.

Bring-up order is flexible throughout: everything is fail-open by contract.

## Roadmap (recorded, out of scope)

- **Change B — first-party services join the contract:** trace continuation from
  ext_proc headers, trace_id-stamped logs, internal spans in tenant-router /
  identity sidecar (the shared plumbing makes these one change, not two).
- **Change C — policy layer:** SLO targets on the RED baseline, multi-window
  burn-rate alerts, error-biased keep policy (head decision stays the ceiling —
  the collector may only subtract), retention economics; collector moves to the
  contrib distribution here if tail sampling lands.

## Open Questions

- Are logs **mandatory** or **recommended** for box compliance? (Spec currently
  requires correlation *when* logs are produced; a box emitting no logs at all is
  arguably still compliant. Decide when the first external box onboards.)
- Log store retention default (traces settled on 48h; logs likely longer — 7–14d?)
  — a config value, decide at apply time.
- Should the contract version itself (like `x-identity-contract: v1`) so a future
  baseline bump (e.g. exemplars, profiling signal) is detectable? Lean yes but
  defer until there is a second version to distinguish.
