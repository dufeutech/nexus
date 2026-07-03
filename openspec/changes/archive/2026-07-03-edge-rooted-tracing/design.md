# Design: edge-rooted-tracing

## Context

Monitoring today is metrics-only (Prometheus + Grafana). The edge (Envoy) has no
tracing stanza; the Rust services use `tracing`/`tracing-subscriber` for structured
logs with no export or propagation; no collector exists. Envoy already generates
`x-request-id` and records it in the JSON access log. The C3 strip list
(header_mutation, first filter) does not cover `traceparent`/`tracestate`, so
client-forged trace context currently reaches backends — and the box contract says
boxes continue an arriving trace.

The Envoy config exists in two hand-mirrored topologies: `deploy/compose/envoy/envoy.yaml`
(compose) and the helm `edge-configmap.yaml` templates (`edge-platform`,
`identity-plane`, `routing-plane` charts), plus a reference copy at `edge/envoy.yaml`.

## Goals / Non-Goals

**Goals:**

- Edge roots every trace; head-sampling decision at the edge; W3C context toward boxes.
- Client trace context stripped at C3 (integrity fix — ships first, standalone-safe).
- All trace export flows through one collection layer; storage/vendor is a
  collection-layer config detail, never a producer config detail.
- Traces queryable in the existing Grafana.
- PII hygiene: span attributes ≤ what the audit access log already allows.
- Identical behavior in compose and helm topologies.

**Non-Goals (roadmap, recorded below):**

- Log aggregation and trace-id ↔ log correlation (phase 2).
- Internal spans inside the Rust services (phase 3) — Envoy's ext_proc spans already
  give per-stage timing without touching Rust.
- Tail sampling, retention/SLO/audit policy docs (phase 4).
- Box-side changes — jsbox/runlet already implement the fail-open contract.

## Architecture

```
 client ──(traceparent STRIPPED at C3)──▶ Envoy edge
                                            │ roots trace, head-samples,
                                            │ injects traceparent → box
                                            │ spans: edge / router ext_proc /
                                            │        identity ext_proc / upstream
                                            ▼ OTLP
                                     collection layer  ──▶ trace store ──▶ Grafana
                                     (single egress;        (query by
                                      future fan-out         trace ID)
                                      lives here only)
```

Dependency direction: producers (Envoy today; Rust services in phase 3) know ONLY the
collection layer's endpoint. Only the collection layer knows the trace store. Grafana
knows the trace store as a datasource. Sampling rate and collector endpoint are
externalized config (compose env / helm values), not literals repeated per topology.

## Decisions

<!-- Recorded via /opsx:decide 2026-07-03; all three approved by the user. -->

### Decision: trace propagation & edge instrumentation — Adopt OpenTelemetry (W3C Trace Context, Envoy native OTel tracer)

- **Status**: approved
- **Why**: W3C Trace Context + OTel is the industry-converged standard (CNCF, what
  boxes already expect per the N6 contract); Envoy ships a native OTel tracer that
  exports OTLP/gRPC and does W3C propagation. Caveat recorded: Envoy's docs still flag
  the OTel tracer extension as work-in-progress, though Istio has shipped it as its
  default tracer since 1.22.
- **Considered**: Envoy Zipkin tracer → collector Zipkin receiver (older but
  battle-tested; B3 propagation would break the W3C box contract unless remapped);
  hand-rolled traceparent injection via header mutation (Build — rejected, defect).
- **Isolation**: tracing stanza lives in the Envoy config only; boxes see pure W3C
  headers, never the tracer implementation.
- **Apply-time finding (2026-07-03)**: Envoy makes its join-vs-root tracing decision
  BEFORE the http_filters run, so the C3 header_mutation strip alone is too late for
  the tracer — a client-forged `traceparent` would be JOINED (client-rooted trace)
  even though the header never reaches the backend. The strip therefore lives in TWO
  places per edge: `early_header_mutation_extensions` (before the tracing decision —
  the integrity half) and the C3 filter strip (defense-in-depth for the
  backend-facing guarantee). Verified live: with the tracer on, a forged traceparent
  produced a fresh edge-rooted trace ID at the backend. Second finding: the runtime
  key `tracing.random_sampling` (the compose env knob) reads an integer as a WHOLE
  PERCENT 0-100 (legacy semantics; verified 50 => ~50% sampled), not the 0-10000
  range some docs suggest; both compose commands and helm values use percent so the
  knob is unit-identical across topologies. Third: Envoy always injects `traceparent`
  once the tracer is configured — unsampled requests carry the not-sampled flag
  (`-00`), which is exactly the spec's negative-decision propagation scenario.

### Decision: telemetry collection layer — Adopt OpenTelemetry Collector

- **Status**: approved
- **Why**: reference vendor-neutral implementation; receives OTLP, exports anywhere;
  keeps the "swap/fan-out destinations = config change" property that is the point of
  the single-egress requirement.
- **Considered**: Grafana Alloy (wraps the same otelcol components, Grafana-polished,
  but ties the neutral egress point to one vendor's distribution); Vector (Rust, strong
  logs/metrics pipeline, traces are secondary).
- **Isolation**: the only component that knows the trace store's address; producers
  know only the collector endpoint (externalized as config).

### Decision: trace storage & query — Adopt Grafana Tempo

- **Status**: approved
- **Why**: fits the existing Grafana investment (native datasource, trace UI, future
  logs↔traces linking); minimal ops — no index cluster, object storage or local disk;
  multi-tenant capable if boxes multiply.
- **Considered**: Jaeger v2 (own UI, adaptive sampling, but heavier storage backend and
  a second UI to operate alongside Grafana); managed/vendor APM (Rent — rejected for
  now: traces stay on the internal network; revisit if ops burden bites).
- **Isolation**: reachable only by the collector and Grafana; nothing else may know it
  exists (enforced by review, and by network topology in helm).

## Risks / Trade-offs

- [Envoy OTel tracer marked WIP upstream] → pin the Envoy image version; smoke-test
  span export in compose before helm rollout; fallback path (Zipkin tracer → collector
  Zipkin receiver) is a config-only swap because the collector is in the middle.
- [Config sprawl: compose + 3 helm charts + reference copy] → single source per value:
  sampling rate and collector endpoint are variables (env/values), the tracing stanza
  is written once per topology; task includes a parity check between topologies.
- [Trace volume/cost surprises] → head sampling default is conservative (config, not
  code); Tempo on local/object storage with short retention initially.
- [PII leakage via default span attributes] → explicitly configure custom tags OFF
  beyond the allowed set; spec scenario covers it; review gate on the stanza.
- [Collector as new single point of failure] → export is fail-open by design (spec
  requirement: telemetry outage never affects requests); Envoy buffers/drops, requests
  unaffected.

## Migration Plan

1. **Phase 0 (standalone-safe):** add `traceparent`/`tracestate` to the C3 strip
   mutation in both topologies. No dependency on anything else; deployable alone.
2. **Phase 1:** add collector + trace store to the monitoring stack (compose first);
   add the Envoy tracing stanza; wire the Grafana datasource; verify a sampled request
   end-to-end (edge span → ext_proc spans → upstream span, queryable by trace ID).
3. Helm parity; update `nexus-upstream-requirements.md` (N6 row → shipped; header
   table `traceparent` → shipped) and `deploy/README.md`.
4. Rollback: remove the tracing stanza / collector containers; the strip-list entry
   stays (it is a security fix, not part of the rollback surface).

Bring-up order relative to boxes is flexible by contract (boxes fail open).

## Roadmap (recorded, out of scope)

- **Phase 2 — log correlation:** log aggregation into Grafana; `trace_id` stamped in
  Rust/box logs via the `tracing` → OTel bridge; logs↔traces pivot.
- **Phase 3 — service spans:** internal spans in identity sidecar / tenant-router,
  continuing the edge trace; OTel semantic conventions from day one.
- **Phase 4 — policy:** retention split (audit access log ≥ 1y vs traces days–weeks),
  SLOs + alerting, error-biased sampling (tail sampling in the collector — the
  single-egress choice keeps this door open).

## Open Questions

- Default head-sampling rate (start 100% in dev/compose, low % in production?) — a
  config value; decide at apply time, not a blocker.
- Tempo storage in helm: local PV vs object storage — infra detail per environment.
