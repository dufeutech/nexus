# Proposal: edge-rooted-tracing

## Why

N6 is the last open row in the upstream requirements contract: no request trace exists
anywhere — the edge neither starts nor propagates W3C trace context, and monitoring is
metrics-only, so a request that misbehaves across edge → routing → identity → backend has
no correlated view. Worse, the fail-open contract is already live against untrusted input:
a client-forged `traceparent` passes through the edge unstripped today, and any box that
honors the contract ("continue the trace if present") would join a client-controlled
trace. Closing N6 now — while there is one backend box — validates the propagation
pattern cheaply and fixes the integrity gap.

## What Changes

- **Trace-context integrity (phase 0, ships alone if needed):** client-supplied
  `traceparent`/`tracestate` join the edge's strip list of unforgeable headers. The edge
  becomes the only origin of trace context on the internal network.
- **Edge-rooted tracing (phase 1 = N6):** the edge starts a trace for sampled requests,
  makes the head-sampling decision, and injects W3C `traceparent`/`tracestate` toward the
  box. Boxes keep the existing fail-open contract: continue the trace when present, root
  their own when absent, never tail-sample.
- **Single telemetry egress point:** trace export flows through one collection layer
  (never edge → storage directly), so a future exporter change (customer SIEM, vendor
  APM) is a config change, not an application change.
- **Trace storage + visualization** wired into the existing metrics/dashboard stack, with
  a PII-hygiene constraint: span attributes carry no header values and no user
  identifiers beyond what the audit access log already allows.
- **Config parity:** the tracing configuration lands in both edge deployment topologies
  (compose and k8s/helm).
- **Roadmap only (recorded in design, NOT in scope):** log aggregation + trace-id log
  correlation, internal spans in the Rust services, retention/SLO/audit policy docs.
- Updates `nexus-upstream-requirements.md` (N6 row + header-contract table) on completion.

## Capabilities

### New Capabilities

- `edge-request-tracing`: the edge roots distributed traces — head-sampling decision at
  the edge, W3C trace-context propagation to backends, telemetry egress through a single
  collection point, and PII hygiene for span attributes. Critical concerns for the
  build-vs-adopt gate: **trace propagation/instrumentation standard**, **telemetry
  collection layer**, **trace storage/query backend** (all reliability-sensitive; none
  are hand-build candidates).

### Modified Capabilities

- `edge-auth-gate`: the "trusted header family is unforgeable by clients" requirement
  extends to trace-context headers (`traceparent`, `tracestate`) — clients cannot inject
  trace context past the edge.

## Impact

- **Edge (Envoy):** tracing configuration in both `deploy/compose/envoy/envoy.yaml` and
  the helm edge configmaps; `traceparent`/`tracestate` added to the C3 strip mutation.
- **Monitoring stack:** two new adopt-tier services (collection layer + trace backend)
  in the compose/helm monitoring topology; dashboard datasource addition.
- **Boxes (jsbox/runlet):** no code change — the fail-open contract is already
  implemented; they simply start receiving a real `traceparent`.
- **Docs:** `nexus-upstream-requirements.md` N6 row and header-contract table; deploy
  README (bring-up order is flexible; boxes tolerate either order).
- **No behavior change for tenants or end users;** anonymous/auth flows untouched.
