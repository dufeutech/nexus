# edge-request-tracing

## Purpose

The distributed-tracing contract rooted at the production edge: the edge is the
only origin of W3C trace context on the internal network, makes the head-sampling
decision, records spans for its own processing stages, and exports all trace
telemetry through a single collection layer. Backends (boxes) keep their fail-open
contract — continue an arriving trace, root their own when absent, never
tail-sample. The mechanism is the Envoy OTel tracer exporting to an OpenTelemetry
Collector in front of a trace store; this spec is tool-agnostic and states only
the observable behavior.

## Requirements

### Requirement: The edge is the sole root of trace context on the internal network

For every request it admits, the edge SHALL be the only party that originates trace
context: it makes the head-sampling decision and, for sampled requests, injects valid
W3C Trace Context (`traceparent`, and `tracestate` when present) toward the backend.
Client-supplied trace context SHALL never propagate past the edge (see the
`edge-auth-gate` unforgeable-header requirement). A backend on the internal network
MUST be able to treat an arriving `traceparent` as edge-rooted and trustworthy.

#### Scenario: Sampled request carries edge-rooted trace context

- **WHEN** the edge admits a request and its head-sampling decision selects it for
  tracing
- **THEN** the request SHALL arrive at the backend with a valid W3C `traceparent`
  whose trace was started at the edge, with the sampled flag set

#### Scenario: Unsampled request carries the negative decision downstream

- **WHEN** the edge admits a request and its head-sampling decision does not select it
- **THEN** any trace context forwarded to the backend SHALL mark the request as
  not-sampled, and no downstream component SHALL override that decision (no tail
  sampling inside nexus)

#### Scenario: Client-forged trace context cannot reach a backend

- **WHEN** an inbound request carries a client-set `traceparent` or `tracestate`
- **THEN** the backend SHALL NOT receive the client-supplied value; it receives either
  edge-rooted trace context or none

### Requirement: Trace spans for the edge request path are recorded and queryable

For sampled requests, the edge SHALL record spans covering its own processing — at
minimum the overall edge span, the routing-resolution stage, the identity-enrichment
stage, and the upstream (backend) call — and those spans SHALL be exported to a trace
store where an operator can query a trace by its trace ID and see the timing breakdown
of the stages.

#### Scenario: Operator inspects where request time went

- **WHEN** an operator looks up a sampled request's trace ID in the trace store
- **THEN** they SHALL see one trace with child spans for the edge's routing stage,
  identity stage, and backend call, each with start time and duration

#### Scenario: Trace export failure does not affect request handling

- **WHEN** the telemetry collection layer or trace store is unavailable
- **THEN** request routing, authentication, and enrichment SHALL proceed unaffected,
  and the edge SHALL NOT fail or delay requests because telemetry cannot be exported

### Requirement: All trace telemetry egresses through a single collection layer

Every component that exports trace telemetry SHALL export it to a single, dedicated
collection layer, which owns delivery to the trace store and any future destinations.
No component SHALL export directly to a specific storage or vendor endpoint, so that
adding, changing, or fanning out destinations is a change to the collection layer's
configuration only.

#### Scenario: A new telemetry destination requires no producer changes

- **WHEN** an operator adds a second telemetry destination (e.g. an external analysis
  system)
- **THEN** only the collection layer's configuration changes; the edge and services
  keep exporting to the same collection endpoint unchanged

### Requirement: Span attributes observe the same PII hygiene as the audit access log

Spans SHALL NOT carry credential material, header values, or user identifiers beyond
the set already permitted in the edge's audit access log (request metadata such as
method, canonical path, status, durations, and the acting workspace ID). In
particular, spans SHALL NOT record `Authorization` values, `x-user-*` values, or
request/response bodies.

#### Scenario: Sampled trace of an authenticated request leaks no credentials

- **WHEN** an authenticated request is sampled and its trace is inspected in the trace
  store
- **THEN** no span attribute SHALL contain the bearer credential, any `x-user-*`
  header value, or any request/response body content

### Requirement: Both edge deployment topologies produce identical tracing behavior

The tracing behavior defined here SHALL hold identically in every supported edge
deployment topology (single-host composition and cluster deployment); a topology
without the tracing configuration is a deployment defect, not an accepted variant.

#### Scenario: Cluster deployment traces like the single-host deployment

- **WHEN** the same sampled request flows through the cluster-deployed edge instead of
  the single-host edge
- **THEN** the resulting trace SHALL have the same span structure, propagation
  behavior, and hygiene guarantees
