# box-telemetry-contract — delta spec

## ADDED Requirements

### Requirement: A single collection endpoint accepts every telemetry signal

nexus SHALL provide exactly one telemetry collection endpoint on the internal
network, accepting traces, metrics, and logs over the openly standardized telemetry
protocol (OTLP). A producer (any box, present or future) SHALL need to know only
this endpoint to emit every signal; only the collection layer's configuration SHALL
know the storage or downstream destinations for any signal. Telemetry emission
SHALL be fail-open on both sides: an unavailable collection endpoint MUST NOT
affect a box's request handling, and a box's telemetry volume MUST NOT be able to
block another producer's request path.

#### Scenario: One endpoint serves all three signals

- **WHEN** a box emits a trace span, a metric data point, and a log record to the
  collection endpoint
- **THEN** all three SHALL be accepted at that single endpoint and each SHALL become
  queryable in its respective store without the box knowing any store address

#### Scenario: A destination change requires no box changes

- **WHEN** an operator adds, replaces, or fans out a storage destination for any
  signal (e.g. a second log destination)
- **THEN** only the collection layer's configuration changes; every box keeps
  emitting to the same endpoint unchanged

#### Scenario: Collection outage never affects request handling

- **WHEN** the collection layer or any telemetry store is unavailable
- **THEN** boxes SHALL continue serving requests unaffected, and telemetry emission
  SHALL resume without box-side intervention when the collection layer returns

### Requirement: A compliant box identifies itself with standard resource attributes

Every signal a compliant box emits SHALL carry the standard resource-identity
attributes: the service name, the service version, and the deployment environment,
following the industry semantic conventions. These attributes SHALL be consistent
across the box's traces, metrics, and logs so one identity selects a service in
every signal.

#### Scenario: One identity selects a service across signals

- **WHEN** an operator filters any signal view by a box's service name
- **THEN** the box's traces, metrics, and logs SHALL all be selected by that same
  name, and two different boxes SHALL never be conflated under one identity

#### Scenario: A regression is attributable to a version

- **WHEN** two versions of the same box run side by side during a rollout
- **THEN** their telemetry SHALL be distinguishable by the service-version attribute

### Requirement: A compliant box correlates every signal to the edge-rooted trace

A compliant box SHALL continue the edge-rooted trace context on arriving requests
(per the `edge-request-tracing` contract) and SHALL stamp the active trace and span
identifiers on every log record produced while handling a traced request, so logs
and traces pivot in both directions.

#### Scenario: Log line pivots to the full trace

- **WHEN** an operator finds a box log record produced during a sampled request
- **THEN** the record SHALL carry the edge-rooted trace identifier, and looking that
  identifier up in the trace store SHALL show the full request trace including the
  edge spans

#### Scenario: Trace pivots to the box's logs

- **WHEN** an operator inspects a sampled trace and asks for the logs of a
  participating box
- **THEN** the box's log records for that request SHALL be findable by the trace
  identifier

### Requirement: Request-driven boxes emit RED metrics as aggregatable distributions

A compliant request-driven box SHALL emit the RED baseline — request rate, error
count/ratio, and request duration — with duration expressed as an aggregatable
distribution (histogram), such that percentiles (p50/p95/p99) are queryable and
correctly aggregatable across replicas. Pre-computed percentile values that cannot
be aggregated SHALL NOT be the canonical latency signal.

#### Scenario: Fleet-wide p99 is queryable

- **WHEN** an operator queries the 99th-percentile latency of a box running as
  multiple replicas
- **THEN** the result SHALL be computed across all replicas' distributions, not an
  average of per-replica percentiles

#### Scenario: Error ratio is queryable per service

- **WHEN** an operator queries a box's error ratio over a time window
- **THEN** the rate of error-classed requests relative to total requests SHALL be
  answerable from the emitted metrics alone

### Requirement: Metric accuracy is independent of trace sampling

RED metrics SHALL be first-class signals whose values are unaffected by the trace
head-sampling rate or by any trace keep/drop policy. Deriving the canonical rate,
error, or duration metrics from sampled traces SHALL be treated as a defect.

#### Scenario: Turning sampling down does not skew metrics

- **WHEN** the trace head-sampling rate is lowered (e.g. from 100% to 1%)
- **THEN** the measured request rate, error ratio, and latency percentiles SHALL be
  unchanged for the same traffic

### Requirement: Box telemetry observes the same PII hygiene as the edge

Telemetry emitted by a compliant box SHALL NOT carry credential material,
request/response bodies, or user identifiers beyond the set permitted in the edge's
audit access log. Log records SHALL be structured (machine-parseable) and
severity-tagged so hygiene and filtering are enforceable mechanically.

#### Scenario: Box telemetry of an authenticated request leaks no credentials

- **WHEN** a box handles an authenticated request and its telemetry for that request
  is inspected across all three signals
- **THEN** no span attribute, metric label, or log field SHALL contain the bearer
  credential, a trusted identity header value outside the permitted set, or body
  content

### Requirement: Logs are queryable beside traces in the shared visualization stack

Aggregated box logs SHALL be queryable — by service identity, time range, severity,
and trace identifier — in the same visualization stack where traces and metrics are
explored, so an operator investigates a request without leaving that stack or
resorting to per-container log access.

#### Scenario: One investigation surface

- **WHEN** an operator investigates a failed request
- **THEN** they SHALL be able to find the box's log records, pivot to the trace, and
  view the service's RED metrics in the same visualization stack, with no
  per-container shell access required
