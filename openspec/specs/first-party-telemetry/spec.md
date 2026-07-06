# first-party-telemetry

## Purpose

Makes nexus's own first-party services instances of the `box-telemetry-contract`
rather than the last non-compliant workloads on the internal network. The routing
plane's resolution and admin services and the identity plane's enrichment,
synchronization, reconciliation, and projection services emit all three signals to
the single collection endpoint, carry consistent resource identity, participate in
the edge-rooted trace on the request hot path (closing the first-party gap between
edge and backend), correlate their logs to that trace, and push RED/operational
metrics whose accuracy is independent of trace sampling — all without ever affecting
request resolution. This spec states only observable behavior; it is
language-, framework-, and vendor-agnostic.

## Requirements

### Requirement: First-party services are compliant boxes under the box telemetry contract

Every first-party service SHALL satisfy the `box-telemetry-contract` requirements as
a producer — the routing plane's resolution and admin services; the identity plane's
enrichment, synchronization, reconciliation, and projection services. Compliance
means: all signals emitted to the single collection endpoint, standard resource
identity (service name, version, deployment environment) consistent across signals,
structured severity-tagged logs, and the contract's PII hygiene. No first-party
service SHALL know any telemetry store address.

#### Scenario: One identity selects a first-party service across signals

- **WHEN** an operator filters traces, metrics, or logs by a first-party service's
  name in the shared visualization stack
- **THEN** that service's telemetry SHALL be selected in every signal by the same
  name, and no per-container access SHALL be needed to read its logs

#### Scenario: First-party telemetry of an authenticated request leaks no credentials

- **WHEN** a first-party service processes an authenticated request and its telemetry
  is inspected across all signals
- **THEN** no span attribute, metric label, or log field SHALL contain credential
  material, request/response bodies, or identity values beyond the edge access log's
  permitted set

### Requirement: The request hot path participates in the edge-rooted trace

Each request-path first-party service SHALL continue the edge-rooted trace context
of the request it is processing (routing resolution, identity enrichment) and SHALL
record a span for its processing stage, so a sampled request's
trace shows the full first-party path — edge, routing decision, enrichment — with no
gap between the edge's spans and the backend's.

#### Scenario: A sampled request's trace includes the first-party stages

- **WHEN** an operator opens the trace of a sampled request that was routed and
  enriched
- **THEN** the trace SHALL contain spans for the routing-resolution and
  identity-enrichment stages, correctly parented within the edge's trace

#### Scenario: The edge's negative sampling decision is respected

- **WHEN** the edge marks a request not-sampled
- **THEN** first-party services SHALL NOT export spans for that request and SHALL NOT
  override the head decision

### Requirement: First-party logs correlate to the active trace

A first-party service SHALL stamp the active trace and span identifiers on every log
record it produces while processing a traced request, so the logs↔traces pivot works
in both directions through the first-party path.

#### Scenario: A routing failure pivots from log to trace and back

- **WHEN** an operator finds a first-party error log recorded during a sampled
  request
- **THEN** the record SHALL carry the request's trace identifier, the trace SHALL be
  retrievable by it, and the trace SHALL lead back to all first-party log records for
  that request

### Requirement: Background work is observable under the same identity rules

Non-request-driven first-party services SHALL emit identity-carrying telemetry for
their operations (synchronization, reconciliation, projection, administrative
operations), rooting their own trace context where no edge-rooted context exists,
with the same log structure and correlation rules.

#### Scenario: A background pass is investigable in the shared stack

- **WHEN** an operator investigates a synchronization or reconciliation pass
- **THEN** its logs SHALL be selectable by that service's identity and severity in
  the shared stack, and records belonging to one pass SHALL be correlatable to that
  pass's trace

### Requirement: Telemetry emission never affects resolution

Telemetry emission SHALL be fail-open and non-blocking for every first-party service:
an unavailable or slow collection endpoint MUST NOT add measurable latency, errors,
or a new failure mode to request processing (routing resolution, enrichment) or to
background duties. Under sustained back-pressure the service SHALL shed telemetry
rather than delay its work, and emission SHALL resume without intervention when the
collection endpoint returns.

#### Scenario: Collector outage leaves the hot path unaffected

- **WHEN** the collection endpoint is unavailable while requests flow
- **THEN** routing and enrichment SHALL proceed with unchanged latency and outcomes,
  and telemetry SHALL resume on its own when the endpoint returns

#### Scenario: Telemetry back-pressure sheds data, not requests

- **WHEN** telemetry cannot drain as fast as it is produced
- **THEN** the service SHALL drop or bound buffered telemetry rather than block or
  slow request processing

### Requirement: Operator-facing metrics remain continuous through the migration

The migration of first-party metrics to the contract path SHALL NOT create a period
in which an operator-facing metrics question (request rates, error ratios, latency
percentiles, cache/feed health) is unanswerable, and existing dashboards SHALL NOT
silently break: the previous collection path retires only after the contract path
answers the same questions. Metric accuracy SHALL remain independent of trace
sampling throughout.

#### Scenario: Dashboards keep answering during the migration

- **WHEN** the migration is in progress and an operator uses an existing dashboard
- **THEN** its queries SHALL keep returning current data until the replacement path
  demonstrably serves the same questions

#### Scenario: Retiring the legacy path is verified, not assumed

- **WHEN** the previous metrics collection path for a service is retired
- **THEN** the operational questions previously answered by it SHALL be answerable
  via the contract path, verified before retirement
