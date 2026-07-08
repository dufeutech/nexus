## ADDED Requirements

### Requirement: Hot-path request-duration metrics are outcome-aware

The request-duration (latency) signal of first-party request-path services SHALL carry
the request outcome as a low-cardinality dimension distinguishing success
from failure, so latency can be sliced by outcome and an availability or latency
objective can be evaluated against non-error traffic. This outcome dimension SHALL stay
within the collection layer's cardinality allow-list, and adding it SHALL NOT introduce
any new high-cardinality label or otherwise change the cost profile of the signal. The
outcome attribution SHALL be recorded at the same point the duration is recorded, on
the request hot path, without adding measurable latency or a new failure mode.

#### Scenario: Latency is sliceable by success versus error

- **WHEN** an operator queries a first-party service's request-duration signal and
  filters to non-error outcomes
- **THEN** the signal SHALL return the latency distribution of successful requests
  only, distinct from failed requests, for every first-party request-path service that
  emits a duration signal

#### Scenario: Outcome attribution stays within the cardinality budget

- **WHEN** the outcome dimension is added to the duration signal
- **THEN** the resulting series SHALL remain within the collection layer's cardinality
  allow-list, and no other producer's metrics SHALL be affected

## MODIFIED Requirements

### Requirement: First-party services are compliant boxes under the box telemetry contract

Every first-party service SHALL satisfy the `box-telemetry-contract` requirements as
a producer — the routing plane's resolution and admin services; the identity plane's
enrichment, synchronization, reconciliation, and projection services. Compliance
means: all signals emitted to the single collection endpoint, standard resource
identity (service name, version, deployment environment) consistent across signals,
structured severity-tagged logs, and the contract's PII hygiene. No first-party
service SHALL know any telemetry store address.

Deployment-environment identity SHALL be a required, verified invariant rather than an
optional operator convenience: a valid deployment-environment attribute SHALL be
present on every signal a first-party service emits. Its absence SHALL be a deploy-time
failure — a service or its deployment SHALL fail to admit before serving rather than
emit environment-less telemetry — and SHALL NOT be enforced at request time, preserving
the fail-open, resolution-never-affected guarantee. The environment value SHALL be
supplied as configuration, defined once, and consistent across all of a service's
signals.

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

#### Scenario: A service without an environment fails to deploy, not to serve

- **WHEN** a first-party service is deployed without a valid deployment-environment
  attribute configured
- **THEN** the deployment SHALL fail to admit before the service serves traffic, and no
  environment-less telemetry SHALL be emitted; a request already in flight SHALL never
  be failed by this check

#### Scenario: Every emitted signal carries the environment

- **WHEN** a compliant first-party service emits any signal
- **THEN** that signal SHALL carry the same valid deployment-environment identity,
  consistent across traces, metrics, and logs
