## ADDED Requirements

### Requirement: Monitoring artifacts derive from a single source

The alerting/recording rules and the dashboards that realize the service SLO
policy SHALL be generated from a single declarative source. Every supported
delivery form SHALL be a rendering of that source; no delivery form SHALL carry
hand-maintained rule or query content that can diverge from the source.

#### Scenario: Regenerating after an objective change updates every form identically

- **WHEN** the SLO source is changed and the monitoring artifacts are regenerated
- **THEN** every delivery form reflects the change identically
- **AND** no delivery form retains stale or divergent rule or dashboard content

#### Scenario: No delivery form is authored by hand

- **WHEN** a reviewer inspects any delivery form's rule or dashboard content
- **THEN** that content is traceable to the single source as a rendering, not an
  independently edited copy

### Requirement: An operator-independent delivery form exists

Monitoring artifacts SHALL be deliverable in a form that requires no cluster-side
controller or custom-resource extension to be installed for the rules to be
evaluated and the dashboards to be loaded. This form SHALL function on a metric
backend that offers only standard rule evaluation and storage.

#### Scenario: A backend with no controller still evaluates the rules

- **WHEN** the monitoring artifacts are delivered to an environment that has no
  rule or monitor controller installed
- **THEN** the SLO rules are evaluated and the dashboards are available
- **AND** no artifact is silently ignored

### Requirement: No single delivery form is mandatory

Selecting a delivery form SHALL be a configuration choice. The system SHALL
continue to offer a controller-based delivery form for environments that provide
such a controller, and SHALL NOT require any single form. Changing the selected
form SHALL NOT modify any telemetry producer and SHALL NOT change the telemetry
exposition behavior.

#### Scenario: Switching delivery form touches no producer

- **WHEN** the selected delivery form is changed from controller-based to
  operator-independent, or the reverse
- **THEN** no telemetry-producing service is modified
- **AND** the telemetry exposition behavior is unchanged

#### Scenario: A controller-based environment consumes the controller form

- **WHEN** artifacts are delivered to an environment that provides a rule or
  monitor controller
- **THEN** the controller-based delivery form is available and consumed

### Requirement: Query content is portable across compatible backends

All rule and dashboard query content SHALL use only query constructs that are
portable across compatible metric backends; it SHALL NOT depend on any
backend-proprietary query extension. The identical rendered artifacts SHALL
evaluate equivalently on any compatible backend.

#### Scenario: The same rules evaluate equivalently on two compatible backends

- **WHEN** the identical rendered rules are evaluated on two different but
  compatible metric backends over the same input series
- **THEN** both backends produce equivalent alerting outcomes

### Requirement: The local reference environment exercises the production delivery form

The monitoring artifacts SHALL be exercisable on a clean local checkout using the
same backend family and the same operator-independent delivery form intended for
the first production environment, so rule evaluation and dashboards are validated
without any cloud dependency. This complements the SLO policy's local
exercisability by fixing the delivery form under test to the production one.

#### Scenario: Clean checkout loads and evaluates the operator-independent form

- **WHEN** the reference stack is brought up from a clean local checkout
- **THEN** the operator-independent rules are loaded and evaluated and the
  dashboards are available
- **AND** a synthesized burn condition raises its corresponding alert with no
  cloud dependency
