## ADDED Requirements

### Requirement: Each in-scope service has a stated objective and error budget

Every service in the SLO scope SHALL have a stated service-level objective for each of
its service-level indicators (at minimum availability, and latency where a duration
signal exists), expressed as an operator-owned target over an explicit rolling window.
From that objective the system SHALL derive an error budget — the complement of the
target over the window — as the single quantity that burn is measured against. The
objectives and window SHALL be defined once as data, never as a magic literal
duplicated across the alerting layer, and SHALL be changeable without touching any
producer.

#### Scenario: An operator reads a service's objective and remaining budget

- **WHEN** an operator asks what a service's objective is and how much error budget
  remains in the current window
- **THEN** the system SHALL report the stated target, the window it is measured over,
  and the fraction of budget consumed, for every service in scope

#### Scenario: Changing an objective touches no producer

- **WHEN** an operator revises a service's target or window
- **THEN** the change SHALL take effect as a policy/configuration change with no
  change to, or redeploy of, the measured service

### Requirement: Alerting is driven by multi-window error-budget burn rate

Alerting SHALL fire on the rate at which a service consumes its error budget, evaluated
over multiple time windows simultaneously, rather than on a single-window instantaneous
threshold. A fast-burn condition (budget being consumed quickly enough to exhaust it
well within the window) SHALL raise a high-severity, page-worthy signal; a slow-burn
condition (sustained consumption that will breach the objective without immediate
danger) SHALL raise a low-severity, ticket-worthy signal. Each burn condition SHALL
require corroboration across a short and a long window so a brief spike alone does not
page.

#### Scenario: A sudden outage pages via fast burn

- **WHEN** a service's error ratio rises sharply enough to threaten near-term budget
  exhaustion, sustained across both the short and long fast-burn windows
- **THEN** a high-severity page-worthy alert SHALL fire, identifying the service and
  the objective being burned

#### Scenario: A slow leak opens a ticket, not a page

- **WHEN** a service consumes budget steadily but far below the fast-burn rate
- **THEN** a low-severity ticket-worthy alert SHALL fire and no page SHALL be raised

#### Scenario: A momentary spike does not page

- **WHEN** error ratio spikes briefly in the short window but the long window does not
  corroborate it
- **THEN** no page SHALL fire

### Requirement: The availability objective is measured over outcome-attributed traffic

Availability burn SHALL be computed from telemetry that distinguishes successful from
failed request outcomes, so the objective is stated and evaluated against non-error
traffic rather than a distribution that fuses success and failure. Where a latency
objective exists, it SHALL be evaluable over successful requests alone.

#### Scenario: Availability is computed from success versus failure

- **WHEN** the SLO layer evaluates an availability objective for a service
- **THEN** it SHALL derive the success ratio from outcome-attributed telemetry, and a
  latency objective SHALL be computable over successful outcomes only

### Requirement: Objectives are scoped per deployment environment

Objectives, budgets, and burn evaluation SHALL be scoped by deployment environment, so
one environment's burn never contaminates another's budget. Telemetry that cannot be
attributed to a deployment environment SHALL NOT be counted toward any environment's
objective.

#### Scenario: Two environments burn independently

- **WHEN** one deployment environment breaches its objective while another stays within
  budget
- **THEN** only the breaching environment's budget SHALL show consumption and only its
  alerts SHALL fire

### Requirement: The SLO policy is exercisable on a clean local checkout

The same objectives and burn-rate policy that run in production SHALL be exercisable
from a clean checkout with no external account or credential, differing only by
configuration supplied via environment. Bringing the stack up SHALL load the policy so
that objectives are evaluated and burn alerts can fire locally.

#### Scenario: Clean checkout evaluates burn locally

- **WHEN** a developer brings the metrics stack up from a fresh checkout
- **THEN** the SLO objectives SHALL be loaded and evaluated, and a synthesized burn
  condition SHALL raise the corresponding alert, with no cloud dependency

### Requirement: SLO evaluation never affects request handling

Objective and burn-rate evaluation SHALL be a read-only consumer of already-emitted
telemetry and SHALL NOT introduce any new failure mode, latency, or blocking behavior
on any request path. An unavailable or misconfigured SLO layer SHALL degrade only the
operator's visibility into burn, never request resolution.

#### Scenario: A broken SLO layer does not touch the hot path

- **WHEN** the SLO evaluation or alerting layer is unavailable or misconfigured
- **THEN** request resolution and enrichment SHALL proceed unchanged, and only burn
  visibility SHALL be degraded
