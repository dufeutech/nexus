# service-slo-policy

## Purpose

The reliability contract for nexus's own services: each in-scope service carries a
stated service-level objective and an error budget, and alerting is driven by the rate
at which that budget burns across multiple time windows — not by single-window
instantaneous thresholds — so a fast outage pages while a slow leak opens a ticket.
Objectives and the burn policy live as operator-owned data, are scoped per deployment
environment, and are exercisable on a clean local checkout. The SLO layer is a
read-only consumer of already-emitted telemetry and never affects request handling.
This spec states only observable behavior; it is language-, framework-, and
vendor-agnostic.

## Requirements

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

### Requirement: Ratio and rate-quantile alerts do not fire below a minimum sample volume

An alert SHALL NOT fire below a configured minimum sample rate when its condition is a
ratio (an error/total fraction) or a rate-quantile (a p99 of a histogram rate): below
the floor the request volume over the evaluation window is too small for the ratio or
quantile to be meaningful. This applies to every such alert, whether it evaluates a
single window or corroborates a fast-burn and slow-burn condition across multiple
windows. The floor is a property of the alerting rule and SHALL be single-sourced as a
tunable value per objective, never a magic literal duplicated across rules. This guard
SHALL be authored at the SLO policy's source of truth so it is preserved through rule
generation and through any downstream vendoring of the rules — a consumer MUST NOT have
to re-add it.

The floor SHALL be a **request rate** — a volume per unit time (requests per second) —
and SHALL be the **same rate on every evaluation window**. It SHALL NOT be expressed as a
per-window sample *count*, because a fixed count is window-length-dependent: a count that
is a meaningful floor on a short window becomes an effective no-op on a long window
(a count sufficient for a 5-minute window corresponds to a far smaller, insignificant rate
over a 6-hour window), leaving the long, slow-burn windows unfloored. When an alert
corroborates a condition across more than one evaluation window, the floor SHALL be
applied to each window against that same window's request **rate**. A window whose rate
clears the floor SHALL remain eligible to fire even while a shorter window with
insufficient rate is withheld, so that a service which is too quiet to judge over a short
window can still be judged over a longer one.

The floor SHALL be expressed against the objective's own denominator: the total-request
rate for an availability/ratio objective, and the histogram count rate for a
latency/quantile objective. Applying the floor SHALL NOT alter the stated objective or
error budget; it only withholds firing when the sample is too small for the ratio or
quantile to be meaningful.

Where the same alert is emitted from more than one rendering path, every rendered copy
SHALL carry the identical floor, so the fired rule does not depend on which path
produced it.

#### Scenario: A near-idle service does not raise a threshold alert

- **WHEN** a ratio- or rate-quantile-based alert's threshold is nominally crossed but
  the request rate over the window is below the objective's configured minimum sample
  rate
- **THEN** the alert SHALL NOT fire, and it SHALL become eligible to fire only once the
  request rate exceeds the floor while the threshold remains crossed

#### Scenario: The floor does not move the objective

- **WHEN** the minimum-sample floor is configured or changed for an objective
- **THEN** the objective's target and error budget SHALL be unchanged, and above the
  floor the alert SHALL evaluate exactly as it did before

#### Scenario: The guard survives generation and vendoring

- **WHEN** the alerting rules are regenerated from the SLO specs, or vendored into a
  downstream consumer
- **THEN** the minimum-sample floor SHALL still be present in the produced rules,
  because it was authored at the policy source rather than patched into a generated or
  vendored copy

#### Scenario: Duplicated alerts carry an identical floor

- **WHEN** the same named alert is rendered from more than one delivery path
- **THEN** each rendered instance SHALL carry the identical minimum-sample floor, so the
  effective rule is independent of the path that produced it

#### Scenario: A multi-window alert floors each window on its own sample volume

- **WHEN** a burn-rate alert corroborates a shorter and a longer evaluation window, and
  the shorter window's request rate is below the floor while the longer window's rate is
  above it
- **THEN** the shorter window SHALL be withheld while the longer window remains eligible
  to evaluate, so a low-traffic objective is still monitored over the window where its
  sample is sufficient

#### Scenario: A long-window count that clears a sample count but not the rate is still withheld

- **WHEN** a low-traffic service's request volume over a long evaluation window exceeds
  what an equivalent fixed sample count would have required, yet its request **rate** over
  that window remains below the objective's minimum sample rate
- **THEN** the alert SHALL be withheld on that window, because the floor is evaluated as a
  window-independent rate rather than as a per-window count that a long window trivially
  clears

### Requirement: A floored availability signal keeps a traffic-independent unavailability backstop

An availability or error-ratio alert subject to a minimum-sample floor SHALL keep the
low-traffic region the floor withholds covered by a separate unavailability
signal that does not depend on request volume, so a genuine outage that coincides with
near-zero traffic is still surfaced. That backstop SHALL derive from an operator-owned
readiness or health indicator of the service rather than from the request ratio itself.
Introducing or changing the floor SHALL NOT reduce the outage coverage that existed
before the floor.

#### Scenario: A near-zero-traffic outage still alerts

- **WHEN** a service is unavailable while its request volume is below the availability
  objective's minimum sample rate, so the floored ratio alert cannot fire
- **THEN** a traffic-independent readiness/health signal SHALL alert on the unavailability

#### Scenario: The floor does not remove existing outage coverage

- **WHEN** a minimum-sample floor is applied to an availability alert that previously had
  no floor
- **THEN** the coverage for a volume-independent outage SHALL be preserved, not reduced,
  by a signal that remains active below the floor

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
