## MODIFIED Requirements

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

When an alert corroborates a condition across more than one evaluation window, the floor
SHALL be applied to each window against that same window's request volume, not against a
single fixed window. A window whose volume clears the floor SHALL remain eligible to
fire even while a shorter window with insufficient volume is withheld, so that a service
which is too quiet to judge over a short window can still be judged over a longer one.

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
  the shorter window's request volume is below the floor while the longer window's volume
  is above it
- **THEN** the shorter window SHALL be withheld while the longer window remains eligible
  to evaluate, so a low-traffic objective is still monitored over the window where its
  sample is sufficient

## ADDED Requirements

### Requirement: A floored availability signal keeps a traffic-independent unavailability backstop

When an availability or error-ratio alert is subject to a minimum-sample floor, the
low-traffic region the floor withholds SHALL remain covered by a separate unavailability
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
