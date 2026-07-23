## ADDED Requirements

### Requirement: Ratio and rate-quantile alerts do not fire below a minimum sample volume

An alert whose condition is a **ratio** (e.g. an error/total fraction) or a **quantile computed over a rate** (e.g. a p99 of a histogram rate) SHALL NOT fire when the request volume over its evaluation window is below a configured minimum sample rate. The floor is a property of the alerting rule and SHALL be single-sourced as a tunable value per objective, never a magic literal duplicated across rules. This guard SHALL be authored at the SLO policy's source of truth so it is preserved through rule generation and through any downstream vendoring of the rules — a consumer MUST NOT have to re-add it.

The floor SHALL be expressed against the objective's own denominator: the total-request rate for an availability/ratio objective, and the histogram count rate for a latency/quantile objective. Applying the floor SHALL NOT alter the stated objective or error budget; it only withholds firing when the sample is too small for the ratio or quantile to be meaningful.

Where the same alert is emitted from more than one rendering path, every rendered copy SHALL carry the identical floor, so the fired rule does not depend on which path produced it.

#### Scenario: A near-idle service does not raise a threshold alert

- **WHEN** a ratio- or rate-quantile-based alert's threshold is nominally crossed but the request rate over the window is below the objective's configured minimum sample rate
- **THEN** the alert SHALL NOT fire, and it SHALL become eligible to fire only once the request rate exceeds the floor while the threshold remains crossed

#### Scenario: The floor does not move the objective

- **WHEN** the minimum-sample floor is configured or changed for an objective
- **THEN** the objective's target and error budget SHALL be unchanged, and above the floor the alert SHALL evaluate exactly as it did before

#### Scenario: The guard survives generation and vendoring

- **WHEN** the alerting rules are regenerated from the SLO specs, or vendored into a downstream consumer
- **THEN** the minimum-sample floor SHALL still be present in the produced rules, because it was authored at the policy source rather than patched into a generated or vendored copy

#### Scenario: Duplicated alerts carry an identical floor

- **WHEN** the same named alert is rendered from more than one delivery path
- **THEN** each rendered instance SHALL carry the identical minimum-sample floor, so the effective rule is independent of the path that produced it
