## ADDED Requirements

### Requirement: Operator-runnable edge capacity validation

The platform SHALL provide an operator-runnable validation that measures the edge's sustained
capacity — throughput and latency under a fixed offered load — separately from correctness
testing. It SHALL be invocable against any reachable edge deployment (local lab or a real
environment) by supplying the edge address and the addressed workspace.

#### Scenario: Validate a running edge

- **WHEN** an operator runs the capacity validation against a reachable edge, giving the edge
  address and the workspace host
- **THEN** it drives load through the edge and reports the measured throughput and latency,
  without requiring any change to the edge or its backends

#### Scenario: Target is unreachable

- **WHEN** the validation is started but the edge address does not answer
- **THEN** it SHALL fail fast with a clear message identifying the unreachable target, rather
  than reporting misleading measurements of a down system

### Requirement: Representative cost paths

The validation SHALL exercise the distinct request cost paths of the edge so results reflect
real per-path cost: at minimum a non-enriched route (proxy only), an enriched route (tenant
resolution + identity enrichment run), and the auth-gate rejection path (a protected route
without a credential). Each path's tail latency SHALL be reported.

#### Scenario: Enriched path is measured distinctly

- **WHEN** the validation runs
- **THEN** the enriched route — which exercises the tenant-resolution and identity-enrichment
  work — SHALL be measured as its own path, so its cost is not hidden behind the cheaper
  proxy-only path

### Requirement: Load model preserves tail-latency truth

The offered load SHALL follow an open model: requests are issued on a schedule independent of
how fast the system responds, so that slowdowns manifest as increased measured latency rather
than as a reduced request count (coordinated omission). Reported latency SHALL include tail
percentiles (at least p95 and p99).

#### Scenario: A slow edge shows as latency, not fewer requests

- **WHEN** the edge slows under load during a run
- **THEN** the slowdown SHALL appear as higher measured p95/p99 latency, and the number of
  requests issued SHALL NOT silently shrink to hide the stall

### Requirement: Explicit SLO gate

The validation SHALL accept operator-supplied SLO thresholds (throughput/latency/error-rate)
and SHALL signal pass or fail against them via its exit status, so it can gate an automated
job. Absent operator thresholds, any built-in defaults SHALL be clearly documented as
placeholders, not as endorsed targets.

#### Scenario: Threshold crossed fails the run

- **WHEN** a run's measured tail latency or error rate exceeds the operator-supplied SLO
- **THEN** the validation SHALL exit non-zero (fail), and SHALL exit zero only when every
  threshold held

#### Scenario: No operator thresholds supplied

- **WHEN** the validation is run without operator-supplied SLO thresholds
- **THEN** it SHALL still run and report, and its output SHALL make clear that any default
  thresholds are placeholders the operator must replace before trusting the pass/fail result

### Requirement: Steady-state measurement

Before recording its measured window, the validation SHALL prime the edge (warm-up) so the
reported numbers reflect steady state rather than cold-start effects.

#### Scenario: Warm-up precedes measurement

- **WHEN** a run begins against a freshly started edge
- **THEN** it SHALL send warm-up traffic before the measured window so first-request
  cold-start costs do not distort the reported percentiles

### Requirement: Separate from the correctness gate

The capacity validation SHALL NOT be wired into the per-change correctness gate by default;
the correctness gate SHALL remain fast and hermetic. Capacity validation is intended for a
scheduled or on-demand job against a production-like environment.

#### Scenario: Correctness gate stays fast

- **WHEN** the per-change CI gate runs
- **THEN** it SHALL NOT run the capacity validation, keeping the correctness gate hermetic and
  fast; capacity validation runs on its own schedule
