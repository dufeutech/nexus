# telemetry-cost-controls — delta spec

## ADDED Requirements

### Requirement: Each signal is stored on a scalable tier with an explicit retention bound

Every telemetry signal (traces, metrics, logs) SHALL be retained on a storage tier
that scales independently of any single host's disk and SHALL have an explicit,
operator-owned retention bound sized to that signal's purpose. Retention SHALL be a
stated configuration value, never an implicit default, and changing it SHALL be a
collection-layer/store configuration change with no producer change.

#### Scenario: Retention is bounded and stated per signal

- **WHEN** an operator asks how long each signal is kept and where it lives
- **THEN** each signal SHALL have a documented retention window and storage tier, and
  data older than the window SHALL be reclaimed automatically

#### Scenario: Storage grows without exhausting a host

- **WHEN** telemetry volume grows over time within the retention window
- **THEN** storage SHALL scale on its tier without filling a single host's local
  disk, and no producer SHALL need reconfiguration for the store to scale

### Requirement: No single producer can exhaust the telemetry budget

The collection layer SHALL bound what any one producer can cost — in metric series
cardinality and in log/telemetry volume — so that a misbehaving or hostile producer
degrades ITS OWN telemetry fidelity rather than the shared bill or the store's
health. These bounds SHALL be enforced at the single collection egress, without any
change to compliant producers.

#### Scenario: A cardinality explosion is contained, not billed

- **WHEN** a producer emits an unbounded or high-cardinality label on a metric
- **THEN** the collection layer SHALL bound the resulting series (e.g. by dropping or
  aggregating the offending dimension) so total series stay within budget, and other
  producers' metrics SHALL be unaffected

#### Scenario: A log flood degrades only the noisy producer

- **WHEN** one producer emits log or telemetry volume far above the norm
- **THEN** the collection layer SHALL bound that producer's contribution so the shared
  store and bill are protected, while other producers' telemetry is delivered intact

#### Scenario: Bounding never touches the request path

- **WHEN** the cost ceiling engages against an abusive producer
- **THEN** only that producer's telemetry fidelity SHALL be reduced; no request
  handling, resolution, or other producer's request path SHALL be affected

### Requirement: The lab runs the cost topology on a clean checkout

The cost-controlled storage topology SHALL be exercisable locally with no external
account or credential: a clean checkout SHALL bring the full stack up on a
self-contained object-storage-compatible tier, so the same configuration that runs in
production is what runs in the lab, differing only by endpoint and credentials
supplied via environment.

#### Scenario: Clean checkout comes up with no cloud dependency

- **WHEN** a developer brings the stack up from a fresh checkout with no cloud
  credentials
- **THEN** all three stores SHALL start on the self-contained storage tier and accept
  and serve telemetry, with no manual provisioning step

### Requirement: Trace cost stays governed by the head decision alone

Trace retention cost SHALL remain governed by the edge's head-sampling decision as
the ceiling; the collection layer SHALL NOT reintroduce dropped traces or add a
stateful tail-retention stage as part of cost control. Reducing trace cost SHALL be
achieved by the head-sampling rate and by the storage tier, not by buffering and
re-deciding traces downstream.

#### Scenario: Cost control does not resurrect head-dropped traces

- **WHEN** the edge marks a request not-sampled
- **THEN** no cost-control mechanism SHALL cause that request's spans to be generated,
  transported, or stored, and trace cost SHALL scale down with the head-sampling rate

#### Scenario: Lowering trace cost needs no new stateful stage

- **WHEN** an operator needs to cut trace storage cost
- **THEN** the available levers SHALL be the head-sampling rate and the storage
  tier/retention, with no stateful downstream trace-buffering component required
