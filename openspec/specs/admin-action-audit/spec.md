# admin-action-audit

## Purpose

Make every administrative action on the platform's two admin surfaces (authz-admin,
control-plane) durably attributable: a **fail-closed, append-only audit ledger** per
plane, written in the same transaction as the mutation it describes — an unrecorded
admin mutation does not commit. Admin credentials are **individually identifiable**
(one named token per caller, rotatable and revocable independently), so every event
names who acted; callers may additionally assert the human operator they act for,
recorded verbatim and never trusted for authorization. Denied access leaves a trace —
rejected authentications and authorization refusals alike (the latter attributed to the
actor with the decision reason, per `admin-plane-authorization`);
idempotent replays are visible as replays; the bootstrap grant is covered; and
each surface exposes a read/query + export path over its own ledger with a governed
retention window. Deliberately NOT telemetry: the ledger never rides the fail-open
collection layer. Provides the SOC 2 CC6.x/CC7.2/CC8.1 administrative-action evidence.

## Requirements

### Requirement: Every mutating admin action is recorded atomically with its effect

The system SHALL record a durable audit event for every mutating administrative
action on either admin surface, and the event SHALL be committed atomically with
the mutation itself: if the audit event cannot be recorded, the mutation SHALL NOT
take effect. Audit recording SHALL NOT depend on the telemetry collection layer,
and telemetry unavailability SHALL NOT affect audit recording.

#### Scenario: Mutation and audit event commit together

- **WHEN** an administrative mutation (e.g. a role grant or workspace transfer)
  succeeds
- **THEN** exactly one audit event describing it is durably recorded, and the event
  is visible to the audit query surface once the mutation is visible

#### Scenario: A mutation that cannot be audited does not commit

- **WHEN** the audit event for an administrative mutation cannot be durably recorded
- **THEN** the mutation is not applied and the caller receives an error, never a
  success with a missing audit event

#### Scenario: Telemetry outage does not touch the ledger

- **WHEN** the telemetry collection layer is unavailable
- **THEN** administrative mutations and their audit recording proceed unaffected

### Requirement: Audit events carry a complete, self-describing record

Each audit event SHALL carry: a typed, time-ordered event identifier unique across
both surfaces; the time of the action; the surface it occurred on; the action name
drawn from a closed vocabulary; the acting credential's identifier; the target of
the action (a typed resource id, subject, domain, or key id); the outcome (success,
or the error class on failure); and correlation data (request/trace identifier where
present, caller network source, and the idempotency key when one was supplied).
Events SHALL NOT contain credential material or other secrets — never a bearer
token, an api-key plaintext, or key material.

#### Scenario: An event reconstructs who did what, where, and when

- **WHEN** an auditor reads a single audit event
- **THEN** it identifies the acting credential, the action, the target resource, the
  outcome, and the time, without consulting any other record

#### Scenario: Events never leak secrets

- **WHEN** an action whose request or response carries secret material (e.g. api-key
  issuance) is audited
- **THEN** the recorded event contains identifiers only and none of the secret
  material

#### Scenario: Event ids are self-describing and time-ordered

- **WHEN** an audit event id appears in a log or export
- **THEN** its type prefix identifies it as an audit event, and lexicographic order
  of ids follows event time order

### Requirement: Admin credentials are individually identifiable

Every credential accepted by an admin surface SHALL be individually identifiable —
issued to one named caller, attributable in every audit event by its identifier —
and SHALL be revocable and rotatable without disturbing other callers' credentials.
A deployment SHALL be able to hold multiple concurrently valid credentials per
surface. No audit event SHALL attribute an action to an anonymous or shared
credential.

#### Scenario: Two callers are distinguishable in the ledger

- **WHEN** two different callers each perform an administrative mutation
- **THEN** the resulting audit events carry two different credential identifiers

#### Scenario: One caller's revocation leaves others working

- **WHEN** one caller's credential is revoked
- **THEN** that credential is rejected on subsequent calls while every other
  caller's credential continues to work

### Requirement: An asserted operator is recorded but confers nothing

The system SHALL accept an optional operator assertion from an authenticated admin
caller naming the human on whose behalf it acts, SHALL record the assertion
verbatim in the audit event marked as caller-asserted, and SHALL NOT let it
influence authentication, authorization, or the outcome of the action in any way.

#### Scenario: Asserted operator lands in the event

- **WHEN** an authenticated caller performs a mutation and asserts an operator
- **THEN** the audit event records both the credential identifier and the asserted
  operator, with the operator marked as asserted

#### Scenario: An assertion cannot authorize

- **WHEN** a caller presents an invalid credential together with an operator
  assertion
- **THEN** the request is rejected exactly as it would be without the assertion

### Requirement: Denied admin access is recorded

The system SHALL record an audit event for every denied request on an admin surface
— both a rejected authentication attempt and an authenticated action refused by
authorization. An authentication denial SHALL carry the time, surface, source, and
the fact that a credential was absent or invalid — without recording the presented
credential material. An authorization denial SHALL carry the time, surface, source,
the authenticated actor's identity, the attempted action, and the machine-readable
decision reason. A failure to record a denial SHALL never convert the denial into
an acceptance.

#### Scenario: A failed authentication leaves a trace

- **WHEN** a request with a missing or invalid credential is rejected by an admin
  surface
- **THEN** a denial event is recorded with time, surface, and source, and the
  presented credential value appears nowhere in it

#### Scenario: An authorization refusal leaves an attributed trace

- **WHEN** an authenticated actor's action is refused because its grant lacks the
  required scope
- **THEN** a denial event is recorded with time, surface, source, the actor's
  identity, the attempted action, and the decision reason

#### Scenario: A failed denial write stays a denial

- **WHEN** recording an authorization denial fails
- **THEN** the request remains refused and the recording failure is surfaced
  operationally

### Requirement: Idempotent replays are audited as replays

The system SHALL record an audit event for a mutating call answered by idempotent
replay, and the event SHALL be distinguishable from the event of the original
creation.

#### Scenario: Replay is visible in the ledger

- **WHEN** a create call replays a previously used idempotency key
- **THEN** an audit event is recorded marking the outcome as a replay of the
  original resource, not a new creation

### Requirement: The ledger is append-only with a governed retention window

Audit events SHALL be immutable once recorded: no admin surface SHALL offer any
operation that alters or deletes an event, and the storage-level ability to modify
or remove events SHALL be withheld from the identities the admin services run as.
Events SHALL remain available for a configurable retention period whose minimum
satisfies the platform's compliance audit window, and removal of events older than
the retention period SHALL be the only permitted removal.

#### Scenario: No mutation path exists for events

- **WHEN** any request attempts to modify or delete an audit event through an admin
  surface
- **THEN** no such operation exists and nothing is altered

#### Scenario: Events survive through the retention window

- **WHEN** an audit event is older than any operational rollover but younger than
  the retention period
- **THEN** it remains retrievable via the audit query surface

### Requirement: The ledger is queryable and exportable for review

Each admin surface SHALL expose, under its own authentication, a read surface over
its audit events filterable at least by time range, acting credential, and target —
and an export of events in a machine-readable form suitable for external audit
consumers. The read surface SHALL be read-only.

#### Scenario: An auditor scopes a review

- **WHEN** an authenticated reviewer queries events for one target resource over a
  time range
- **THEN** exactly the matching events are returned in time order

#### Scenario: Evidence leaves the system intact

- **WHEN** a reviewer exports events for the audit period
- **THEN** a machine-readable export of those events is produced and the ledger is
  unchanged

### Requirement: The bootstrap grant is audited

The system SHALL record an audit event when the break-glass bootstrap mechanism
grants the initial administrative role at startup, identifying the granted subject
and marking the actor as the bootstrap mechanism. A startup where the bootstrap
grant does not fire (an admin already exists) SHALL NOT produce a grant event.

#### Scenario: Break-glass leaves a trace

- **WHEN** the bootstrap mechanism grants the initial admin role at startup
- **THEN** an audit event records the granted subject with the bootstrap mechanism
  as the actor

#### Scenario: A no-op bootstrap is silent

- **WHEN** the service starts and an administrator already exists
- **THEN** no bootstrap grant event is recorded
