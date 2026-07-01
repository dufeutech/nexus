# membership-projection-sync

## Purpose

Keep the identity plane's membership projection converged to the routing-side source of
record: propagate membership changes to the projection within seconds, self-heal missed
signals via a periodic reconcile, and preserve one writer per store — so live acting-scope
resolution sees current membership state without a new authentication token.

## Requirements

### Requirement: A membership change propagates to the identity projection within seconds

The system SHALL reflect a membership change at the source of record — a grant,
modification, or revocation for a subject — in the identity plane's membership projection
for that subject within seconds, so live acting-scope resolution sees the new state
without a new authentication token. The projection SHALL converge to the
**source-of-record** state for the subject, not merely apply the payload of a single
signal.

#### Scenario: A granted membership becomes resolvable
- **WHEN** a membership is created for `sub` at the source of record
- **THEN** the identity projection for `sub` SHALL, within seconds, include that
  membership so acting-scope resolution authorizes the subject into that workspace

#### Scenario: A revoked membership stops resolving
- **WHEN** a membership for `sub` is deleted at the source of record
- **THEN** the identity projection for `sub` SHALL, within seconds, no longer include
  that membership, and acting-scope resolution SHALL fail closed for that workspace

### Requirement: Propagation self-heals when a real-time signal is missed

The real-time change signal SHALL be treated as best-effort. The system SHALL run a
periodic reconcile that re-derives each subject's projected memberships from the source
of record, so a dropped or unobserved signal converges within a bounded staleness window
rather than leaving the projection permanently wrong.

#### Scenario: A dropped signal converges via the backstop
- **WHEN** a membership change occurs but its real-time signal is never observed by the
  consumer (e.g. the consumer was down)
- **THEN** the next reconcile pass SHALL re-merge the source-of-record memberships into
  the projection so it matches the source of record

#### Scenario: Existing memberships are backfilled on first run
- **WHEN** the projection sync runs for the first time against a store that already holds
  source-of-record memberships with no corresponding projected memberships
- **THEN** the reconcile pass SHALL merge those existing memberships into the projections
  (no separate one-off migration is required)

### Requirement: Projection sync never clobbers memberships on unrelated updates

Writing the identity projection for a subject SHALL preserve that subject's projected
memberships whenever the write is driven by an unrelated identity-attribute or role
change. A projection write MUST NOT zero or drop memberships as a side effect of updating
other fields.

#### Scenario: An identity-attribute update preserves memberships
- **WHEN** a subject's identity attributes or roles change and the projection is
  rewritten, while the subject's source-of-record memberships are unchanged
- **THEN** the rewritten projection SHALL retain the subject's memberships unchanged

### Requirement: The source of record remains authoritative and singly owned

The routing-side membership store SHALL remain the single source of record for
memberships; the identity projection SHALL be a derived read-model. Only the identity
plane SHALL write the identity projection — the source-of-record side SHALL emit a change
signal but SHALL NOT write the projection directly, preserving one writer per store.

#### Scenario: The signal carries identity, not authority
- **WHEN** a change signal is emitted for a membership change
- **THEN** the consumer SHALL re-read the source of record for the affected subject to
  derive the projected memberships, rather than trusting the signal payload as the new
  authoritative state
