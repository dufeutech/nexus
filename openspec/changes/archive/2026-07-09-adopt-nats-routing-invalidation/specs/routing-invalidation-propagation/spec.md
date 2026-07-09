## ADDED Requirements

### Requirement: Invalidation reaches every router instance

When routing source-of-truth changes, the invalidation SHALL propagate to every running
router instance's cache, independent of whether that instance shares the writer's local
signaling scope (for example, an instance serving a different region edge).

The affected routing key SHALL be evicted from each instance's cache so that the next
request for that key re-resolves from source-of-truth rather than serving the prior
cached decision.

#### Scenario: Invalidation delivered to a co-located instance

- **WHEN** a routing record changes and a router instance sharing the writer's local signaling scope is running
- **THEN** that instance evicts the cached decision for the affected key
- **AND** the next request for that key re-resolves from source-of-truth

#### Scenario: Invalidation delivered across a region edge

- **WHEN** a routing record changes and a router instance runs outside the writer's local signaling scope (a different region, replica, or failover target)
- **THEN** that instance still receives the invalidation and evicts the cached decision for the affected key
- **AND** it does not continue serving the stale decision until the TTL backstop alone would have expired it

### Requirement: Delivery is best-effort with a bounded-staleness backstop

Invalidation delivery SHALL be best-effort: a dropped, delayed, or duplicated signal MUST
NOT cause indefinitely incorrect routing.

Worst-case staleness for any cached routing decision SHALL remain bounded by the routing
cache time-to-live, which is the correctness floor when a signal is missed. A duplicate or
out-of-order signal SHALL be safe to apply (eviction is idempotent).

#### Scenario: A signal is dropped

- **WHEN** an invalidation signal for a key is never delivered to an instance
- **THEN** that instance serves the stale decision for at most the routing cache time-to-live
- **AND** re-resolves from source-of-truth once the entry expires

#### Scenario: A duplicate signal arrives

- **WHEN** the same invalidation for a key is delivered more than once to an instance
- **THEN** each delivery evicts the key with no additional observable effect beyond the first

### Requirement: Transport-agnostic eviction parity

The observable outcome of an invalidation SHALL be identical regardless of which configured
delivery transport carried it.

Switching the configured transport SHALL NOT change routing behavior, the set of keys
evicted for a given source-of-truth change, or the correctness backstop; it changes only the
delivery path.

#### Scenario: Same outcome under either transport

- **WHEN** the same routing record change occurs under two different configured delivery transports
- **THEN** the same routing key is evicted on every instance in both cases
- **AND** the subsequent re-resolution produces the same routing decision
