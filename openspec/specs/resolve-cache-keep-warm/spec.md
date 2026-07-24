# resolve-cache-keep-warm

## Purpose

Keep the resolution cache warm so steady-state traffic never pays a cache refill on the request
path. Once a key is resident and actively read, the service refreshes it in the background ahead of
its staleness deadline and answers every request from the value already held — so no live request
eats the latency of a synchronous store refill for a host the cache already knows. First-ever
lookups still resolve on demand, change-propagation (invalidation) still takes effect promptly, idle
keys still age out, and served values stay within a bounded staleness. This is the liveness
complement to resolution correctness and change-propagation: those decide *what* is served; this
decides that serving it never periodically re-cools on a user's request.

## Requirements

### Requirement: Resident entries never refill on the request path

An actively-read cache entry that is already resident MUST be refreshed without imposing the
refill on a live request. Once a key has been resolved and is being read repeatedly, the
service SHALL continue to answer every request for that key directly from the cached value,
including across the entry's staleness deadline, so that no request observes the latency of a
synchronous store fetch for a key the cache already holds.

#### Scenario: Read straddling the staleness deadline is served from cache

- **WHEN** a key is resolved, then read continuously at a steady rate across the moment its
  cached value passes its staleness deadline
- **THEN** every one of those reads is answered from the cached value
- **AND** no read triggers a synchronous store fetch on the request path

#### Scenario: Steady-state reads incur zero request-path refills

- **WHEN** a single key is read continuously for a duration spanning several staleness
  deadlines
- **THEN** the count of request-path store fetches after the initial population is zero

### Requirement: Refresh happens in the background ahead of staleness

The service SHALL refresh a resident, actively-read entry in the background before its cached
value would become unusable, replacing it in place. The background refresh MUST NOT block, delay,
or fail the concurrent request that observes the still-valid cached value. Concurrent refreshes of
the same key MUST be collapsed so that a burst of reads triggers at most one in-flight refresh per
key.

#### Scenario: Background refresh updates the value without blocking reads

- **WHEN** a resident key crosses its refresh point and a read arrives
- **THEN** the read is answered immediately from the current cached value
- **AND** a single background refresh is initiated
- **AND** subsequent reads observe the refreshed value once the refresh completes

#### Scenario: A refresh failure does not evict or fail requests

- **WHEN** a background refresh of a resident key fails
- **THEN** in-flight and subsequent reads are still answered from the last good cached value
- **AND** the failure does not surface as a request error

### Requirement: First-ever lookups and invalidations are unchanged

Keeping resident entries warm MUST NOT change how absent or explicitly-invalidated keys behave. A
key that has never been resolved, or one that has been evicted by a change-propagation signal, MUST
still be resolved on demand for the requesting caller. Idle keys that are no longer read MUST still
age out rather than being kept warm indefinitely.

#### Scenario: First-ever lookup resolves on demand

- **WHEN** a request arrives for a key the cache has never held
- **THEN** the key is resolved from the store for that request, as before

#### Scenario: Invalidated key is re-resolved

- **WHEN** a change-propagation signal invalidates a key and a request for it then arrives
- **THEN** the key is resolved from the store and the fresh value is served and cached

#### Scenario: Idle key is not kept warm

- **WHEN** a key stops being read for longer than its lifetime
- **THEN** it is no longer kept warm and eventually leaves the cache

### Requirement: Keep-warm timing derives from existing cache lifetime

The keep-warm behavior MUST NOT introduce a new externally-tunable configuration value. The point
at which a resident entry is refreshed SHALL be derived from the cache's already-configured entry
lifetime, so that operators tune a single lifetime value and the refresh timing follows from it.

#### Scenario: No new configuration surface

- **WHEN** the service is configured only with its existing cache lifetime setting
- **THEN** keep-warm is active with a refresh point derived from that lifetime
- **AND** no additional keep-warm-specific setting is required to enable it

### Requirement: Bounded staleness is preserved

Serving a resident value while it refreshes MUST NOT let a key drift arbitrarily stale. The value
handed to a request SHALL never be older than the entry lifetime plus the time to complete one
refresh; if a refresh cannot complete within the entry lifetime, the entry MUST fall back to the
existing on-demand resolution rather than serving an unboundedly old value.

#### Scenario: Value age stays within the lifetime-plus-one-refresh bound

- **WHEN** a resident key is read continuously and refreshes succeed
- **THEN** the value served is never older than the configured lifetime plus one refresh duration

#### Scenario: Persistent refresh failure falls back to on-demand resolution

- **WHEN** background refreshes for a key fail continuously past the entry lifetime
- **THEN** the entry stops being served as warm and the next request resolves it on demand
