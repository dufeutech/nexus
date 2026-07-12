## ADDED Requirements

### Requirement: Resolution caching is optional and off by default
The system SHALL treat api-key resolution caching as an explicitly enabled option, and when it is not enabled the observable behavior SHALL be identical to resolving every request against the live store.

#### Scenario: Disabled by default
- **WHEN** no operator has enabled resolution caching
- **THEN** each api-key request is resolved against the live store, and revocation or expiry takes effect on the next request exactly as if no cache existed

#### Scenario: Enabled by explicit configuration
- **WHEN** an operator enables resolution caching
- **THEN** the system may serve a subsequently presented, still-valid key from a cached resolution instead of re-resolving it against the live store

### Requirement: Only valid resolutions are cached, and doubt fails to the live store
The system SHALL cache only the resolution of a key that is currently present, active, and unexpired, and SHALL NOT cache the absence, invalidity, or rejection of a key; on any uncertainty it SHALL fall through to a live resolution rather than admit or reject from cache.

#### Scenario: Unknown or invalid key is never cached
- **WHEN** a presented key does not resolve to a valid, active, unexpired authority
- **THEN** the negative outcome is not stored, and a later request presenting that key is resolved against the live store

#### Scenario: Uncertainty resolves live
- **WHEN** a resolution cannot be served with confidence from cache
- **THEN** the system resolves the key against the live store and admits the caller only on a live match

### Requirement: Expiry is enforced regardless of caching
The system SHALL reject a key once it is expired even when a resolution for that key is held in cache, so caching never extends a key's usable lifetime past its expiration.

#### Scenario: Cached key past expiry is rejected
- **WHEN** a key whose resolution is held in cache is presented after its expiration time
- **THEN** the caller resolves to no authority and is rejected

### Requirement: Live revocation is preserved when caching is enabled
The system SHALL ensure that revoking or rotating a key takes effect within seconds even while resolution caching is enabled, by invalidating the affected key's cached resolution in response to a change signal from the store.

#### Scenario: Revoked key stops working within seconds
- **WHEN** a key with a cached resolution is revoked
- **THEN** the system invalidates that key's cached resolution and subsequent requests presenting the key are rejected within seconds

#### Scenario: Rotation does not let the superseded secret persist via cache
- **WHEN** a key is rotated
- **THEN** the superseded secret's cached resolution is invalidated within seconds and no longer admits a caller

#### Scenario: Only the affected key is invalidated
- **WHEN** a single key changes state
- **THEN** cached resolutions for other, unaffected keys remain usable

### Requirement: Staleness is bounded even if a change signal is missed
The system SHALL bound how long a cached resolution can be served without confirmation from the store, so that a lost or missed change signal cannot let a stale resolution persist indefinitely.

#### Scenario: Missed signal self-heals
- **WHEN** a change signal for a revoked key is not delivered
- **THEN** the cached resolution still stops being served within a bounded time and the key is re-resolved against the live store

### Requirement: Cache capacity is bounded to the working set
The system SHALL bound the number of cached resolutions to a configured capacity independent of the total number of issued keys, retaining actively used keys and shedding idle ones, so cache memory scales with active traffic rather than with the size of the keyspace.

#### Scenario: Capacity does not grow with the keyspace
- **WHEN** far more keys exist than the configured capacity, but only a small subset are actively presenting requests
- **THEN** the actively used keys are served from cache and the cache does not grow beyond its configured capacity

### Requirement: Cache activity is observable
The system SHALL expose observable measures of resolution-cache hits, misses, and invalidations so operators can confirm the cache is effective and reason about revocation propagation.

#### Scenario: Operators can observe cache effect
- **WHEN** resolution caching is enabled and serving traffic
- **THEN** hits, misses, and invalidations are exposed as observable metrics
