## Why

API keys are the **machine/app identity**: an app authenticates with one stable key and drives sustained, high-RPS traffic. Unlike the human path (self-validating JWT, no DB) and unlike the platform service path (a small resident registry warmed by a change feed), every api-key request today does an HMAC + a **live indexed Postgres SELECT of the same row** against a deliberately-tiny read-only pool. The creator's Profile and the signed contract are already cached downstream, so this resolve SELECT is the one cost that does **not** collapse on repeats — it is the remaining per-request DB hit and pool-contention point on the machine hot path, and it scales with request volume rather than with the number of distinct keys.

## What Changes

- Introduce an **opt-in, bounded working-set cache** in the identity sidecar for the api-key resolve step: presented-secret hash → resolved candidate. It caches the small set of keys *actively making traffic*, not the (unbounded) full keyspace.
- **Default OFF.** When disabled, behavior is byte-for-byte the status quo (a fresh, fail-closed SELECT per request; revocation effective on the next request). Enabling it is a deliberate operational choice via configuration.
- When enabled, keep revocation/expiry **live within seconds** by consuming the existing `api_key_changes` change feed to **evict the single affected entry** (targeted invalidation), with a bounded time-to-live and a poll/TTL self-heal fallback for any dropped notification. A cached entry SHALL still be rejected once expired.
- Cache **only positive resolves of currently-valid keys** (fail-closed); a miss, an expired entry, or any doubt falls through to the live SELECT. Invalid/unknown keys are **not** cached.
- Emit observability for cache hits, misses, and evictions, consistent with existing sidecar cache metrics.

Non-goals (explicitly out of scope): negative caching / a credential-stuffing shield (a hit-only cache does nothing for it — a distinct concern with opposite pressures); caching the platform service-token path (already resident); any change to the hash/pepper construction or to key issuance.

## Capabilities

### New Capabilities
- `apikey-resolve-cache`: An optional, fail-closed cache of api-key resolutions on the sidecar hot path. Owns the observable contract of the cache: opt-in and default-off; positive-only, expiry-respecting entries; bounded capacity with working-set eviction; and preservation of the live-revocation guarantee via change-feed-driven targeted invalidation with a self-healing fallback. The **cache/eviction store** and the **change-feed consumption** are the reliability-critical concerns whose realization is a build-vs-adopt decision, deferred to `/opsx:decide`.

### Modified Capabilities
<!-- None. `customer-api-keys` already requires revocation "within seconds", which this
     change must honor but does not alter. This capability adds a new, optional behavior
     layer beneath that contract rather than changing it. -->

## Impact

- **Code**: `identity-rs/sidecar` (a resolve-cache decorator around the api-key reader, feed-listener task wired in the sidecar startup/watch path, config parsing, metrics). `identity-rs/core` stays DB- and cache-agnostic — the cache isolates behind the existing `ApiKeyReader` port.
- **Config**: new opt-in environment knobs (enable flag, TTL, max capacity, poll fallback) mirroring the existing contract-cache configuration style; default-off. Documented in the deploy compose/README and Helm values.
- **Data / infra**: consumes the already-shipped `api_key_changes` NOTIFY channel and `identity.api_keys` table — no schema change. No new external service (in-process cache).
- **Behavior contract**: honors `customer-api-keys` (revocation within seconds) and `identity-revocation-integrity`; when disabled, no behavioral change at all.
