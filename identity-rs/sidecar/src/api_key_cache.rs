//! Opt-in, bounded working-set cache for the api-key resolve step (`apikey-resolve-cache`).
//!
//! WHY (design.md): an app on an api-key hammers ONE key row thousands of times/sec. The
//! profile and contract caches already collapse the downstream repeat cost, leaving the
//! resolve SELECT as the only per-request DB hit on the machine hot path. The set of keys
//! *actively presenting traffic* is tiny even though the keyspace is unbounded, so a
//! **bounded** cache of recently-resolved keys captures nearly all the benefit while
//! staying memory-bounded.
//!
//! Build-vs-adopt (decide gate): the tier is `moka` **in-process** — the same house
//! pattern as [`crate::token_cache::ContractTokenCache`], never Redis (a network hop on a
//! fail-closed auth step defeats the purpose and adds a failure mode). This sits on the
//! ext_proc hot path in front of every request; an in-process read is nanoseconds and
//! cannot fail-open on a network blip.
//!
//! Safety invariants this module upholds (conforms to `customer-api-keys` +
//! `identity-revocation-integrity`):
//!   - **Positive-only + fail-closed.** Only a resolution of a currently-valid key is
//!     stored; a miss, an unknown/invalid key, or any error is NEVER cached (no negative
//!     cache) and falls through to the live reader.
//!   - **Expiry-safe.** Each cached entry carries the key's own `expires_at`; a hit past
//!     it is treated as a miss (evict → live-resolve → reject), so caching never extends a
//!     key's usable life past expiration.
//!   - **Revocation-live.** A change-feed signal evicts ONLY the affected key's entry via a
//!     `key_id → key_hash` reverse index (the NOTIFY payload is `key_id`, the cache is
//!     keyed by `key_hash`), so revoke/rotate take effect within seconds; unaffected
//!     entries stay usable.
//!   - **Bounded + self-healing.** Capacity is bounded to the working set (moka eviction);
//!     the TTL is the staleness ceiling that self-heals a dropped NOTIFY.

use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;

use identity_core::api_key::{ApiKeyCandidate, ApiKeyReader};
use identity_core::store::BoxError;

use crate::state::{now_secs, METRICS};

/// A cached positive resolution. The candidate carries the key's `expires_at`
/// (epoch secs, `None` = no expiry), so expiry is enforced on a hit without a re-read.
#[derive(Clone)]
struct CachedResolve {
    candidate: ApiKeyCandidate,
}

/// The bounded working-set cache, shared by the resolve decorator and the change-feed
/// eviction listener. Cheap to `Clone` (moka shares one inner), so a clone hands the
/// listener the SAME cache the decorator reads.
#[derive(Clone)]
pub(crate) struct ApiKeyResolveCache {
    /// presented-secret hash → resolved candidate. TTL = the staleness ceiling.
    entries: Cache<String, CachedResolve>,
    /// key_id → key_hash reverse index, so a `key_id`-only change signal can address the
    /// single hashed entry without widening the NOTIFY payload or ever enumerating the
    /// keyspace. Bounded + TTL'd alongside `entries`.
    id_index: Cache<String, String>,
}

impl ApiKeyResolveCache {
    /// Build a cache bounded to `max_capacity` recently-used keys, each entry living at
    /// most `ttl` (the staleness ceiling). Both maps share the same bounds.
    pub(crate) fn new(max_capacity: u64, ttl: Duration) -> Self {
        Self {
            entries: Cache::builder().max_capacity(max_capacity).time_to_live(ttl).build(),
            id_index: Cache::builder().max_capacity(max_capacity).time_to_live(ttl).build(),
        }
    }

    /// Resolve `key_hash` through the cache, falling to `inner` on a miss/expiry. `now`
    /// (epoch secs) is injected for testability. Positive-only + fail-closed: only a
    /// currently-valid key is cached; a miss, an expired entry, an unknown key, or an error
    /// falls through to `inner` and is never stored as a negative.
    async fn resolve_through(
        &self,
        inner: &dyn ApiKeyReader,
        key_hash: &str,
        now: i64,
    ) -> Result<Option<ApiKeyCandidate>, BoxError> {
        if let Some(entry) = self.entries.get(key_hash) {
            // Expiry is enforced regardless of caching: a hit whose key is past its own
            // expiry is treated as a miss (evict → live-resolve → reject), so a cached
            // entry never extends a key's usable life past expiration.
            if entry.candidate.expires_at.is_none_or(|exp| exp > now) {
                METRICS.apikey_resolve_cache_hits.add(1, &[]);
                return Ok(Some(entry.candidate));
            }
            self.entries.invalidate(key_hash);
        }
        METRICS.apikey_resolve_cache_misses.add(1, &[]);
        let resolved = inner.lookup(key_hash).await?;
        if let Some(candidate) = resolved.as_ref() {
            // Cache ONLY a positive resolve of a currently-valid key. Record the reverse
            // index first so a concurrent eviction can always find the entry it maps to.
            self.id_index.insert(candidate.key_id.clone(), key_hash.to_owned());
            self.entries
                .insert(key_hash.to_owned(), CachedResolve { candidate: candidate.clone() });
        }
        Ok(resolved)
    }

    /// Evict the entry for `key_id` in response to a change signal (revoke / rotate / any
    /// mutation). Only the affected key is dropped — unaffected entries stay usable. A
    /// `key_id` we never cached is a no-op (it is not in our working set).
    pub(crate) fn invalidate_key_id(&self, key_id: &str) {
        if let Some(hash) = self.id_index.get(key_id) {
            self.entries.invalidate(&hash);
            self.id_index.invalidate(key_id);
            METRICS.apikey_resolve_cache_evictions.add(1, &[]);
        }
    }
}

/// The `ApiKeyReader` decorator: wraps the live reader with an [`ApiKeyResolveCache`] so
/// `core` never learns a cache exists (the cache is a sidecar adapter behind the port).
/// Constructed only when the cache is enabled — disabled ⇒ the live reader is used
/// directly (byte-for-byte the resolve-per-request status quo).
pub(crate) struct CachingApiKeyReader {
    inner: Arc<dyn ApiKeyReader>,
    cache: ApiKeyResolveCache,
}

impl CachingApiKeyReader {
    pub(crate) fn new(inner: Arc<dyn ApiKeyReader>, cache: ApiKeyResolveCache) -> Self {
        Self { inner, cache }
    }
}

#[tonic::async_trait]
impl ApiKeyReader for CachingApiKeyReader {
    async fn lookup(&self, key_hash: &str) -> Result<Option<ApiKeyCandidate>, BoxError> {
        self.cache
            .resolve_through(self.inner.as_ref(), key_hash, now_secs().cast_signed())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::ApiKeyScope;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// A reader that counts live lookups and can be flipped to "revoked" (returns `None`),
    /// so tests can assert cache hits (no inner call) vs. misses (an inner call) and model
    /// revocation/expiry at the live layer.
    struct CountingReader {
        calls: AtomicUsize,
        candidate: Mutex<Option<ApiKeyCandidate>>,
    }

    impl CountingReader {
        fn new(candidate: Option<ApiKeyCandidate>) -> Self {
            Self { calls: AtomicUsize::new(0), candidate: Mutex::new(candidate) }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
        /// Model a revocation/expiry at the store: subsequent live lookups return `None`.
        fn revoke(&self) {
            *self.candidate.lock().unwrap() = None;
        }
    }

    #[tonic::async_trait]
    impl ApiKeyReader for CountingReader {
        async fn lookup(&self, _key_hash: &str) -> Result<Option<ApiKeyCandidate>, BoxError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.candidate.lock().unwrap().clone())
        }
    }

    fn candidate(expires_at: Option<i64>) -> ApiKeyCandidate {
        ApiKeyCandidate {
            key_id: "pak_1".to_owned(),
            creator_sub: "u-creator".to_owned(),
            scope: ApiKeyScope::new(vec!["ws-1".to_owned()]),
            expires_at,
        }
    }

    fn cache() -> ApiKeyResolveCache {
        // TTL far larger than any test's logical time so moka never evicts mid-test; the
        // expiry check is driven by the injected `now` instead.
        ApiKeyResolveCache::new(1000, Duration::from_hours(1))
    }

    #[tokio::test]
    async fn repeat_resolves_hit_cache_and_skip_the_live_reader() {
        // Task 6.2: one key presented N times resolves live ONCE, then serves from cache —
        // the DB resolve count collapses from N to 1.
        let inner = CountingReader::new(Some(candidate(None)));
        let cache = cache();
        let first = cache.resolve_through(&inner, "hash-a", 1000).await.unwrap();
        let second = cache.resolve_through(&inner, "hash-a", 1001).await.unwrap();
        assert_eq!(first.map(|c| c.key_id), Some("pak_1".to_owned()));
        assert_eq!(second.map(|c| c.key_id), Some("pak_1".to_owned()));
        assert_eq!(inner.calls(), 1, "the second resolve must be served from cache, not the live reader");
    }

    #[tokio::test]
    async fn unknown_key_is_never_cached() {
        // A negative outcome is not stored: a key that resolves to None hits the live
        // reader every time (no negative cache — a distinct, out-of-scope concern).
        let inner = CountingReader::new(None);
        let cache = cache();
        assert!(cache.resolve_through(&inner, "hash-x", 1000).await.unwrap().is_none());
        assert!(cache.resolve_through(&inner, "hash-x", 1001).await.unwrap().is_none());
        assert_eq!(inner.calls(), 2, "an unknown key must re-resolve live every time");
    }

    #[tokio::test]
    async fn revocation_via_targeted_eviction_stops_serving_within_the_signal() {
        // Tasks 6.3 / 6.4: a cached key is revoked (or its secret superseded by rotation).
        // The change-feed listener calls invalidate_key_id, which drops the single entry;
        // the next resolve goes live and — now revoked — is rejected. Other keys untouched.
        let inner = CountingReader::new(Some(candidate(None)));
        let cache = cache();
        // Warm the cache (1 live call), then confirm a hit (still 1).
        assert!(cache.resolve_through(&inner, "hash-a", 1000).await.unwrap().is_some());
        assert!(cache.resolve_through(&inner, "hash-a", 1000).await.unwrap().is_some());
        assert_eq!(inner.calls(), 1);
        // Revoke at the store AND deliver the change signal (payload = key_id).
        inner.revoke();
        cache.invalidate_key_id("pak_1");
        // The next resolve misses → live → None (rejected). The eviction forced a re-read.
        assert!(cache.resolve_through(&inner, "hash-a", 1000).await.unwrap().is_none());
        assert_eq!(inner.calls(), 2, "post-eviction resolve must re-read the live store");
    }

    #[tokio::test]
    async fn a_signal_for_another_key_leaves_this_entry_usable() {
        // "Only the affected key is invalidated": a change signal for an unrelated key_id
        // does not drop this entry, and an unknown key_id is a no-op.
        let inner = CountingReader::new(Some(candidate(None)));
        let cache = cache();
        assert!(cache.resolve_through(&inner, "hash-a", 1000).await.unwrap().is_some());
        cache.invalidate_key_id("pak_other"); // never cached → no-op
        assert!(cache.resolve_through(&inner, "hash-a", 1000).await.unwrap().is_some());
        assert_eq!(inner.calls(), 1, "an unrelated eviction must leave this entry served from cache");
    }

    #[tokio::test]
    async fn a_cached_key_past_its_expiry_is_rejected() {
        // Task 6.5: a key cached with expires_at=1060, presented at now=1070, is treated as
        // a miss and re-resolved live; the live store (past expiry) returns None → rejected.
        // Caching never extends the key's usable life past its expiration.
        let inner = CountingReader::new(Some(candidate(Some(1060))));
        let cache = cache();
        // Warm at now=1000 (before expiry): a normal positive resolve + cache.
        assert!(cache.resolve_through(&inner, "hash-a", 1000).await.unwrap().is_some());
        assert_eq!(inner.calls(), 1);
        // The key expires at the store; model that as the live reader now returning None.
        inner.revoke();
        // Presented at now=1070 (past expires_at): the cached entry is bypassed as expired,
        // forcing a live re-read that now rejects.
        assert!(cache.resolve_through(&inner, "hash-a", 1070).await.unwrap().is_none());
        assert_eq!(inner.calls(), 2, "a past-expiry hit must re-resolve live rather than serve the cached entry");
    }
}
