//! The OPTIONAL shared L2 cache tier port (RFC §6 decision 9 / Shared Cache
//! Tier). It sits between the per-edge bounded L1 caches and the routing store
//! to raise aggregate hit rate and absorb miss-load fan-out — and MUST remain a
//! performance optimization, never a correctness dependency (the plane is
//! correct with L1 + the store alone). Vendor-free (rules §2); a concrete tier
//! (e.g. Redis) is an adapter.

use async_trait::async_trait;

use crate::domain::RoutingDecision;
use crate::store::BoxError;

#[async_trait]
pub trait SharedCache: Send + Sync {
    /// Read a cached decision by normalized domain key. `None` on a miss; an
    /// adapter error MUST be recoverable (the caller falls back to the store).
    async fn get(&self, key: &str) -> Result<Option<RoutingDecision>, BoxError>;

    /// Cache a decision with a staleness TTL (the L2 backstop). A "no tenant"
    /// result is NEVER stored (RFC §3.10) — only positive resolutions.
    async fn put(&self, key: &str, decision: &RoutingDecision, ttl_secs: u64)
        -> Result<(), BoxError>;

    /// Evict a key on a control-plane invalidation.
    async fn invalidate(&self, key: &str) -> Result<(), BoxError>;
}
