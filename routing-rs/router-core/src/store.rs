//! The Routing Store port (RFC §3.10/§3.11) and the cache-invalidation feed port
//! (RFC C16) — the abstract capabilities core needs, with NO vendor concretion
//! (rules §2). An adapter crate implements these against a concrete database;
//! core and the services depend only on the traits.

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::domain::TenantConfig;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Abstract routing store: point lookups by domain and tenant on the request
/// path (no scans, RFC §3.10), plus the control-plane write surface (RFC §3.13).
///
/// `lookup_domain` is the hot-path read (on a cache miss): a point read by the
/// **normalized** domain key. The router does at most two — one exact, then one
/// wildcard-parent (RFC C14). Only **verified** mappings resolve (RFC C16):
/// an unverified domain MUST NOT resolve to a tenant on protected routes.
#[async_trait]
pub trait RoutingStore: Send + Sync {
    /// Resolve a normalized domain to its owning tenant id, if a *verified*
    /// mapping exists. `wildcard = false` matches an exact custom domain/subdomain;
    /// `wildcard = true` matches a wildcard registered against the parent domain.
    async fn lookup_domain(&self, domain: &str, wildcard: bool)
        -> Result<Option<String>, BoxError>;

    /// Load a tenant's config (the routing value). `None` if absent.
    async fn get_tenant(&self, tenant_id: &str) -> Result<Option<TenantConfig>, BoxError>;

    // --- control-plane write surface (RFC §3.13) ---------------------------- //

    /// Create or update a tenant config.
    async fn upsert_tenant(&self, cfg: &TenantConfig) -> Result<(), BoxError>;

    /// Create or update a domain → tenant mapping.
    async fn upsert_domain(
        &self,
        domain: &str,
        tenant_id: &str,
        wildcard: bool,
        verified: bool,
    ) -> Result<(), BoxError>;

    /// Set a domain's ownership-verification flag (RFC C16: verify ownership).
    async fn set_domain_verified(&self, domain: &str, verified: bool) -> Result<(), BoxError>;

    /// Remove a domain mapping (idempotent — missing is not an error).
    async fn delete_domain(&self, domain: &str) -> Result<(), BoxError>;

    /// The domains owned by a tenant — used by the control plane to publish the
    /// precise invalidations for a tenant-config change.
    async fn domains_for_tenant(&self, tenant_id: &str) -> Result<Vec<String>, BoxError>;
}

/// A live invalidation feed (RFC C16): the control plane publishes the affected
/// **normalized domain key** on every mutation; resolvers evict that key from
/// every cache tier so they converge promptly. The payload is the domain string.
pub type InvalidationFeed = BoxStream<'static, Result<String, BoxError>>;

/// The capability of subscribing to control-plane invalidations. Kept distinct
/// from the store so a different transport (a message bus, a poll) is an adapter
/// swap, never a core change.
#[async_trait]
pub trait Invalidations: Send + Sync {
    /// Open a live invalidation feed. Callers reopen on error.
    async fn subscribe(&self) -> Result<InvalidationFeed, BoxError>;
}
