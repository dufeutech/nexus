//! The Routing Store port (RFC §3.10/§3.11) and the cache-invalidation feed port
//! (RFC C16) — the abstract capabilities core needs, with NO vendor concretion
//! (rules §2). An adapter crate implements these against a concrete database;
//! core and the services depend only on the traits.

use std::error::Error;

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::auth::AuthPolicy;
use crate::domain::TenantConfig;

pub type BoxError = Box<dyn Error + Send + Sync>;

/// A stored domain mapping as the control plane sees it (RFC §3.13): which tenant
/// owns it, whether it is a wildcard, and whether it is verified. Unlike the
/// hot-path `lookup_domain`, this reads a row regardless of verification state —
/// the lifecycle (declare/verify) needs to see pending rows too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRecord {
    pub tenant_id: String,
    pub wildcard: bool,
    pub verified: bool,
}

/// A live ownership-proof challenge (RFC C4): the minted token and whether it has
/// passed its time-to-live. The challenge name is derived (see
/// `crate::verify::challenge_name`), not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub domain: String,
    pub token: String,
    pub expired: bool,
}

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

    /// Read a domain row regardless of verification state (RFC C3): lets the
    /// lifecycle detect a cross-tenant claim and an idempotent re-declare. `None`
    /// if the domain is unknown.
    async fn get_domain(&self, domain: &str) -> Result<Option<DomainRecord>, BoxError>;

    /// Count the domains a tenant holds — **verified plus pending** (RFC C3/I6),
    /// the figure the quota gate compares against the plan limit.
    async fn count_domains_for_tenant(&self, tenant_id: &str) -> Result<u32, BoxError>;

    /// The pending (unverified) domains, for the periodic verification poll
    /// (RFC C4). Order is unspecified.
    async fn pending_domains(&self) -> Result<Vec<String>, BoxError>;

    /// Expire pending (unverified) domains older than `ttl_secs` (RFC C3): an
    /// abandoned declare is removed, freeing its quota slot and dropping out of
    /// the verification poll. Returns the removed domain keys. A pending domain
    /// never routed, so its removal changes no resolution/authorization outcome
    /// and MUST NOT trigger an invalidation.
    async fn expire_pending_domains(&self, ttl_secs: i64) -> Result<Vec<String>, BoxError>;

    // --- per-route auth policy (RFC N4) ------------------------------------- //

    /// Load a tenant's route-protection policy (RFC N4). A hot-path read folded
    /// into the router's decision miss-load. Returns the pass-through default
    /// ([`AuthPolicy::default`]) when the tenant has no rules — absence of a
    /// policy is "public", never an error, so no row needs to exist for a site to
    /// work.
    async fn get_auth_policy(&self, tenant_id: &str) -> Result<AuthPolicy, BoxError>;

    /// Create or update one path-prefix rule for a tenant (control-plane write).
    /// The per-tenant default is the rule with `prefix = "/"`.
    async fn upsert_auth_route(
        &self,
        tenant_id: &str,
        prefix: &str,
        required: bool,
    ) -> Result<(), BoxError>;

    /// Remove one path-prefix rule (idempotent — missing is not an error).
    async fn delete_auth_route(&self, tenant_id: &str, prefix: &str) -> Result<(), BoxError>;
}

/// The ownership-proof challenge store (RFC C4). Kept distinct from the routing
/// store so the challenge lifecycle (a control-plane concern) never touches the
/// hot read path; an adapter MAY back both with one technology (rules §2).
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Idempotently obtain the challenge for a domain (RFC C3 idempotence): if a
    /// live (unexpired) challenge exists, return it unchanged; if none exists, or
    /// the existing one has expired, mint a fresh token with the given TTL and
    /// return that. Re-declaring a pending domain therefore yields the SAME
    /// challenge until it expires, then a re-issued one (RFC C4: re-issuable).
    async fn mint_or_get_challenge(
        &self,
        domain: &str,
        tenant_id: &str,
        ttl_secs: i64,
    ) -> Result<Challenge, BoxError>;

    /// Read the current challenge with its expiry computed, if any.
    async fn get_challenge(&self, domain: &str) -> Result<Option<Challenge>, BoxError>;

    /// Retire a challenge on successful verification (idempotent — missing is not
    /// an error).
    async fn delete_challenge(&self, domain: &str) -> Result<(), BoxError>;
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
