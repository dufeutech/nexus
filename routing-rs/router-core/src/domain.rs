//! The canonical routing-plane value types: the finite backend-pool set, the
//! Tenant Config (the routing store's value), and the Routing Decision the edge
//! data plane enacts. Field identifiers are normalized lower `snake_case`
//! (RFC §3.8). Vendor-free (rules §2).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::auth::AuthPolicy;

/// One backend pool selector: the stable wire name shared by the `target_pool`
/// column and the edge data plane's route header (`x-route-pool`). It is a
/// **validated name**, not a free string — membership in the allowed set is
/// enforced by [`PoolSet::parse`] at the write boundary; the read path trusts a
/// value it previously validated. Serialized transparently as that bare string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pool(String);

impl Pool {
    /// Wrap a pool name. This does NOT validate membership — go through
    /// [`PoolSet::parse`] for admin/stored input; use this only for a name the
    /// store previously wrote (already validated) or a test fixture.
    pub fn new(name: impl Into<String>) -> Self {
        Pool(name.into())
    }

    /// The stable wire identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The **data-driven** allow-list of backend pools (RFC C15, decision 13). The
/// set is LOADED FROM CONFIGURATION, never compiled in (mirrors [`crate::plan::
/// PlanLimits`]; rules §1.3/§5: no embedded constants in logic) — so adding a pool
/// is a config change plus an edge-cluster change, NOT a recompile. It is still
/// **finite and reviewed**: configuration never invents a network destination at
/// request time, it only declares which of a vetted set a tenant may select. The
/// service builds this from config and supplies a conservative default; this
/// module holds only the type and the membership decision.
#[derive(Debug, Clone, Default)]
pub struct PoolSet {
    allowed: BTreeSet<String>,
}

impl PoolSet {
    pub fn new(allowed: BTreeSet<String>) -> Self {
        Self { allowed }
    }

    /// Whether a name is in the allow-list.
    pub fn contains(&self, name: &str) -> bool {
        self.allowed.contains(name)
    }

    /// Validate a stored/admin-supplied selector against the allow-list. `None`
    /// for an unknown pool — the caller MUST reject rather than invent a
    /// destination (the same fail-closed contract the old compiled `parse` had).
    pub fn parse(&self, s: &str) -> Option<Pool> {
        if self.allowed.contains(s) {
            Some(Pool::new(s))
        } else {
            None
        }
    }

    /// The allowed names, sorted — for diagnostics and error messages.
    pub fn names(&self) -> Vec<&str> {
        self.allowed.iter().map(String::as_str).collect()
    }
}

/// The routing store's value, keyed by tenant identifier (RFC §3.11): the target
/// backend selector (from the finite pool set), a plan, and feature flags.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantConfig {
    pub tenant_id: String,
    pub plan: String,
    pub target_pool: Pool,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// The resolved selection the edge data plane enacts (RFC §3.12): one backend
/// pool plus the trusted tenant annotations attached as request metadata. The
/// plane only resolves and annotates — the data plane does the forwarding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingDecision {
    pub tenant_id: String,
    pub plan: String,
    pub pool: Pool,
    #[serde(default)]
    pub features: Vec<String>,
    /// The tenant's per-route authentication policy (RFC N4). Carried on the
    /// cached decision so it rides the existing domain-keyed invalidation (a
    /// policy change invalidates the tenant's domains, evicting this value), and
    /// so the per-request emit needs no second lookup — only the request path.
    /// `#[serde(default)]` keeps a pre-N4 cached value (no `auth` block) readable
    /// as the pass-through default.
    #[serde(default)]
    pub auth: AuthPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PoolSet {
        PoolSet::new(
            ["application", "api", "assets"]
                .into_iter()
                .map(String::from)
                .collect(),
        )
    }

    #[test]
    fn parse_accepts_allowed_and_rejects_unknown() {
        let pools = sample();
        assert_eq!(pools.parse("api").map(|p| p.as_str().to_string()), Some("api".into()));
        assert!(pools.parse("checkout").is_none()); // not in this set -> rejected
        assert!(pools.parse("").is_none());
    }

    #[test]
    fn empty_set_rejects_everything() {
        // Fail-closed: an unconfigured set never invents a destination.
        let pools = PoolSet::default();
        assert!(pools.parse("application").is_none());
    }

    #[test]
    fn names_are_sorted_for_diagnostics() {
        assert_eq!(sample().names(), vec!["api", "application", "assets"]);
    }

    #[test]
    fn pool_serializes_as_a_bare_string() {
        // #[serde(transparent)] — the wire form is the plain name, matching the
        // x-route-pool header and the target_pool column.
        let p = Pool::new("api");
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"api\"");
        let back: Pool = serde_json::from_str("\"api\"").unwrap();
        assert_eq!(back, p);
    }
}
