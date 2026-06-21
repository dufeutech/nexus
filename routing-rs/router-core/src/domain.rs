//! The canonical routing-plane value types: the finite backend-pool set, the
//! Tenant Config (the routing store's value), and the Routing Decision the edge
//! data plane enacts. Field identifiers are normalized lower `snake_case`
//! (RFC §3.8). Vendor-free (rules §2).

use serde::{Deserialize, Serialize};

/// The **small, finite, pre-declared** set of backend pools (RFC C15,
/// decision 13). A tenant's target selects exactly one of these; configuration
/// MUST NOT introduce a new network destination at request time (no per-tenant
/// cluster explosion, no in-app proxy). Adding a pool is a deliberate change
/// here AND in the edge data plane's cluster set — never a runtime/config event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pool {
    Application,
    Api,
    Checkout,
    Assets,
}

impl Pool {
    /// The stable wire identifier (matches the edge data plane's route header
    /// value and the `target_pool` column).
    pub fn as_str(self) -> &'static str {
        match self {
            Pool::Application => "application",
            Pool::Api => "api",
            Pool::Checkout => "checkout",
            Pool::Assets => "assets",
        }
    }

    /// Parse a stored/admin-supplied selector into the finite set. `None` for an
    /// unknown pool — the caller MUST reject rather than invent a destination.
    pub fn parse(s: &str) -> Option<Pool> {
        match s {
            "application" => Some(Pool::Application),
            "api" => Some(Pool::Api),
            "checkout" => Some(Pool::Checkout),
            "assets" => Some(Pool::Assets),
            _ => None,
        }
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
}
