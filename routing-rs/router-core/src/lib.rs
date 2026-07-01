//! router-core — the language-agnostic tenant-routing domain, shared by the
//! tenant-router (request-time reads) and the control-plane (admin writes).
//!
//! This is the routing-plane instantiation of the RFC's shared Resolution Engine
//! (RFC decision 12): a key (the request host/domain) resolves to a value (the
//! owning tenant + a routing decision) via a bounded cache → optional shared L2 →
//! authoritative store, kept fresh by a control-plane invalidation feed. Holding
//! the decision shape, the host-normalization, and the store/cache **ports** in
//! ONE place is the invariant the rest of the plane depends on (rules §2, §5).
//!
//! No vendor concretion lives here (rules §2): Postgres, Redis, and the edge
//! transport are adapters that depend on these ports, never the reverse.

pub mod auth;
pub mod cache;
pub mod context;
pub mod domain;
pub mod geo;
pub mod normalize;
pub mod plan;
pub mod store;
pub mod verify;

pub use auth::{AuthPolicy, PathRule, RouteAuth};
pub use domain::{Pool, RoutingDecision, WorkspaceConfig};
pub use plan::{DomainLimit, PlanLimits, QuotaExceeded};
