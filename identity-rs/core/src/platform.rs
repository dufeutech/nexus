//! The platform-service registry port (`platform-service-authz` capability) — the
//! abstract capability the sidecar needs to resolve a core service's platform
//! authority, with NO vendor concretion (rules §2). An adapter crate implements it
//! against Postgres (`platform.services`); core and the sidecar depend only on this
//! trait.
//!
//! A core platform service is authorized from a **platform-level permission set** it
//! owns, not from per-workspace membership (ADR-3). That set is resolved LIVE from the
//! registry so a revoke/permission change takes effect within seconds, and a service
//! absent (or inactive) resolves to NO authority — rejected, never admitted open
//! (`platform-service-authz` spec, fail-closed).
//!
//! The registry is SMALL (a handful of core services), so the reader returns the whole
//! active set in one call; the sidecar holds it resident and refreshes it on the live
//! change feed (unlike the billion-row Profile store, which is miss-loaded).

use async_trait::async_trait;

use crate::principal::PlatformScope;
use crate::store::BoxError;

/// One registered platform service: its stable id and the least-privilege permission
/// set it carries. Only ACTIVE services are ever surfaced by a [`PlatformServiceReader`]
/// (an inactive/revoked row is excluded — the fail-closed enforcement point, mirroring
/// [`crate::SourceMembershipReader`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformService {
    /// The service identity the infra-trust credential proves (e.g. the projected
    /// ServiceAccount `sub`, `system:serviceaccount:ns:name`).
    pub service_id: String,
    /// The platform permission set this service is authorized for.
    pub scope: PlatformScope,
}

/// Read the **active** platform-service registry — the source of record for a core
/// service's platform authority. Implemented by a read-only adapter over the platform
/// store; consumed by the sidecar, which holds the set resident and refreshes it on the
/// change feed so a revocation propagates within seconds.
///
/// **Fail-closed by contract:** an adapter MUST exclude non-active rows, so a service
/// missing from the returned set holds no authority. An `Err` is a transient resolution
/// failure the caller treats as "cannot decide" (keep the last known set / block a cold
/// start), never as a disproof.
#[async_trait]
pub trait PlatformServiceReader: Send + Sync {
    /// Every currently-active platform service. An empty vec means "no active
    /// services" (which resolves every service to no authority).
    async fn active_services(&self) -> Result<Vec<PlatformService>, BoxError>;
}
