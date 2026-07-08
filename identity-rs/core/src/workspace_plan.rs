//! The workspace plan-tier port (`workspace-plan-tier` capability) — the abstract
//! capability the sidecar needs to resolve the acting workspace's **plan tier**, with
//! NO vendor concretion (rules §2). An adapter crate implements it against Postgres
//! (`routing.workspaces.plan`); core and the sidecar depend only on this trait.
//!
//! Plan tier is a nexus-owned, routing-plane workspace attribute (control-plane-written,
//! `DEFAULT 'free'`). The identity plane PROJECTS it read-only — exactly as it already
//! projects `routing.memberships` — so a box can drive storage-cap / feature policy from
//! a nexus-authored fact rather than a client hint. That set is resolved LIVE so an
//! upgrade/downgrade takes effect within seconds (revocation-consistent with membership
//! and suspension).
//!
//! **Opaque wire string (design R2):** `plan` is carried as a bare string. The canonical
//! vocabulary is nexus-owned via the config-driven `router-core::PlanLimits` and validated
//! at the control-plane WRITE boundary; the read path here does **not** re-validate it (it
//! trusts a value the write path already validated — mirroring the `membership kind` read
//! path). A workspace absent from the returned set resolves to NO plan, which a box treats
//! as not-provisioned (fail-soft, design D2).

use async_trait::async_trait;

use crate::store::BoxError;

/// One provisioned workspace and its current plan tier. `plan` is an opaque wire string
/// (design R2) — the reader does not interpret or validate it; the box maps it onto policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspacePlan {
    /// The workspace this plan applies to (`routing.workspaces.workspace_id`).
    pub workspace_id: String,
    /// The current plan tier (e.g. `free`, `pro`) — a nexus-authored opaque string.
    pub plan: String,
}

/// Read the **provisioned** workspace→plan set — the source of record for a workspace's
/// plan tier. Implemented by a read-only adapter over the routing store; consumed by the
/// sidecar, which holds the set resident and refreshes it on the change feed so a
/// plan change propagates within seconds.
///
/// A workspace missing from the returned set resolves to NO plan (fail-soft, design D2):
/// the sidecar omits the plan rather than substitute a default, and a box treats an
/// absent plan as not-provisioned. An `Err` is a transient resolution failure the caller
/// treats as "cannot decide" (keep the last known set), never as a disproof.
#[async_trait]
pub trait WorkspacePlanReader: Send + Sync {
    /// Every currently-provisioned workspace and its plan. An empty vec means "no
    /// workspaces resolved" (every workspace then resolves to no plan → omitted).
    async fn all_plans(&self) -> Result<Vec<WorkspacePlan>, BoxError>;
}
