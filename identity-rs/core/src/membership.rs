//! Workspace membership — the nexus-owned authorization edge. A typed
//! relationship (staff|customer) between a user and a workspace, carrying the
//! workspace-scoped role. The identity plane resolves it live and fail-closed to
//! decide the acting workspace the backend is told about (`x-workspace-id`).
//!
//! Resolution lives behind the [`MembershipResolver`] port so the storage can be
//! swapped (v1: denormalized into the Profile; later: a ReBAC engine) without
//! touching the sidecar — see the change's design ADR.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::store::BoxError;

/// How a user relates to a workspace. Emitted as `x-user-type`; the backend flips
/// staff-mode vs customer-mode on it.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MemberType {
    /// Operates the workspace (owner/admin/editor/…).
    Staff,
    /// Uses the workspace's app (tier/app-defined role).
    Customer,
}

impl MemberType {
    /// The stable wire value for the `x-user-type` header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Staff => "staff",
            Self::Customer => "customer",
        }
    }
}

/// One typed membership edge: the user's relationship to a single workspace. A
/// user holds a small set of these (few workspaces), denormalized into the
/// [`crate::Profile`] so the identity plane resolves the acting workspace in one
/// lookup. `role` is scoped to `(workspace, type)`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The stable workspace id this membership is for (never a domain string).
    pub workspace_id: String,
    /// Staff or customer.
    #[serde(rename = "type")]
    pub member_type: MemberType,
    /// The role scoped to `(workspace, type)` — e.g. `admin` for staff, a tier for
    /// a customer. Empty means "no explicit role" (still a member).
    #[serde(default)]
    pub role: String,
    /// Workspace-scoped entitlements, if any.
    #[serde(default)]
    pub entitlements: Vec<String>,
}

/// The resolved acting scope for an authenticated request: the authorized
/// workspace plus the user's type and role in it. Produced by a
/// [`MembershipResolver`] and emitted as `x-workspace-id` / `x-user-type` /
/// `x-user-role`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMembership {
    /// The authorized acting workspace.
    pub workspace_id: String,
    /// The user's relationship type to it.
    pub member_type: MemberType,
    /// The user's workspace-scoped role.
    pub role: String,
}

/// Resolve a subject's authorized relationship to a workspace. **Fail-closed:**
/// `Ok(None)` means "not an authorized member" (NOT an error); `Err` is a
/// transient resolution failure the caller must treat as "cannot decide" (block),
/// never as a disproof.
///
/// The v1 adapter reads the denormalized [`crate::Profile`]; a future adapter can
/// delegate to a ReBAC engine (OpenFGA/SpiceDB) without changing the sidecar.
#[async_trait]
pub trait MembershipResolver: Send + Sync {
    /// Resolve `(sub, workspace_id)` → the authorized membership, if any.
    async fn resolve(
        &self,
        sub: &str,
        workspace_id: &str,
    ) -> Result<Option<ResolvedMembership>, BoxError>;
}

/// Read the **source-of-record** memberships that back the `Profile.memberships`
/// projection. Implemented by a read-only adapter over the routing plane's
/// membership store; consumed by the membership-sync worker (real-time path) and
/// its reconcile backstop. Read-only by contract — the routing store remains the
/// single writer/source of record; the identity plane only projects it.
#[async_trait]
pub trait SourceMembershipReader: Send + Sync {
    /// The subject's currently-authorized memberships (the fail-closed projection
    /// set — an adapter MUST exclude non-active rows). An empty vec means "member of
    /// nothing" (e.g. every membership revoked), which clears the projection.
    async fn memberships_for(&self, sub: &str) -> Result<Vec<Membership>, BoxError>;

    /// Every subject that currently holds at least one membership. The backstop's
    /// enumeration input so it can converge/backfill all projections (paired with a
    /// scan of profiles that still carry stale memberships, to heal revoke-to-zero).
    async fn all_member_subjects(&self) -> Result<Vec<String>, BoxError>;
}
