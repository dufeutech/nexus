//! Accounts, Workspaces, and Memberships (nexus-owned-workspace-tenancy 2.1–2.4).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use opentelemetry::KeyValue;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use router_core::domain::WorkspaceConfig;
use router_core::store::{Membership, MembershipStore, OwnershipStore, RoutingStore, MEMBER_TYPES};

use crate::app::{internal, App, METRICS};
use crate::tenants::default_plan;

// --------------------------------------------------------------------------- //
// Accounts (ownership container) — nexus-owned-workspace-tenancy 2.1
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
pub(crate) struct AccountBody {
    account_id: String,
    /// The user this account is provisioned for — becomes its `owner` member.
    owner_sub: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    payer_ref: Option<String>,
}

/// Provision an account and its owner member (2.1). Idempotent: on repeat (e.g. a
/// re-run of first-signup provisioning) the account is left as-is and the owner
/// membership is re-asserted, so it is safe to call unconditionally on signup.
/// Trusted-broker model: the authenticated caller supplies the ids and owner sub.
pub(crate) async fn provision_account(State(s): State<App>, Json(body): Json<AccountBody>) -> Response {
    let created = match s
        .store
        .create_account(&body.account_id, &body.name, body.payer_ref.as_deref())
        .await
    {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    if let Err(e) = s.store.add_account_member(&body.account_id, &body.owner_sub, "owner").await {
        return internal(e);
    }
    METRICS.mutations.add(1, &[KeyValue::new("op", "provision_account")]);
    info!(account = %body.account_id, owner = %body.owner_sub, created, "account provisioned");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "account_id": body.account_id, "created": created })),
    )
        .into_response()
}

pub(crate) async fn get_account(State(s): State<App>, Path(id): Path<String>) -> Response {
    let account = match s.store.get_account(&id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "not found", "account_id": id })))
                .into_response();
        }
        Err(e) => return internal(e),
    };
    let members = match s.store.account_members(&id).await {
        Ok(m) => m,
        Err(e) => return internal(e),
    };
    (StatusCode::OK, Json(json!({ "account": account, "members": members }))).into_response()
}

// --------------------------------------------------------------------------- //
// Workspaces (the stable-ID routing pivot) — nexus-owned-workspace-tenancy 2.2
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
pub(crate) struct WorkspaceBody {
    workspace_id: String,
    /// Owning account. Supplied at create; OMITTED on a config-only update leaves
    /// ownership unchanged. An ownership CHANGE goes through `/transfer`, never here.
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default = "default_plan")]
    plan: String,
    target_pool: String,
    #[serde(default)]
    features: Vec<String>,
}

pub(crate) async fn upsert_workspace(State(s): State<App>, Json(body): Json<WorkspaceBody>) -> Response {
    // Same pool allow-list validation as the legacy alias (RFC C15, fail-closed).
    let Some(pool) = s.pools.parse(&body.target_pool) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid target_pool",
                "value": body.target_pool,
                "allowed": s.pools.names(),
            })),
        )
            .into_response();
    };
    // If an account was supplied, it MUST exist — check first so the FK surfaces as
    // a clean 404 instead of a raw 500.
    if let Some(account_id) = &body.account_id {
        match s.store.get_account(account_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "unknown_account", "account_id": account_id })),
                )
                    .into_response();
            }
            Err(e) => return internal(e),
        }
    }
    let cfg = WorkspaceConfig {
        workspace_id: body.workspace_id.clone(),
        plan: body.plan,
        target_pool: pool,
        features: body.features,
        updated_at: None,
    };
    if let Err(e) = s.store.upsert_workspace(&cfg).await {
        return internal(e);
    }
    // Assign ownership at create time (no staff reset — a new workspace has none).
    if let Some(account_id) = &body.account_id {
        match s.store.set_workspace_account(&body.workspace_id, account_id).await {
            Ok(true) => {}
            // We just upserted the row, so a no-match is unexpected — log, don't fail.
            Ok(false) => warn!(workspace = %body.workspace_id, "ownership set matched no row"),
            Err(e) => return internal(e),
        }
    }
    // A workspace change affects all of its domains — invalidate each precisely.
    match s.store.domains_for_workspace(&body.workspace_id).await {
        Ok(domains) => {
            for d in &domains {
                s.invalidate(d).await;
            }
            METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_workspace")]);
            info!(workspace = %body.workspace_id, invalidated = domains.len(), "workspace upserted");
        }
        Err(e) => warn!(error = %e, "domains_for_workspace failed; relying on TTL"),
    }
    (StatusCode::OK, Json(json!({ "result": "ok", "workspace_id": body.workspace_id }))).into_response()
}

pub(crate) async fn get_workspace(State(s): State<App>, Path(id): Path<String>) -> Response {
    match s.store.get_workspace(&id).await {
        Ok(Some(cfg)) => (StatusCode::OK, Json(serde_json::to_value(cfg).unwrap())).into_response(),
        Ok(None) => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": "not found", "workspace_id": id })))
                .into_response()
        }
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct TransferBody {
    /// The new owning account. Must already exist.
    account_id: String,
}

/// Transfer a workspace to a different account (2.4). Repoints ownership and resets
/// staff atomically (customers, domains, and data ride through unchanged).
pub(crate) async fn transfer_workspace(
    State(s): State<App>,
    Path(workspace_id): Path<String>,
    Json(body): Json<TransferBody>,
) -> Response {
    // Target account must exist — clean 404 rather than a raw FK 500.
    match s.store.get_account(&body.account_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown_account", "account_id": body.account_id })),
            )
                .into_response();
        }
        Err(e) => return internal(e),
    }
    let staff_removed = match s.store.transfer_workspace(&workspace_id, &body.account_id).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown_workspace", "workspace_id": workspace_id })),
            )
                .into_response();
        }
        Err(e) => return internal(e),
    };
    METRICS.mutations.add(1, &[KeyValue::new("op", "transfer_workspace")]);
    info!(workspace = %workspace_id, new_account = %body.account_id, staff_removed, "workspace transferred");
    (
        StatusCode::OK,
        Json(json!({
            "result": "ok",
            "workspace_id": workspace_id,
            "account_id": body.account_id,
            "staff_removed": staff_removed,
        })),
    )
        .into_response()
}

// --------------------------------------------------------------------------- //
// Memberships (the live authz source of record) — nexus-owned-workspace-tenancy 2.3
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
pub(crate) struct MembershipBody {
    user_sub: String,
    /// `"staff"` or `"customer"` — validated against `MEMBER_TYPES`.
    member_type: String,
    #[serde(default = "default_member_role")]
    role: String,
    #[serde(default = "default_status")]
    status: String,
}

pub(crate) fn default_member_role() -> String {
    "member".to_owned()
}

pub(crate) fn default_status() -> String {
    "active".to_owned()
}

/// Grant or update a workspace membership (2.3). Writes the source-of-record row;
/// the identity plane picks the change up via the change feed to resolve the acting
/// workspace scope (the feed wiring lands with the identity-plane stage).
pub(crate) async fn upsert_membership(
    State(s): State<App>,
    Path(workspace_id): Path<String>,
    Json(body): Json<MembershipBody>,
) -> Response {
    if !MEMBER_TYPES.contains(&body.member_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_member_type", "value": body.member_type, "allowed": MEMBER_TYPES })),
        )
            .into_response();
    }
    // Unknown workspace → clean 404 (the FK would otherwise surface as a 500).
    match s.store.get_workspace(&workspace_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown_workspace", "workspace_id": workspace_id })),
            )
                .into_response();
        }
        Err(e) => return internal(e),
    }
    let m = Membership {
        user_sub: body.user_sub,
        workspace_id: workspace_id.clone(),
        member_type: body.member_type,
        role: body.role,
        status: body.status,
    };
    if let Err(e) = s.store.upsert_membership(&m).await {
        return internal(e);
    }
    // Best-effort signal to the identity plane's membership-sync worker. A failed
    // notify must NOT fail the committed write — the reconcile backstop heals it.
    if let Err(e) = s.store.notify_membership_change(&m.user_sub).await {
        warn!(error = %e, user = %m.user_sub, "membership-change notify failed; backstop will heal");
    }
    METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_membership")]);
    info!(workspace = %workspace_id, user = %m.user_sub, member_type = %m.member_type, "membership granted");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "workspace_id": workspace_id, "user_sub": m.user_sub })),
    )
        .into_response()
}

pub(crate) async fn delete_membership(
    State(s): State<App>,
    Path((workspace_id, user_sub)): Path<(String, String)>,
) -> Response {
    if let Err(e) = s.store.delete_membership(&user_sub, &workspace_id).await {
        return internal(e);
    }
    // Best-effort signal (see upsert_membership) — the consumer re-reads the
    // subject's remaining memberships, so a revoke propagates without the workspace.
    if let Err(e) = s.store.notify_membership_change(&user_sub).await {
        warn!(error = %e, user = %user_sub, "membership-change notify failed; backstop will heal");
    }
    METRICS.mutations.add(1, &[KeyValue::new("op", "delete_membership")]);
    (StatusCode::OK, Json(json!({ "result": "ok", "workspace_id": workspace_id, "user_sub": user_sub })))
        .into_response()
}

pub(crate) async fn list_memberships(State(s): State<App>, Path(workspace_id): Path<String>) -> Response {
    match s.store.memberships_for_workspace(&workspace_id).await {
        Ok(memberships) => {
            (StatusCode::OK, Json(json!({ "workspace_id": workspace_id, "memberships": memberships })))
                .into_response()
        }
        Err(e) => internal(e),
    }
}
