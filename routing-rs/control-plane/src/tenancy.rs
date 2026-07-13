//! Accounts, Workspaces, and Memberships (nexus-owned-workspace-tenancy 2.1–2.4;
//! server-minted-ids). Ids are nexus-minted (`router_core::ids`), never
//! caller-supplied — `deny_unknown_fields` on every create body rejects a
//! request that still tries. Creation is replay-safe via an optional caller
//! idempotency key (provisioning-idempotency); create and reconfigure are
//! disjoint operations (`POST /workspaces` vs `PUT /workspaces/{id}`).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use opentelemetry::KeyValue;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use router_core::audit::AuditCtx;
use router_core::domain::WorkspaceConfig;
use router_core::idempotency::{validate_key, IDEMPOTENCY_KEY_MAX_BYTES};
use router_core::ids::{mint_account_id, mint_workspace_id};
use router_core::store::{
    Membership, MembershipStore, NewAccount, OwnershipStore, RoutingStore, MEMBER_TYPES,
};

use crate::app::{internal, App, METRICS};

pub(crate) fn default_plan() -> String {
    "free".to_owned()
}

/// The 400 rejection for a malformed caller-supplied idempotency key
/// (provisioning-idempotency: non-empty, bounded, visible ASCII), or `None` when
/// the key is acceptable. An ABSENT key is always acceptable — replay protection
/// is opt-in.
fn invalid_idempotency_key(key: Option<&str>) -> Option<Response> {
    let reason = key.map(validate_key)?.err()?;
    Some(
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_idempotency_key",
                "reason": reason.to_string(),
                "max_bytes": IDEMPOTENCY_KEY_MAX_BYTES,
            })),
        )
            .into_response(),
    )
}

// --------------------------------------------------------------------------- //
// Accounts (ownership container) — nexus-owned-workspace-tenancy 2.1
// --------------------------------------------------------------------------- //
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AccountBody {
    /// The user this account is provisioned for — becomes its `owner` member.
    owner_sub: String,
    /// Display name: NO identity or uniqueness semantics (workspace-tenancy).
    #[serde(default)]
    name: String,
    #[serde(default)]
    payer_ref: Option<String>,
    /// Optional replay guard (provisioning-idempotency). Opaque to nexus — the
    /// caller encodes its flow in the value (e.g. the broker's `signup:<sub>`),
    /// which is where "one auto-provisioned account per subject" lives.
    #[serde(default)]
    idempotency_key: Option<String>,
}

/// Provision an account (2.1): nexus mints `acct_<uuidv7>` and returns it — the
/// caller never chooses the id (server-minted-ids). With an idempotency key, a
/// replay returns the ORIGINAL account (`created: false`) and only re-asserts
/// the owner membership, so keyed signup provisioning stays safe to call
/// unconditionally.
pub(crate) async fn provision_account(
    State(s): State<App>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<AccountBody>,
) -> Response {
    if let Some(rejection) = invalid_idempotency_key(body.idempotency_key.as_deref()) {
        return rejection;
    }
    let minted = mint_account_id();
    // One store call = one transaction: account insert, owner membership, and
    // the `account.provision` audit event commit together (admin-action-audit).
    let outcome = match s
        .store
        .provision_account(
            &NewAccount {
                account_id: &minted,
                name: &body.name,
                payer_ref: body.payer_ref.as_deref(),
                owner_sub: &body.owner_sub,
                idempotency_key: body.idempotency_key.as_deref(),
            },
            &actx,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return internal(e),
    };
    METRICS.mutations.add(1, &[KeyValue::new("op", "provision_account")]);
    info!(account = %outcome.id, owner = %body.owner_sub, created = outcome.created, "account provisioned");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "account_id": outcome.id, "created": outcome.created })),
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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceBody {
    /// Display name: NO identity or uniqueness semantics (workspace-tenancy).
    #[serde(default)]
    name: String,
    /// Owning account, optional at create. An ownership CHANGE goes through
    /// `/transfer`, never here.
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default = "default_plan")]
    plan: String,
    target_pool: String,
    #[serde(default)]
    features: Vec<String>,
    /// Optional replay guard (provisioning-idempotency) — see `AccountBody`.
    #[serde(default)]
    idempotency_key: Option<String>,
}

/// Create a workspace (2.2): nexus mints `ws_<uuidv7>` and returns it. Create
/// NEVER overwrites an existing workspace (reconfigure is `PUT
/// /workspaces/{id}`); with an idempotency key, a replay returns the ORIGINAL
/// workspace (`created: false`) untouched.
pub(crate) async fn create_workspace(
    State(s): State<App>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<WorkspaceBody>,
) -> Response {
    // Validate against the data-driven pool allow-list (RFC C15, fail-closed).
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
    if let Some(rejection) = invalid_idempotency_key(body.idempotency_key.as_deref()) {
        return rejection;
    }
    // If an account was supplied, it MUST exist — check first so the FK surfaces
    // as a clean 404 instead of a raw 500.
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
        workspace_id: mint_workspace_id(),
        name: body.name,
        plan: body.plan,
        target_pool: pool,
        features: body.features,
        updated_at: None,
    };
    // One store call = one transaction: the insert, the create-time ownership
    // assignment (real insert only — a replay never re-owns), and the
    // `workspace.create` audit event commit together (admin-action-audit).
    let outcome = match s
        .store
        .create_workspace(&cfg, body.account_id.as_deref(), body.idempotency_key.as_deref(), &actx)
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return internal(e),
    };
    // No invalidation on create: a fresh workspace has no domains yet, and a
    // replay changed nothing.
    METRICS.mutations.add(1, &[KeyValue::new("op", "create_workspace")]);
    info!(workspace = %outcome.id, created = outcome.created, "workspace created");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "workspace_id": outcome.id, "created": outcome.created })),
    )
        .into_response()
}

/// Body of `PUT /workspaces/{id}` — the full desired routing config. Name and
/// ownership are deliberately NOT reconfigurable here (name is create-time
/// data; ownership changes ride `/transfer`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconfigureBody {
    plan: String,
    target_pool: String,
    #[serde(default)]
    features: Vec<String>,
}

/// Reconfigure an existing workspace (server-minted-ids D3): update-only — an
/// unknown id is a 404, NEVER an implicit create (a typo'd id must not mint a
/// ghost workspace).
pub(crate) async fn update_workspace(
    State(s): State<App>,
    Path(workspace_id): Path<String>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<ReconfigureBody>,
) -> Response {
    // Same pool allow-list validation as create (RFC C15, fail-closed).
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
    let cfg = WorkspaceConfig {
        workspace_id: workspace_id.clone(),
        // Placeholder for the shared type — update_workspace never writes name.
        name: String::new(),
        plan: body.plan,
        target_pool: pool,
        features: body.features,
        updated_at: None,
    };
    match s.store.update_workspace(&cfg, &actx).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown_workspace", "workspace_id": workspace_id })),
            )
                .into_response();
        }
        Err(e) => return internal(e),
    }
    // A workspace change affects all of its domains — invalidate each precisely.
    match s.store.domains_for_workspace(&workspace_id).await {
        Ok(domains) => {
            for d in &domains {
                s.invalidate(d).await;
            }
            METRICS.mutations.add(1, &[KeyValue::new("op", "update_workspace")]);
            info!(workspace = %workspace_id, invalidated = domains.len(), "workspace reconfigured");
        }
        Err(e) => warn!(error = %e, "domains_for_workspace failed; relying on TTL"),
    }
    (StatusCode::OK, Json(json!({ "result": "ok", "workspace_id": workspace_id }))).into_response()
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
    Extension(actx): Extension<AuditCtx>,
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
    let staff_removed = match s.store.transfer_workspace(&workspace_id, &body.account_id, &actx).await {
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
    Extension(actx): Extension<AuditCtx>,
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
    if let Err(e) = s.store.upsert_membership(&m, &actx).await {
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
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    if let Err(e) = s.store.delete_membership(&user_sub, &workspace_id, &actx).await {
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

// --------------------------------------------------------------------------- //
// Body-contract tests (server-minted-ids): the create bodies are where
// "callers never choose ids" is enforced — `deny_unknown_fields` makes a
// caller-supplied id a request rejection, not a silently adopted value. The
// replay/404 behavior itself is pinned by the store-postgres integration tests
// (the SQL enforces it); the full HTTP path is driven by the e2e suite.
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod tests {
    use super::{AccountBody, ReconfigureBody, WorkspaceBody};

    #[test]
    fn account_create_rejects_a_caller_supplied_id() {
        // workspace-tenancy scenario: "Caller-supplied ids are not honored".
        let err = serde_json::from_str::<AccountBody>(
            r#"{"account_id": "acct_forged", "owner_sub": "user-1"}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("account_id"),
            "rejection names the offending field: {err}"
        );
    }

    #[test]
    fn workspace_create_rejects_a_caller_supplied_id() {
        let err = serde_json::from_str::<WorkspaceBody>(
            r#"{"workspace_id": "ws_forged", "target_pool": "application"}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("workspace_id"),
            "rejection names the offending field: {err}"
        );
    }

    #[test]
    fn reconfigure_carries_config_only() {
        // PUT reconfigures plan/pool/features — identity, ownership, and the
        // display name are all rejected, not silently dropped.
        for body in [
            r#"{"workspace_id":"ws_x","plan":"free","target_pool":"application"}"#,
            r#"{"account_id":"acct_x","plan":"free","target_pool":"application"}"#,
            r#"{"name":"renamed","plan":"free","target_pool":"application"}"#,
        ] {
            assert!(
                serde_json::from_str::<ReconfigureBody>(body).is_err(),
                "must reject non-config field: {body}"
            );
        }
        // ...and plan is REQUIRED (no silent default that could downgrade a tier).
        assert!(
            serde_json::from_str::<ReconfigureBody>(r#"{"target_pool":"application"}"#).is_err(),
            "an omitted plan is a missing-field error, not a downgrade to the default"
        );
    }

    #[test]
    fn create_bodies_accept_the_documented_shape() {
        let account: AccountBody = serde_json::from_str(
            r#"{"owner_sub":"user-1","name":"Acme","idempotency_key":"signup:user-1"}"#,
        )
        .expect("documented account body parses");
        assert_eq!(account.idempotency_key.as_deref(), Some("signup:user-1"));

        let ws: WorkspaceBody =
            serde_json::from_str(r#"{"name":"Shop","target_pool":"application"}"#)
                .expect("documented workspace body parses");
        assert_eq!(ws.plan, "free", "plan defaults to free at create");
        assert!(ws.idempotency_key.is_none(), "the replay guard is opt-in");
    }
}
