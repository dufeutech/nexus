//! Tenants — DEPRECATED alias of Workspaces (nexus-owned-workspace-tenancy, 2.2).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use opentelemetry::KeyValue;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use router_core::domain::WorkspaceConfig;
use router_core::store::RoutingStore;

use crate::app::{internal, App, METRICS};

// --------------------------------------------------------------------------- //
// Tenants — DEPRECATED alias of Workspaces (nexus-owned-workspace-tenancy, 2.2).
// The `/tenants*` routes + this account-less `tenant_id` body are frozen for the
// running broker/e2e during cut-over; new callers use `/workspaces*` (which also
// carries `account_id` + membership). Removed in a later archive step. The handler
// maps `tenant_id` → the store's `workspace_id` (the same identifier).
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
pub(crate) struct TenantBody {
    tenant_id: String,
    #[serde(default = "default_plan")]
    plan: String,
    target_pool: String,
    #[serde(default)]
    features: Vec<String>,
}

pub(crate) fn default_plan() -> String {
    "free".to_owned()
}

pub(crate) async fn upsert_tenant(State(s): State<App>, Json(body): Json<TenantBody>) -> impl IntoResponse {
    // Validate against the data-driven allow-list (RFC C15): reject an unknown pool
    // rather than invent a destination. The error lists the configured pools so a
    // typo/missing-config is obvious without a redeploy.
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
    // Migration seam: the store/core now speak `workspace_id`, but this HTTP body
    // is still the legacy `tenant_id` field (the `/tenants` API rename is task 2.2).
    // The value is the same workspace identifier — map it across here.
    let cfg = WorkspaceConfig {
        workspace_id: body.tenant_id.clone(),
        plan: body.plan,
        target_pool: pool,
        features: body.features,
        updated_at: None,
    };
    if let Err(e) = s.store.upsert_workspace(&cfg).await {
        return internal(e);
    }
    // A workspace change affects all of its domains — invalidate each precisely so
    // both the L1 (per-edge) and L2 (shared) tiers converge by domain key.
    match s.store.domains_for_workspace(&body.tenant_id).await {
        Ok(domains) => {
            for d in &domains {
                s.invalidate(d).await;
            }
            METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_tenant")]);
            info!(tenant = ?body.tenant_id, invalidated = domains.len(), "tenant upserted");
        }
        Err(e) => warn!(error = %e, "domains_for_tenant failed; relying on TTL"),
    }
    (StatusCode::OK, Json(json!({ "result": "ok", "tenant_id": body.tenant_id }))).into_response()
}

pub(crate) async fn get_tenant(State(s): State<App>, Path(id): Path<String>) -> impl IntoResponse {
    match s.store.get_workspace(&id).await {
        Ok(Some(cfg)) => (StatusCode::OK, Json(serde_json::to_value(cfg).unwrap())).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found", "tenant_id": id })))
            .into_response(),
        Err(e) => internal(e),
    }
}
