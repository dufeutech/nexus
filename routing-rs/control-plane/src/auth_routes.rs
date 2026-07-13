//! Per-route auth policy (RFC N4): CRUD over a tenant's path-prefix rules.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use opentelemetry::KeyValue;
use serde::Deserialize;
use serde_json::json;
use tracing::{info, warn};

use router_core::auth::RouteAuth;
use router_core::store::RoutingStore;

use crate::app::{internal, App, METRICS};

// --------------------------------------------------------------------------- //
// Per-route auth policy (RFC N4): CRUD over a tenant's path-prefix rules. A
// change re-protects live traffic, so every mutation invalidates ALL the tenant's
// domains (same precise per-domain invalidation as a tenant-config change) so the
// routers reload the policy promptly over the one invalidation feed (RFC C16).
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
pub(crate) struct AuthRouteBody {
    path_prefix: String,
    auth_required: bool,
    /// Phase-2 requirements (N4): optional; any of them present demands
    /// `auth_required = true` (validated at write time — see the handler).
    #[serde(default)]
    requires_role: Option<String>,
    #[serde(default)]
    requires_entitlement: Option<String>,
    #[serde(default)]
    min_aal: Option<u8>,
    /// identity-existence-hiding: mark a protected route as account-scoped
    /// (reachable without a workspace membership, e.g. `/me`). Default `false`
    /// (workspace-scoped, membership-gated) — the fail-closed existence-hiding
    /// posture. Only meaningful when `auth_required = true`.
    #[serde(default)]
    account_scoped: bool,
}

#[derive(Deserialize)]
pub(crate) struct AuthRouteDelete {
    path_prefix: String,
}

impl App {
    /// Invalidate every domain a tenant owns — the precise convergence signal for
    /// a change that affects all of the tenant's routes (policy or config).
    async fn invalidate_tenant(&self, workspace_id: &str, op: &'static str) {
        match self.store.domains_for_workspace(workspace_id).await {
            Ok(domains) => {
                for d in &domains {
                    self.invalidate(d).await;
                }
                info!(tenant = ?workspace_id, op, invalidated = domains.len(), "tenant invalidated");
            }
            Err(e) => warn!(error = %e, "domains_for_tenant failed; relying on TTL"),
        }
    }

    /// Reject a path prefix that is not rooted at `/` — the policy matches request
    /// paths, which always begin with `/`, so a non-rooted prefix can never match.
    fn valid_prefix(prefix: &str) -> bool {
        prefix.starts_with('/')
    }

    /// A rule combining a phase-2 requirement with `auth_required = false` is
    /// contradictory (requirements imply authentication): the gate would leak
    /// authorization policy as 403s to callers who were never asked to log in.
    /// Rejected at write time so such a rule never enters the store.
    const fn inconsistent_requirements(auth: &RouteAuth) -> bool {
        auth.has_requirements() && !auth.required
    }
}

pub(crate) async fn upsert_auth_route(
    State(s): State<App>,
    Path(workspace_id): Path<String>,
    Json(body): Json<AuthRouteBody>,
) -> Response {
    if !App::valid_prefix(&body.path_prefix) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_prefix", "path_prefix": body.path_prefix, "hint": "must start with '/'" })),
        )
            .into_response();
    }
    let auth = RouteAuth {
        required: body.auth_required,
        requires_role: body.requires_role.clone(),
        requires_entitlement: body.requires_entitlement.clone(),
        min_aal: body.min_aal,
        account_scoped: body.account_scoped,
    };
    if App::inconsistent_requirements(&auth) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "requirements_need_auth",
                "path_prefix": body.path_prefix,
                "hint": "a rule with requires_role/requires_entitlement/min_aal must set auth_required = true",
            })),
        )
            .into_response();
    }
    // The FK would reject an unknown workspace as a 500; check first for a clean 404.
    match s.store.get_workspace(&workspace_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown_workspace", "workspace_id": workspace_id })))
                .into_response();
        }
        Err(e) => return internal(e),
    }
    if let Err(e) = s.store.upsert_auth_route(&workspace_id, &body.path_prefix, &auth).await {
        return internal(e);
    }
    s.invalidate_tenant(&workspace_id, "upsert_auth_route").await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_auth_route")]);
    (
        StatusCode::OK,
        Json(json!({
            "result": "ok",
            "workspace_id": workspace_id,
            "path_prefix": body.path_prefix,
            "auth_required": auth.required,
            "requires_role": auth.requires_role,
            "requires_entitlement": auth.requires_entitlement,
            "min_aal": auth.min_aal,
            "account_scoped": auth.account_scoped,
        })),
    )
        .into_response()
}

pub(crate) async fn delete_auth_route(
    State(s): State<App>,
    Path(workspace_id): Path<String>,
    Json(body): Json<AuthRouteDelete>,
) -> Response {
    if let Err(e) = s.store.delete_auth_route(&workspace_id, &body.path_prefix).await {
        return internal(e);
    }
    s.invalidate_tenant(&workspace_id, "delete_auth_route").await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "delete_auth_route")]);
    (StatusCode::OK, Json(json!({ "result": "ok", "workspace_id": workspace_id, "path_prefix": body.path_prefix })))
        .into_response()
}

pub(crate) async fn list_auth_routes(State(s): State<App>, Path(workspace_id): Path<String>) -> Response {
    match s.store.get_auth_policy(&workspace_id).await {
        Ok(policy) => {
            let routes: Vec<_> = policy
                .rules()
                .iter()
                .map(|r| {
                    json!({
                        "path_prefix": r.prefix,
                        "auth_required": r.auth.required,
                        "requires_role": r.auth.requires_role,
                        "requires_entitlement": r.auth.requires_entitlement,
                        "min_aal": r.auth.min_aal,
                        "account_scoped": r.auth.account_scoped,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "workspace_id": workspace_id, "routes": routes }))).into_response()
        }
        Err(e) => internal(e),
    }
}

#[cfg(test)]
mod auth_route_validation_tests {
    use super::{App, RouteAuth};

    /// Spec "Inconsistent rule is rejected at write time": any requirement field
    /// with `auth_required = false` is the rejected combination; the same fields
    /// with `auth_required = true`, or no fields at all, are accepted.
    /// (Persistence + NOTIFY of an accepted rule is covered by the store
    /// integration round-trip and the shared `invalidate_tenant` path.)
    #[test]
    fn requirement_with_anonymous_route_is_inconsistent() {
        let anonymous_gated = RouteAuth {
            required: false,
            requires_role: Some("admin".into()),
            ..RouteAuth::PASS_THROUGH
        };
        assert!(App::inconsistent_requirements(&anonymous_gated));

        let authed_gated = RouteAuth {
            required: true,
            min_aal: Some(2),
            ..RouteAuth::PASS_THROUGH
        };
        assert!(!App::inconsistent_requirements(&authed_gated));

        let phase1_public = RouteAuth::PASS_THROUGH;
        assert!(!App::inconsistent_requirements(&phase1_public));
    }
}
