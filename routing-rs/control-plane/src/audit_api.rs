//! Audit ledger read surface + named-admin-token provisioning + retention
//! (admin-action-audit D4–D7).
//!
//! Read-only over the ledger: `GET /audit/events` (filtered, time-ordered,
//! cursor-paginated) and `GET /audit/events/export` (NDJSON stream). NO
//! mutation endpoint over events exists — append-only is a property of the
//! whole system, not just the store grants. Token provisioning (issue / rotate
//! / revoke) is itself an audited admin mutation on the same gated surface.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures::stream;
use opentelemetry::KeyValue;
use serde::Deserialize;
use serde_json::json;
use tokio::time::interval;
use tracing::{error, info, warn};

use router_core::admin_authz::{is_known_scope, LastTokenAdminGuard};
use router_core::audit::{AuditCtx, AuditQuery, InvalidQueryBound};
use router_core::store::BoxError;
use store_postgres::{PgAuditMaintenance, PgRoutingStore};

use crate::app::{internal, App, METRICS};

/// The compliance floor for `AUDIT_RETENTION_DAYS` (design D7): SOC 2 mandates
/// no period, but 12 months is the auditor expectation — anything shorter is
/// refused at startup.
pub(crate) const AUDIT_RETENTION_FLOOR_DAYS: u32 = 365;

/// The default retention (design D7): a Type II 12-month observation window
/// plus buffer (~15 months).
pub(crate) const AUDIT_RETENTION_DEFAULT_DAYS: u32 = 450;

/// Export/read page size (adapter-clamped upper bound).
const EXPORT_PAGE: u32 = 1000;

/// Parse + validate the retention config (startup-validated floor, design D7).
/// Empty/unset → the default; unparseable or below the floor → an error the
/// caller turns into a refused start.
pub(crate) fn retention_days_from_env(raw: &str) -> Result<u32, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(AUDIT_RETENTION_DEFAULT_DAYS);
    }
    let days: u32 = trimmed
        .parse()
        .map_err(|_| format!("AUDIT_RETENTION_DAYS must be a whole number of days, got '{trimmed}'"))?;
    if days < AUDIT_RETENTION_FLOOR_DAYS {
        return Err(format!(
            "AUDIT_RETENTION_DAYS={days} is below the compliance floor of \
             {AUDIT_RETENTION_FLOOR_DAYS} days (admin-action-audit D7)"
        ));
    }
    Ok(days)
}

/// The periodic retention purge — the ONLY deleter of audit events, running on
/// the separate maintenance-role connection (design D7). Daily cadence; the
/// first pass runs at startup so a long-stopped deployment converges promptly.
pub(crate) async fn retention_purge(maintenance: PgAuditMaintenance, retention_days: u32) {
    let mut tick = interval(Duration::from_hours(24));
    loop {
        tick.tick().await;
        match maintenance.purge_events_older_than_days(retention_days).await {
            Ok(0) => {}
            Ok(purged) => info!(purged, retention_days, "audit retention purge"),
            Err(e) => warn!(error = %e, "audit retention purge failed (will retry next pass)"),
        }
    }
}

/// The 400 for a malformed `from`/`to` bound.
fn invalid_time_bound() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_time_bound", "hint": "use an RFC 3339 timestamp" })),
    )
        .into_response()
}

// --------------------------------------------------------------------------- //
// Read surface (design D6).
// --------------------------------------------------------------------------- //

#[derive(Deserialize)]
pub(crate) struct EventsParams {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

impl EventsParams {
    fn into_query(self) -> AuditQuery {
        AuditQuery {
            from: self.from,
            to: self.to,
            actor: self.actor,
            target: self.target,
            cursor: self.cursor,
            limit: self.limit,
        }
    }
}

/// `GET /audit/events` — time-ordered, filtered, cursor-paginated. `next_cursor`
/// resumes strictly after this page; an empty `events` page means done.
pub(crate) async fn list_audit_events(
    State(s): State<App>,
    Query(params): Query<EventsParams>,
) -> Response {
    let query = params.into_query();
    match s.store.query_audit_events(&query).await {
        Ok(events) => {
            let next_cursor = events.last().map(|event| event.event_id.clone());
            (StatusCode::OK, Json(json!({ "events": events, "next_cursor": next_cursor })))
                .into_response()
        }
        Err(e) if e.downcast_ref::<InvalidQueryBound>().is_some() => invalid_time_bound(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub(crate) struct ExportParams {
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
}

/// Pagination state threaded through the export stream.
struct ExportState {
    store: Arc<PgRoutingStore>,
    from: Option<String>,
    to: Option<String>,
    cursor: Option<String>,
    done: bool,
}

/// `GET /audit/events/export` — a lossless NDJSON stream of the time range
/// (design D6/export ADR): one event per line, streamed in pages so the ledger
/// is never buffered whole. Read-only: exporting evidence leaves the ledger
/// unchanged. An OCSF/SIEM mapping can be added beside this as a pure output
/// adapter without touching the record shape.
pub(crate) async fn export_audit_events(
    State(s): State<App>,
    Query(params): Query<ExportParams>,
) -> Response {
    // Probe the bounds up front so a malformed timestamp is a clean 400 — a
    // streaming body cannot change its status once bytes flow.
    let probe = AuditQuery {
        from: params.from.clone(),
        to: params.to.clone(),
        limit: Some(1),
        ..AuditQuery::default()
    };
    if let Err(e) = s.store.query_audit_events(&probe).await {
        return if e.downcast_ref::<InvalidQueryBound>().is_some() {
            invalid_time_bound()
        } else {
            internal(e)
        };
    }

    let init = ExportState {
        store: Arc::clone(&s.store),
        from: params.from,
        to: params.to,
        cursor: None,
        done: false,
    };
    let body_stream = stream::unfold(init, |mut st| async move {
        if st.done {
            return None;
        }
        let query = AuditQuery {
            from: st.from.clone(),
            to: st.to.clone(),
            cursor: st.cursor.clone(),
            limit: Some(EXPORT_PAGE),
            ..AuditQuery::default()
        };
        match st.store.query_audit_events(&query).await {
            Ok(events) if events.is_empty() => None,
            Ok(events) => {
                st.cursor = events.last().map(|event| event.event_id.clone());
                if events.len() < EXPORT_PAGE as usize {
                    st.done = true;
                }
                let mut chunk = String::new();
                for event in &events {
                    match serde_json::to_string(event) {
                        Ok(line) => {
                            chunk.push_str(&line);
                            chunk.push('\n');
                        }
                        Err(e) => {
                            st.done = true;
                            return Some((Err(Box::new(e) as BoxError), st));
                        }
                    }
                }
                Some((Ok(chunk), st))
            }
            Err(e) => {
                st.done = true;
                Some((Err(e), st))
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/x-ndjson")
        .body(Body::from_stream(body_stream))
        .unwrap_or_else(|e| {
            error!(error = %e, "export response build failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "internal_error" })))
                .into_response()
        })
}

// --------------------------------------------------------------------------- //
// Named-token provisioning (design D4). Chicken-and-egg on a fresh deployment
// is solved by the migration mode: the FIRST named token is minted while the
// legacy shared token (or auth-disabled dev mode) still authenticates the call.
// --------------------------------------------------------------------------- //

/// 503 when named-token management is not configured (`ADMIN_TOKEN_PEPPER` unset).
fn token_mgmt_unconfigured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "admin_token_mgmt_unconfigured", "hint": "set ADMIN_TOKEN_PEPPER" })),
    )
        .into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssueTokenBody {
    /// The named caller this credential is issued to (e.g. `signup-broker`,
    /// `ops-cli`, `ci`). Attribution, not authorization.
    name: String,
    /// The credential's grant (admin-plane-authorization: "Grants are explicit
    /// at provisioning") — REQUIRED and non-empty; there is no implicit
    /// default. Each entry must be in the closed scope vocabulary.
    scopes: Vec<String>,
}

/// `POST /admin-tokens` — issue a named credential with an explicit grant.
/// The secret is returned exactly once and never persisted or logged.
pub(crate) async fn issue_admin_token(
    State(s): State<App>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<IssueTokenBody>,
) -> Response {
    let Some(tokens) = s.auth.tokens.as_ref() else {
        return token_mgmt_unconfigured();
    };
    let name = body.name.trim();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "name_required" }))).into_response();
    }
    // Fail-closed at the boundary (spec "An unscoped provisioning request is
    // refused"): no scopes → 400, an unknown scope word → 400; nothing mints.
    if body.scopes.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "scopes_required",
                "hint": "grant an explicit, non-empty scope set (read, provision, token-admin)",
            })),
        )
            .into_response();
    }
    if let Some(unknown) = body.scopes.iter().find(|scope| !is_known_scope(scope)) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "unknown_scope", "scope": unknown })),
        )
            .into_response();
    }
    match tokens.issue(name, &body.scopes, &actx).await {
        Ok(issued) => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "issue_admin_token")]);
            info!(token_id = %issued.token_id, name, scopes = ?body.scopes, "admin token issued");
            (
                StatusCode::CREATED,
                Json(json!({ "token_id": issued.token_id, "secret": issued.secret })),
            )
                .into_response()
        }
        Err(e) => internal(e),
    }
}

/// `GET /admin-tokens` — enumerate credentials for review (spec "A
/// credential's grant is reviewable"): identity, grant, status, lineage —
/// never secret material (the store does not even select it).
pub(crate) async fn list_admin_tokens(State(s): State<App>) -> Response {
    let Some(tokens) = s.auth.tokens.as_ref() else {
        return token_mgmt_unconfigured();
    };
    match tokens.list().await {
        Ok(records) => (StatusCode::OK, Json(json!({ "tokens": records }))).into_response(),
        Err(e) => internal(e),
    }
}

/// `POST /admin-tokens/{id}/rotate` — new secret under the same name + lineage;
/// the old credential stops working, every other caller's keeps working.
pub(crate) async fn rotate_admin_token(
    State(s): State<App>,
    Path(token_id): Path<String>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    let Some(tokens) = s.auth.tokens.as_ref() else {
        return token_mgmt_unconfigured();
    };
    match tokens.rotate(&token_id, &actx).await {
        Ok(Some(issued)) => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "rotate_admin_token")]);
            info!(token_id = %issued.token_id, rotated_from = %token_id, "admin token rotated");
            (
                StatusCode::CREATED,
                Json(json!({ "token_id": issued.token_id, "secret": issued.secret })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no_active_token", "token_id": token_id })),
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

/// `POST /admin-tokens/{id}/revoke` — status flip; idempotent (`revoked: false`
/// when the id was already revoked or unknown). Refuses with 409 when the
/// target is the LAST active `token-admin` credential (spec "The last
/// credential administrator cannot be removed") — the lockout hazard is named,
/// and the credential stays active.
pub(crate) async fn revoke_admin_token(
    State(s): State<App>,
    Path(token_id): Path<String>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    let Some(tokens) = s.auth.tokens.as_ref() else {
        return token_mgmt_unconfigured();
    };
    match tokens.revoke(&token_id, &actx).await {
        Ok(revoked) => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "revoke_admin_token")]);
            info!(%token_id, revoked, "admin token revoke");
            (StatusCode::OK, Json(json!({ "result": "ok", "revoked": revoked }))).into_response()
        }
        Err(e) if e.downcast_ref::<LastTokenAdminGuard>().is_some() => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "last_token_admin",
                "reason": e.to_string(),
                "token_id": token_id,
            })),
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        retention_days_from_env, AUDIT_RETENTION_DEFAULT_DAYS, AUDIT_RETENTION_FLOOR_DAYS,
    };

    #[test]
    fn retention_defaults_and_floors() {
        // Unset → the documented default (covers a Type II window + buffer).
        assert_eq!(retention_days_from_env(""), Ok(AUDIT_RETENTION_DEFAULT_DAYS));
        assert_eq!(retention_days_from_env("  "), Ok(AUDIT_RETENTION_DEFAULT_DAYS));
        // At/above the floor → accepted.
        assert_eq!(retention_days_from_env("365"), Ok(AUDIT_RETENTION_FLOOR_DAYS));
        assert_eq!(retention_days_from_env("730"), Ok(730));
        // Below the floor → refused (startup-validated floor, design D7).
        assert!(retention_days_from_env("364").is_err(), "below-floor retention must refuse");
        assert!(retention_days_from_env("0").is_err(), "zero retention must refuse");
        // Garbage → refused, never a silent default.
        assert!(retention_days_from_env("a year").is_err(), "unparseable must refuse");
        assert!(retention_days_from_env("-1").is_err(), "negative must refuse");
    }
}
