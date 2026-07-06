//! authz-admin (Rust) — the identity-plane administrative authoring surface.
//!
//! It is the SINGLE source of record for nexus-native authorization facts
//! (`nexus-native-authorization` spec R4): roles, entitlements, and suspension are
//! created/changed/revoked ONLY here, never by a token, event, or the OIDC provider.
//! Writes go through the [`AuthzAuthoring`] port over the identity store; the change
//! propagates to the sidecar over the existing `LISTEN/NOTIFY` feed within seconds
//! (spec R3). The surface depends only on the ports, so the backend is swappable
//! (spec R5).
//!
//! Auth-gated exactly like the routing control-plane (`CONTROL_AUTH_TOKEN`):
//! fail-closed, a shared bearer token from a Secret; refuses to start without an
//! explicit choice. Not on the request hot path — reachable on an admin boundary only.
//!
//! Bootstrap (spec R4): a configured bootstrap-admin subject is granted the admin
//! role at startup IFF no administrator exists yet — idempotent break-glass, so the
//! surface is never unreachable from an empty store.

use std::env::var;
use std::error::Error;
#[cfg(not(unix))]
use std::future::pending;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use opentelemetry::metrics::Counter;
use opentelemetry::{global, KeyValue};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::sleep;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info, warn};

use identity_core::authz::{AuthzAuthoring, AuthzResolver};
use identity_core::store::BoxError;
use identity_core::telemetry;
use store_postgres::PgProfileStore;

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): every authoring mutation + rejected request is
// counted through the OTel meter. The counter name DROPS the Prometheus `_total`
// suffix (the OTLP receiver re-appends it). `op` carries the authoring kind.
// --------------------------------------------------------------------------- //
struct Metrics {
    mutations: Counter<u64>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("authz-admin");
    Metrics {
        mutations: meter.u64_counter("authz_admin_mutations").build(),
    }
});

fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
}

/// Total per-request timeout (http-request-resilience): operator-tunable via
/// `HTTP_REQUEST_TIMEOUT_SECS` with a finite 30s default — never unbounded.
fn request_timeout() -> Duration {
    Duration::from_secs(
        var("HTTP_REQUEST_TIMEOUT_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(30),
    )
}

#[derive(Clone)]
struct App {
    /// Authoring + resolution reach the store through the PORTS (spec R5), so a
    /// future engine adapter swaps in without touching this surface.
    authoring: Arc<dyn AuthzAuthoring>,
    resolver: Arc<dyn AuthzResolver>,
    /// Shared admin bearer token required on every authoring endpoint. `None` ONLY
    /// when auth is explicitly disabled at startup; the server otherwise refuses to
    /// start without a token, so it is never silently open.
    auth_token: Option<Arc<str>>,
}

/// Constant-time byte comparison — no early exit on the first differing byte, so a
/// rejected token leaks no timing signal about how much of it matched. (Length may
/// differ, which is not secret.)
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Parse `Authorization: Bearer <token>` (RFC 7235: case-insensitive scheme). An
/// empty token is treated as absent.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = raw.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty())
        .then(|| token.trim().to_owned())
}

/// Admin-token gate: every authoring/read endpoint requires a valid bearer token,
/// compared in constant time. `/healthz` is intentionally NOT behind this (liveness).
/// When `auth_token` is `None` the operator explicitly disabled auth at startup.
async fn require_auth(State(s): State<App>, req: Request, next: Next) -> Response {
    let Some(expected) = s.auth_token.as_deref() else {
        return next.run(req).await;
    };
    let presented = bearer_token(req.headers());
    match &presented {
        Some(tok) if ct_eq(tok.as_bytes(), expected.as_bytes()) => next.run(req).await,
        _ => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "unauthorized")]);
            // Audit line (method + path only — never the presented credential).
            warn!(
                method = %req.method(),
                path = %req.uri().path(),
                had_bearer = presented.is_some(),
                "unauthorized authz-admin request"
            );
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response()
        }
    }
}

/// Uniform 500 for an unexpected store error — LOGGED with detail for operators, but
/// the raw error is NEVER returned to the client (it can leak SQL/topology).
fn internal(e: BoxError) -> Response {
    error!(error = %e, "authz-admin store error");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "internal_error" }))).into_response()
}

/// Map an authoring result to a uniform 200/500 response, counting the mutation.
fn authored(result: Result<(), BoxError>, op: &'static str) -> Response {
    match result {
        Ok(()) => {
            METRICS.mutations.add(1, &[KeyValue::new("op", op)]);
            (StatusCode::OK, Json(json!({ "result": "ok" }))).into_response()
        }
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct RoleBody {
    role: String,
}

#[derive(Deserialize)]
struct EntitlementBody {
    entitlement: String,
}

async fn assign_role(
    State(s): State<App>,
    Path(sub): Path<String>,
    Json(body): Json<RoleBody>,
) -> Response {
    // `sub` is a user id (PII) — keep it out of info logs.
    info!(op = "assign_role", "authoring");
    authored(s.authoring.assign_role(&sub, &body.role).await, "assign_role")
}

async fn revoke_role(State(s): State<App>, Path((sub, role)): Path<(String, String)>) -> Response {
    info!(op = "revoke_role", "authoring");
    authored(s.authoring.revoke_role(&sub, &role).await, "revoke_role")
}

async fn grant_entitlement(
    State(s): State<App>,
    Path(sub): Path<String>,
    Json(body): Json<EntitlementBody>,
) -> Response {
    info!(op = "grant_entitlement", "authoring");
    authored(
        s.authoring.grant_entitlement(&sub, &body.entitlement).await,
        "grant_entitlement",
    )
}

async fn revoke_entitlement(
    State(s): State<App>,
    Path((sub, entitlement)): Path<(String, String)>,
) -> Response {
    info!(op = "revoke_entitlement", "authoring");
    authored(
        s.authoring.revoke_entitlement(&sub, &entitlement).await,
        "revoke_entitlement",
    )
}

async fn suspend(State(s): State<App>, Path(sub): Path<String>) -> Response {
    info!(op = "suspend", "authoring");
    authored(s.authoring.suspend(&sub).await, "suspend")
}

async fn reactivate(State(s): State<App>, Path(sub): Path<String>) -> Response {
    info!(op = "reactivate", "authoring");
    authored(s.authoring.reactivate(&sub).await, "reactivate")
}

/// Read a subject's effective facts (ops/audit convenience). Absent subject resolves
/// to the deny-by-default zero value, so this is a 200 with empty facts, not a 404.
async fn get_facts(State(s): State<App>, Path(sub): Path<String>) -> Response {
    match s.resolver.facts(&sub).await {
        Ok(f) => (
            StatusCode::OK,
            Json(json!({
                "sub": sub,
                "roles": f.roles,
                "entitlements": f.entitlements,
                "is_suspended": f.is_suspended,
            })),
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// Seed the first administrator if none exists yet (spec R4). Idempotent break-glass:
/// only fires from an empty-of-admins store, so a re-run after a real admin is
/// authored is a no-op. Rotate/disable the bootstrap secret once a real admin exists.
async fn bootstrap_admin(
    authoring: &dyn AuthzAuthoring,
    admin_role: &str,
    bootstrap_sub: Option<&str>,
) -> Result<(), BoxError> {
    let Some(sub) = bootstrap_sub else {
        info!("bootstrap: no AUTHZ_BOOTSTRAP_ADMIN_SUB configured; skipping seed");
        return Ok(());
    };
    if authoring.any_subject_has_role(admin_role).await? {
        info!(role = %admin_role, "bootstrap: an administrator already exists; skipping seed");
        return Ok(());
    }
    authoring.assign_role(sub, admin_role).await?;
    warn!(
        role = %admin_role,
        "bootstrap: seeded the initial administrator (break-glass) — rotate/disable the bootstrap secret now that a real admin can author grants"
    );
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Shared telemetry (first-party-telemetry): honors RUST_LOG/LOG_LEVEL/LOG_FORMAT,
    // plus OTLP export when the endpoint env is set. Held for the process lifetime.
    let _telemetry = telemetry::init("authz-admin");

    let pg_url = env("PROFILE_PG_URL", "postgres://postgres:postgres@postgres:5432/identitydb");
    // The admin role name is data-driven so an operator's role taxonomy isn't baked
    // in; the edge gate matches whatever string routes require.
    let admin_role = env("AUTHZ_ADMIN_ROLE", "admin");
    let bootstrap_sub = var("AUTHZ_BOOTSTRAP_ADMIN_SUB").ok().filter(|s| !s.trim().is_empty());

    // Admin-token gate, fail-closed: refuse to start without an explicit choice —
    // either supply IDENTITY_ADMIN_TOKEN (non-empty) or opt out with
    // IDENTITY_ADMIN_AUTH_DISABLED=true (trusted-network/dev only).
    let auth_disabled = matches!(
        env("IDENTITY_ADMIN_AUTH_DISABLED", "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    );
    let token = env("IDENTITY_ADMIN_TOKEN", "");
    let auth_token = match (auth_disabled, token.trim().is_empty()) {
        (true, _) => {
            warn!("IDENTITY_ADMIN_AUTH_DISABLED=true — authz-admin endpoints are UNAUTHENTICATED");
            None
        }
        (false, false) => Some(Arc::from(token.as_str())),
        (false, true) => {
            error!("IDENTITY_ADMIN_TOKEN is unset; refusing to start open. Set it, or set IDENTITY_ADMIN_AUTH_DISABLED=true to run without auth.");
            return Err("missing IDENTITY_ADMIN_TOKEN".into());
        }
    };

    // The authoring surface is an authoritative writer, so it owns idempotent identity
    // schema setup on startup before the first grant.
    let store: Arc<PgProfileStore> = loop {
        match PgProfileStore::connect(&pg_url).await {
            Ok(s) => match s.init_schema().await {
                Ok(()) => break Arc::new(s),
                Err(e) => warn!(error = %e, "schema init failed; retrying"),
            },
            Err(e) => warn!(error = %e, "waiting for Postgres"),
        }
        sleep(Duration::from_secs(2)).await;
    };
    // Depend on the PORTS (spec R5): the same store object satisfies both.
    let authoring: Arc<dyn AuthzAuthoring> = store.clone();
    let resolver: Arc<dyn AuthzResolver> = store;

    // Bootstrap the first administrator before serving (spec R4). A failure here is
    // fatal — an unreachable authoring surface is worse than a crash-loop the operator
    // can see and fix.
    bootstrap_admin(authoring.as_ref(), &admin_role, bootstrap_sub.as_deref()).await?;

    let app = App { authoring, resolver, auth_token };

    // Authoring + read endpoints behind the admin-token gate (route_layer so an
    // unknown path 404s without first demanding a token).
    let data = Router::new()
        .route("/authz/{sub}", get(get_facts))
        .route("/authz/{sub}/roles", put(assign_role))
        .route("/authz/{sub}/roles/{role}", delete(revoke_role))
        .route("/authz/{sub}/entitlements", put(grant_entitlement))
        .route(
            "/authz/{sub}/entitlements/{entitlement}",
            delete(revoke_entitlement),
        )
        .route("/authz/{sub}/suspend", post(suspend))
        .route("/authz/{sub}/reactivate", post(reactivate))
        .route_layer(middleware::from_fn_with_state(app.clone(), require_auth));

    let router = data
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, request_timeout()))
        .with_state(app);

    let listener = TcpListener::bind("0.0.0.0:9300").await?;
    info!(
        admin_role = %admin_role,
        "authz-admin on :9300 (/authz/{{sub}}[+/roles,/entitlements,/suspend,/reactivate], /healthz)"
    );
    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        error!(error = %e, "server error");
    }
    info!("stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn ct_eq_matches_only_identical_bytes() {
        assert!(ct_eq(b"secret-token", b"secret-token"));
        assert!(!ct_eq(b"secret-token", b"secret-toney"));
        assert!(!ct_eq(b"short", b"longer-token"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn bearer_parses_case_insensitive_scheme() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer abc123".parse().unwrap());
        assert_eq!(bearer_token(&h).as_deref(), Some("abc123"));
        h.insert(AUTHORIZATION, "bearer   abc123  ".parse().unwrap());
        assert_eq!(bearer_token(&h).as_deref(), Some("abc123"));
        // Wrong scheme / empty token / missing header → absent.
        h.insert(AUTHORIZATION, "Basic abc123".parse().unwrap());
        assert!(bearer_token(&h).is_none());
        h.insert(AUTHORIZATION, "Bearer   ".parse().unwrap());
        assert!(bearer_token(&h).is_none());
        assert!(bearer_token(&HeaderMap::new()).is_none());
    }

    // ---- Bootstrap gate (spec R4) ------------------------------------------- //

    /// Minimal in-memory authoring port: records assigned (sub, role) pairs and
    /// answers `any_subject_has_role` from them, so the bootstrap gate is testable
    /// without a store.
    #[derive(Default)]
    struct FakeAuthoring {
        grants: Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl AuthzAuthoring for FakeAuthoring {
        async fn assign_role(&self, sub: &str, role: &str) -> Result<(), BoxError> {
            self.grants.lock().unwrap().push((sub.to_owned(), role.to_owned()));
            Ok(())
        }
        async fn revoke_role(&self, _sub: &str, _role: &str) -> Result<(), BoxError> {
            Ok(())
        }
        async fn grant_entitlement(&self, _sub: &str, _e: &str) -> Result<(), BoxError> {
            Ok(())
        }
        async fn revoke_entitlement(&self, _sub: &str, _e: &str) -> Result<(), BoxError> {
            Ok(())
        }
        async fn suspend(&self, _sub: &str) -> Result<(), BoxError> {
            Ok(())
        }
        async fn reactivate(&self, _sub: &str) -> Result<(), BoxError> {
            Ok(())
        }
        async fn any_subject_has_role(&self, role: &str) -> Result<bool, BoxError> {
            Ok(self.grants.lock().unwrap().iter().any(|(_, r)| r == role))
        }
    }

    #[tokio::test]
    async fn bootstrap_seeds_first_admin_then_is_idempotent() {
        let a = FakeAuthoring::default();
        // Empty store → seeds the configured bootstrap admin.
        bootstrap_admin(&a, "admin", Some("u-boot")).await.unwrap();
        assert_eq!(a.grants.lock().unwrap().as_slice(), &[("u-boot".to_owned(), "admin".to_owned())]);
        // Second run → an admin already exists, so no further grant is authored.
        bootstrap_admin(&a, "admin", Some("u-boot")).await.unwrap();
        assert_eq!(a.grants.lock().unwrap().len(), 1, "bootstrap must not re-seed once an admin exists");
    }

    #[tokio::test]
    async fn bootstrap_without_configured_sub_is_a_noop() {
        let a = FakeAuthoring::default();
        bootstrap_admin(&a, "admin", None).await.unwrap();
        assert!(a.grants.lock().unwrap().is_empty(), "no bootstrap sub → no seed");
    }
}
