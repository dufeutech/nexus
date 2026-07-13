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

mod audit_api;

use std::collections::BTreeMap;
use std::env::var;
use std::error::Error;
#[cfg(not(unix))]
use std::future::pending;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Request, State};
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

use identity_core::audit::{
    AuditCtx, DenialEvent, DenialKind, ACTOR_AUTH_DISABLED, ACTOR_LEGACY_SHARED,
    ASSERTED_OPERATOR_MAX_BYTES, TRACE_ID_MAX_BYTES,
};
use identity_core::authz::{AuthzAuthoring, AuthzResolver};
use identity_core::store::{BoxError, ProfileStore};
use identity_core::telemetry;
use identity_core::SecretHasher;
use store_postgres::{
    HmacSecretHasher, IssueKeyRequest, PgAdminAuditStore, PgAdminTokenStore, PgApiKeyStore,
    PgAuditMaintenance, PgProfileStore,
};

use crate::audit_api::{
    export_audit_events, issue_admin_token, list_audit_events, retention_days_from_env,
    retention_purge, revoke_admin_token, rotate_admin_token,
};

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
    /// Read the creator's live memberships for the "a key may not exceed its creator"
    /// issuance check (`customer-api-keys` task 6.3).
    profiles: Arc<dyn ProfileStore>,
    /// The api-key store (issue/rotate/revoke). `None` when key management is not
    /// configured (`APIKEY_HMAC_PEPPER` unset) — the `/apikeys` endpoints then 503.
    api_keys: Option<Arc<PgApiKeyStore>>,
    /// The admin audit ledger's denial/read surface (admin-action-audit).
    audit: Arc<PgAdminAuditStore>,
    /// The admin authentication configuration (admin-action-audit D4/D5):
    /// individually identifiable named tokens, with an explicit legacy-shared
    /// migration mode. Fail-closed — the server refuses to start without an
    /// explicit choice, so it is never silently open.
    auth: AdminAuth,
    /// Per-source rate limit for DENIAL ledger writes only (an unauthenticated
    /// scanner must not flood the ledger); mutation events are never limited.
    denials: Arc<DenialLimiter>,
}

/// How admin callers authenticate (admin-action-audit D4/D5). Every accepted
/// credential resolves to an individually identifiable actor id — a named
/// token's `token_id`, or the reserved `legacy-shared` / `auth-disabled` ids.
#[derive(Clone)]
struct AdminAuth {
    /// Auth explicitly disabled at startup (`IDENTITY_ADMIN_AUTH_DISABLED=true`,
    /// trusted-network/dev only): requests pass through as `auth-disabled`.
    disabled: bool,
    /// The named-token verifier (`ADMIN_TOKEN_PEPPER` set). `None` = named
    /// tokens unconfigured; provisioning endpoints then answer 503.
    tokens: Option<Arc<PgAdminTokenStore>>,
    /// The legacy shared token (`IDENTITY_ADMIN_TOKEN`), honored ONLY while
    /// `legacy_ok` (design D5's migration mode).
    legacy: Option<Arc<str>>,
    /// `ADMIN_LEGACY_TOKEN_OK=true` — the explicit, deprecation-warned gate for
    /// the shared token. Default off; flipping it off is the migration's
    /// completion step (and re-enabling it is the rollback).
    legacy_ok: bool,
}

/// Fixed-window per-source counter bounding DENIAL event writes (design risk:
/// "denial-event flooding of the ledger by an unauthenticated scanner"). Only
/// the ledger WRITE is limited — the 401 itself and its log line always happen.
struct DenialLimiter {
    window: Duration,
    max_per_window: u32,
    state: Mutex<BTreeMap<String, (Instant, u32)>>,
}

impl DenialLimiter {
    /// At most `max_per_window` recorded denials per source per `window`.
    const fn new(window: Duration, max_per_window: u32) -> Self {
        Self { window, max_per_window, state: Mutex::new(BTreeMap::new()) }
    }

    /// Whether a denial from `source` may be recorded now.
    fn allow(&self, source: &str) -> bool {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // Opportunistically drop stale windows so a scanner cycling source
        // addresses cannot grow the map without bound.
        if state.len() >= 4096 {
            state.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = state.entry(source.to_owned()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 = entry.1.saturating_add(1);
        let allowed = entry.1 <= self.max_per_window;
        drop(state);
        allowed
    }
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

/// Read a header value if present, valid UTF-8, non-empty, and within `max`
/// bytes; anything else is treated as absent (correlation data is best-effort).
fn header_capped(headers: &HeaderMap, name: &str, max: usize) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= max)
        .map(str::to_owned)
}

/// The caller-asserted operator (`x-acting-operator`, spec: recorded verbatim,
/// confers nothing). Over-long or non-UTF-8 values are REJECTED (400) rather
/// than truncated — a truncated assertion would not be verbatim. Only ever
/// evaluated AFTER authentication succeeded, so it cannot influence an auth
/// outcome.
fn asserted_operator(headers: &HeaderMap) -> Result<Option<String>, Box<Response>> {
    let Some(raw) = headers.get("x-acting-operator") else {
        return Ok(None);
    };
    let rejection = || {
        Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "invalid_acting_operator",
                    "hint": "UTF-8, non-empty, at most the documented byte length",
                    "max_bytes": ASSERTED_OPERATOR_MAX_BYTES,
                })),
            )
                .into_response(),
        )
    };
    let Ok(value) = raw.to_str() else {
        return Err(rejection());
    };
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > ASSERTED_OPERATOR_MAX_BYTES {
        return Err(rejection());
    }
    Ok(Some(value.to_owned()))
}

/// Resolve a presented bearer secret to its individually identifiable actor id
/// (admin-action-audit D4/D5): a named token's id via the peppered-hash lookup,
/// or the reserved `legacy-shared` id while the migration flag allows the old
/// shared token (compared in constant time, deprecation-warned per use).
/// `None` = not authenticated.
async fn resolve_actor(auth: &AdminAuth, presented: &str) -> Result<Option<String>, BoxError> {
    if let Some(tokens) = &auth.tokens
        && let Some(token_id) = tokens.lookup(presented).await?
    {
        return Ok(Some(token_id));
    }
    if auth.legacy_ok
        && let Some(legacy) = auth.legacy.as_deref()
        && ct_eq(presented.as_bytes(), legacy.as_bytes())
    {
        warn!(
            "legacy shared admin token used (ADMIN_LEGACY_TOKEN_OK=true) — provision a named \
             token for this caller and flip the flag off (admin-action-audit migration)"
        );
        return Ok(Some(ACTOR_LEGACY_SHARED.to_owned()));
    }
    Ok(None)
}

/// The 401 tail: a best-effort, rate-limited denial ledger event (spec:
/// "Denied admin access is recorded"). A failed denial write logs an error and
/// STAYS a denial — it never converts into an acceptance and never 500s.
/// Never carries the presented credential. (Owned data only, so the middleware
/// future stays `Send` — the request is not held across this await.)
async fn deny(state: &App, had_bearer: bool, correlation: (Option<String>, Option<String>)) -> Response {
    let (source_ip, trace_id) = correlation;
    let source_key = source_ip.clone().unwrap_or_else(|| "unknown".to_owned());
    if state.denials.allow(&source_key) {
        let denial = DenialEvent {
            kind: if had_bearer { DenialKind::Invalid } else { DenialKind::Absent },
            source_ip,
            trace_id,
        };
        if let Err(e) = state.audit.record_auth_denial(&denial).await {
            warn!(error = %e, "denial event write failed (still denying)");
        }
    }
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response()
}

/// Admin-token gate (admin-action-audit D4/D5): every authoring/read endpoint
/// requires a bearer credential that resolves to an individually identifiable
/// actor — a named token from `identity.admin_tokens` (peppered-HMAC indexed
/// lookup; deterministic HMAC comparison leaks nothing without the pepper) or,
/// during migration only, the legacy shared token (constant-time compare
/// preserved). On success the request carries an [`AuditCtx`] with the actor
/// and transport facts for the store layer's same-transaction audit recording.
/// `/healthz` is intentionally NOT behind this (liveness). When auth is
/// explicitly disabled at startup, requests pass through as `auth-disabled`.
async fn require_auth(State(s): State<App>, mut req: Request, next: Next) -> Response {
    // Correlation facts ride BOTH paths: the mutation's audit context and the
    // denial event.
    let source_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string());
    let trace_id = header_capped(req.headers(), "traceparent", TRACE_ID_MAX_BYTES);

    let actor = if s.auth.disabled {
        ACTOR_AUTH_DISABLED.to_owned()
    } else {
        let presented = bearer_token(req.headers());
        let resolved = match &presented {
            Some(secret) => match resolve_actor(&s.auth, secret).await {
                Ok(resolved) => resolved,
                // A verifier failure (e.g. the token table unreachable) is a
                // 500, not a 401: fail closed without recording a false denial.
                Err(e) => return internal(e),
            },
            None => None,
        };
        if let Some(actor) = resolved {
            actor
        } else {
            METRICS.mutations.add(1, &[KeyValue::new("op", "unauthorized")]);
            // Method + path only — never the presented credential. `had_bearer`
            // distinguishes a bad token from a missing/malformed header.
            warn!(
                method = %req.method(),
                path = %req.uri().path(),
                had_bearer = presented.is_some(),
                "unauthorized authz-admin request"
            );
            return deny(&s, presented.is_some(), (source_ip, trace_id)).await;
        }
    };

    // Validated only after authentication: an assertion can never change an
    // auth outcome — an invalid credential + assertion is rejected identically.
    let operator = match asserted_operator(req.headers()) {
        Ok(operator) => operator,
        Err(rejection) => return *rejection,
    };
    let _prior = req.extensions_mut().insert(AuditCtx {
        actor,
        asserted_operator: operator,
        trace_id,
        source_ip,
    });
    next.run(req).await
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
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<RoleBody>,
) -> Response {
    // `sub` is a user id (PII) — keep it out of info logs.
    info!(op = "assign_role", "authoring");
    authored(s.authoring.assign_role(&sub, &body.role, &actx).await, "assign_role")
}

async fn revoke_role(
    State(s): State<App>,
    Path((sub, role)): Path<(String, String)>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    info!(op = "revoke_role", "authoring");
    authored(s.authoring.revoke_role(&sub, &role, &actx).await, "revoke_role")
}

async fn grant_entitlement(
    State(s): State<App>,
    Path(sub): Path<String>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<EntitlementBody>,
) -> Response {
    info!(op = "grant_entitlement", "authoring");
    authored(
        s.authoring.grant_entitlement(&sub, &body.entitlement, &actx).await,
        "grant_entitlement",
    )
}

async fn revoke_entitlement(
    State(s): State<App>,
    Path((sub, entitlement)): Path<(String, String)>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    info!(op = "revoke_entitlement", "authoring");
    authored(
        s.authoring.revoke_entitlement(&sub, &entitlement, &actx).await,
        "revoke_entitlement",
    )
}

async fn suspend(
    State(s): State<App>,
    Path(sub): Path<String>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    info!(op = "suspend", "authoring");
    authored(s.authoring.suspend(&sub, &actx).await, "suspend")
}

async fn reactivate(
    State(s): State<App>,
    Path(sub): Path<String>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    info!(op = "reactivate", "authoring");
    authored(s.authoring.reactivate(&sub, &actx).await, "reactivate")
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

// --------------------------------------------------------------------------- //
// customer-api-keys: the key-management surface (issue / rotate / revoke).
// --------------------------------------------------------------------------- //

/// Wall-clock seconds since the Unix epoch — the basis for a key's absolute `expires_at`.
fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// 400 for an invalid issuance request (the message names the problem — no secrets).
fn bad_request(message: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response()
}

/// 503 when key management is not configured (no `APIKEY_HMAC_PEPPER`).
fn key_mgmt_unconfigured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "api key management not configured" })),
    )
        .into_response()
}

/// The "a key may not exceed its creator" gate (task 6.3), isolated for unit tests:
/// every requested scope MUST be a workspace the creator is a live member of, and at
/// least one scope is required (an unscoped key resolves to no authority). Returns the
/// offending scope on rejection.
fn scopes_within_creator(requested: &[String], member_workspaces: &[String]) -> Result<(), String> {
    if requested.is_empty() {
        return Err("at least one scope (workspace id) is required".to_owned());
    }
    for ws in requested {
        if !member_workspaces.iter().any(|m| m == ws) {
            return Err(format!("scope '{ws}' exceeds the creator's memberships"));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct IssueKeyBody {
    /// The creating user's subject — the human the key acts on behalf of.
    creator_sub: String,
    /// The workspace ids the key may act in (must be a subset of the creator's live
    /// memberships).
    #[serde(default)]
    scopes: Vec<String>,
    /// Optional lifetime; absent = a non-expiring key.
    #[serde(default)]
    expires_in_seconds: Option<i64>,
}

/// Issue a new PAT for a creating user (task 6.1). Human-only issuance is enforced at the
/// deployment boundary (this surface is admin-token gated / reached only after human
/// auth); "may not exceed the creator" is enforced HERE against the creator's live
/// memberships AND again at resolve time in the sidecar (the real guarantee). The secret
/// is returned exactly once and never persisted in plaintext.
async fn issue_api_key(
    State(s): State<App>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<IssueKeyBody>,
) -> Response {
    let Some(store) = s.api_keys.as_ref() else {
        return key_mgmt_unconfigured();
    };
    if body.creator_sub.trim().is_empty() {
        return bad_request("creator_sub is required");
    }
    // The creator's live membership workspaces bound the key's scopes.
    let member_workspaces = match s.profiles.get(&body.creator_sub).await {
        Ok(Some(p)) => p.memberships.iter().map(|m| m.workspace_id.clone()).collect::<Vec<_>>(),
        Ok(None) => Vec::new(),
        Err(e) => return internal(e),
    };
    if let Err(msg) = scopes_within_creator(&body.scopes, &member_workspaces) {
        return bad_request(&msg);
    }
    let request = IssueKeyRequest {
        creator_sub: &body.creator_sub,
        scopes: &body.scopes,
        expires_in_seconds: body.expires_in_seconds,
        now_epoch: now_epoch(),
    };
    match store.issue(&request, &actx).await {
        Ok(issued) => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "issue_api_key")]);
            // Audit (task 7.1): the key id is not PII; the secret is NEVER logged.
            info!(op = "issue_api_key", key_id = %issued.key_id, "authoring");
            (
                StatusCode::CREATED,
                Json(json!({
                    "key_id": issued.key_id,
                    "secret": issued.secret,
                    "expires_at": issued.expires_at,
                })),
            )
                .into_response()
        }
        Err(e) => internal(e),
    }
}

/// Rotate a key (task 6.2): mint a new secret under a preserved lineage with the SAME
/// scopes (no widening) and revoke the old one. Returns the new secret once, or 404 if
/// the key id is not an active key.
async fn rotate_api_key(
    State(s): State<App>,
    Path(key_id): Path<String>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    let Some(store) = s.api_keys.as_ref() else {
        return key_mgmt_unconfigured();
    };
    match store.rotate(&key_id, &actx).await {
        Ok(Some(issued)) => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "rotate_api_key")]);
            info!(op = "rotate_api_key", key_id = %issued.key_id, "authoring");
            (
                StatusCode::CREATED,
                Json(json!({
                    "key_id": issued.key_id,
                    "secret": issued.secret,
                    "expires_at": issued.expires_at,
                })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no active key with that id" })),
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

/// Revoke a key (task 6.2): flip it to `revoked` so the sidecar rejects it on the next
/// request. Idempotent — revoking an already-revoked/unknown key is a 200 with
/// `revoked: false`.
async fn revoke_api_key(
    State(s): State<App>,
    Path(key_id): Path<String>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    let Some(store) = s.api_keys.as_ref() else {
        return key_mgmt_unconfigured();
    };
    match store.revoke(&key_id, &actx).await {
        Ok(revoked) => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "revoke_api_key")]);
            info!(op = "revoke_api_key", %key_id, revoked, "authoring");
            (StatusCode::OK, Json(json!({ "result": "ok", "revoked": revoked }))).into_response()
        }
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
        // A no-op startup writes nothing — no grant, no audit event (spec:
        // "A no-op bootstrap is silent").
        info!(role = %admin_role, "bootstrap: an administrator already exists; skipping seed");
        return Ok(());
    }
    // The grant + its `bootstrap.grant` audit event commit in one transaction
    // (admin-action-audit D8), attributed to the reserved bootstrap actor.
    authoring.bootstrap_grant(sub, admin_role).await?;
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
    // Depend on the PORTS (spec R5): the same store object satisfies all three.
    let authoring: Arc<dyn AuthzAuthoring> = store.clone();
    let profiles: Arc<dyn ProfileStore> = store.clone();
    let resolver: Arc<dyn AuthzResolver> = store;

    // Admin audit ledger (admin-action-audit): its schema must exist BEFORE the
    // first authoring write (the bootstrap grant records an event in the same
    // transaction), so bootstrap it here, fail-fatal.
    let audit = match PgAdminAuditStore::connect(&pg_url).await {
        Ok(audit_store) => match audit_store.init_schema().await {
            Ok(()) => Arc::new(audit_store),
            Err(e) => {
                error!(error = %e, "audit schema init failed; refusing to start unauditable");
                return Err(e);
            }
        },
        Err(e) => {
            error!(error = %e, "audit store connect failed; refusing to start unauditable");
            return Err(e);
        }
    };

    // Admin auth (admin-action-audit D4/D5), fail-closed: refuse to start
    // without an explicit choice. Named tokens are the credential of record
    // (ADMIN_TOKEN_PEPPER enables verification against identity.admin_tokens);
    // the legacy shared IDENTITY_ADMIN_TOKEN is honored ONLY behind the
    // explicit ADMIN_LEGACY_TOKEN_OK migration flag (attributed
    // `legacy-shared`, deprecation-warned per use). BREAKING: a deployment
    // that only sets IDENTITY_ADMIN_TOKEN must now also set
    // ADMIN_LEGACY_TOKEN_OK=true (step 1 of the migration).
    let auth_disabled = matches!(
        env("IDENTITY_ADMIN_AUTH_DISABLED", "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    );
    let legacy_ok = matches!(
        env("ADMIN_LEGACY_TOKEN_OK", "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    );
    let auth = if auth_disabled {
        warn!("IDENTITY_ADMIN_AUTH_DISABLED=true — authz-admin endpoints are UNAUTHENTICATED");
        AdminAuth { disabled: true, tokens: None, legacy: None, legacy_ok: false }
    } else {
        let admin_pepper = env("ADMIN_TOKEN_PEPPER", "");
        let tokens = if admin_pepper.trim().is_empty() {
            None
        } else {
            let hasher: Arc<dyn SecretHasher> =
                Arc::new(HmacSecretHasher::new(admin_pepper.into_bytes()));
            Some(Arc::new(PgAdminTokenStore::new(&audit, hasher)))
        };
        let legacy_token = env("IDENTITY_ADMIN_TOKEN", "");
        let legacy: Option<Arc<str>> = if legacy_token.trim().is_empty() {
            None
        } else {
            Some(Arc::from(legacy_token.as_str()))
        };
        if legacy_ok && legacy.is_none() {
            error!("ADMIN_LEGACY_TOKEN_OK=true but IDENTITY_ADMIN_TOKEN is unset; refusing to start.");
            return Err("missing IDENTITY_ADMIN_TOKEN for legacy mode".into());
        }
        if tokens.is_none() && !legacy_ok {
            error!(
                "no admin auth configured; refusing to start open. Set ADMIN_TOKEN_PEPPER \
                 (named admin tokens), or ADMIN_LEGACY_TOKEN_OK=true with IDENTITY_ADMIN_TOKEN \
                 (migration mode), or IDENTITY_ADMIN_AUTH_DISABLED=true (trusted-network/dev only)."
            );
            return Err("missing admin auth configuration".into());
        }
        if legacy_ok {
            warn!(
                "legacy shared-token mode enabled (ADMIN_LEGACY_TOKEN_OK=true) — provision named \
                 tokens per caller, then flip this flag off"
            );
        }
        AdminAuth {
            disabled: false,
            tokens,
            legacy: if legacy_ok { legacy } else { None },
            legacy_ok,
        }
    };

    // Audit retention (admin-action-audit D7): startup-validated floor; the
    // periodic purge — the only deleter — runs under the separate maintenance
    // role when its connection is configured.
    let retention_days = match retention_days_from_env(&env("AUDIT_RETENTION_DAYS", "")) {
        Ok(days) => days,
        Err(msg) => {
            error!("{msg}");
            return Err(msg.into());
        }
    };
    let maintenance_url = env("AUDIT_MAINTENANCE_PG_URL", "");
    if maintenance_url.trim().is_empty() {
        info!(
            retention_days,
            "AUDIT_MAINTENANCE_PG_URL unset — audit retention purge must run externally under \
             the maintenance role"
        );
    } else {
        match PgAuditMaintenance::connect(&maintenance_url).await {
            Ok(maintenance) => {
                let _task = tokio::spawn(retention_purge(maintenance, retention_days));
                info!(retention_days, "audit retention purge enabled (maintenance role)");
            }
            Err(e) => {
                error!(error = %e, "audit maintenance connection failed; refusing to start misconfigured");
                return Err(e);
            }
        }
    }

    // customer-api-keys: key management is ENABLED when APIKEY_HMAC_PEPPER is set (the
    // same pepper the sidecar verifies with). The api-key store shares the identity DB
    // (PROFILE_PG_URL) and owns its idempotent schema setup here. Without a pepper the
    // /apikeys endpoints answer 503 (fail closed — never mint a key we can't hash).
    let api_keys = if let Some(pepper) = var("APIKEY_HMAC_PEPPER").ok().filter(|p| !p.trim().is_empty())
    {
        let hasher: Arc<dyn SecretHasher> = Arc::new(HmacSecretHasher::new(pepper.into_bytes()));
        match PgApiKeyStore::connect(&pg_url, hasher).await {
            Ok(ks) => match ks.init_schema().await {
                Ok(()) => {
                    info!("customer-api-key management ENABLED (/apikeys)");
                    Some(Arc::new(ks))
                }
                Err(e) => {
                    error!(error = %e, "api_keys schema init failed -> key management OFF");
                    None
                }
            },
            Err(e) => {
                error!(error = %e, "api-key store connect failed -> key management OFF");
                None
            }
        }
    } else {
        info!("APIKEY_HMAC_PEPPER unset -> customer-api-key management OFF");
        None
    };

    // Bootstrap the first administrator before serving (spec R4). A failure here is
    // fatal — an unreachable authoring surface is worse than a crash-loop the operator
    // can see and fix.
    bootstrap_admin(authoring.as_ref(), &admin_role, bootstrap_sub.as_deref()).await?;

    let app = App {
        authoring,
        resolver,
        profiles,
        api_keys,
        audit,
        auth,
        // Bound DENIAL ledger writes per source (design risk: scanner flooding);
        // 30/min/source keeps real break-in attempts visible without unbounded growth.
        denials: Arc::new(DenialLimiter::new(Duration::from_mins(1), 30)),
    };

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
        // customer-api-keys: issue / rotate / revoke Personal Access Tokens.
        .route("/apikeys", post(issue_api_key))
        .route("/apikeys/{key_id}/rotate", post(rotate_api_key))
        .route("/apikeys/{key_id}/revoke", post(revoke_api_key))
        // Audit ledger read surface + named-token provisioning (admin-action-audit
        // D4/D6) — same admin gate; the ledger has NO mutation endpoints.
        .route("/audit/events", get(list_audit_events))
        .route("/audit/events/export", get(export_audit_events))
        .route("/admin-tokens", post(issue_admin_token))
        .route("/admin-tokens/{id}/rotate", post(rotate_admin_token))
        .route("/admin-tokens/{id}/revoke", post(revoke_admin_token))
        .route_layer(middleware::from_fn_with_state(app.clone(), require_auth));

    let router = data
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, request_timeout()))
        .with_state(app);

    let listener = TcpListener::bind("0.0.0.0:9300").await?;
    info!(
        admin_role = %admin_role,
        "authz-admin on :9300 (/authz/{{sub}}[+/roles,/entitlements,/suspend,/reactivate], \
         /apikeys, /audit/events[+/export], /admin-tokens, /healthz)"
    );
    // ConnectInfo so audit events record the caller network source.
    if let Err(e) = axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
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

    // ---- customer-api-keys: "a key may not exceed its creator" (task 6.3) --- //

    #[test]
    fn scopes_must_be_a_subset_of_the_creators_memberships() {
        let member = vec!["ws-1".to_owned(), "ws-2".to_owned()];
        // A subset of the creator's memberships is accepted.
        assert!(scopes_within_creator(&["ws-1".to_owned()], &member).is_ok());
        assert!(scopes_within_creator(&["ws-1".to_owned(), "ws-2".to_owned()], &member).is_ok());
        // A scope the creator is not a member of is rejected (may not exceed the creator).
        let err = scopes_within_creator(&["ws-1".to_owned(), "ws-3".to_owned()], &member)
            .expect_err("ws-3 exceeds the creator");
        assert!(err.contains("ws-3"), "the rejection names the offending scope");
        // An unscoped key (no scopes) is rejected — it would resolve to no authority.
        assert!(scopes_within_creator(&[], &member).is_err());
        // A creator with no memberships can scope a key to nothing.
        assert!(scopes_within_creator(&["ws-1".to_owned()], &[]).is_err());
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
        async fn assign_role(&self, sub: &str, role: &str, _actx: &AuditCtx) -> Result<(), BoxError> {
            self.grants.lock().unwrap().push((sub.to_owned(), role.to_owned()));
            Ok(())
        }
        async fn revoke_role(&self, _sub: &str, _role: &str, _actx: &AuditCtx) -> Result<(), BoxError> {
            Ok(())
        }
        async fn grant_entitlement(
            &self,
            _sub: &str,
            _e: &str,
            _actx: &AuditCtx,
        ) -> Result<(), BoxError> {
            Ok(())
        }
        async fn revoke_entitlement(
            &self,
            _sub: &str,
            _e: &str,
            _actx: &AuditCtx,
        ) -> Result<(), BoxError> {
            Ok(())
        }
        async fn suspend(&self, _sub: &str, _actx: &AuditCtx) -> Result<(), BoxError> {
            Ok(())
        }
        async fn reactivate(&self, _sub: &str, _actx: &AuditCtx) -> Result<(), BoxError> {
            Ok(())
        }
        async fn any_subject_has_role(&self, role: &str) -> Result<bool, BoxError> {
            Ok(self.grants.lock().unwrap().iter().any(|(_, r)| r == role))
        }
        async fn bootstrap_grant(&self, sub: &str, role: &str) -> Result<(), BoxError> {
            // The fake records the grant like a normal assign; the real adapter
            // additionally writes the bootstrap.grant audit event in-tx.
            self.grants.lock().unwrap().push((sub.to_owned(), role.to_owned()));
            Ok(())
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
