//! Shared application core: the `App` state, its metrics, config loaders, the
//! admin-token gate, and the HTTP resilience layering every handler module
//! builds on.

use std::collections::{BTreeMap, BTreeSet};
use std::env::var;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, StatusCode};
use headers::authorization::Bearer;
use headers::{Authorization, HeaderMapExt};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use tower_http::timeout::TimeoutLayer;
// first-party-telemetry: a per-request span at INFO so admin operations root their
// own trace (DEBUG default would be filtered out and never exported).
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;
use opentelemetry::metrics::Counter;
use opentelemetry::{global, KeyValue};
use serde_json::json;
use tracing::{error, warn};

use router_core::audit::{
    AuditCtx, DenialEvent, DenialKind, ACTOR_AUTH_DISABLED, ACTOR_LEGACY_SHARED,
    ASSERTED_OPERATOR_MAX_BYTES, TRACE_ID_MAX_BYTES,
};
use router_core::domain::PoolSet;
use router_core::plan::{DomainLimit, PlanLimits};
use router_core::store::{BoxError, InvalidationPublisher};
use router_core::verify::{ct_eq, OwnershipProof};
use store_postgres::{PgAdminTokenStore, PgRoutingStore};

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): every control mutation is counted through the
// OTel meter (push path via router_core::telemetry). The counter name DROPS the
// Prometheus `_total` suffix — Prometheus's OTLP receiver re-appends it, so the
// stored series keeps its name (control_mutations_total) and dashboards keep
// working. The `op` label carries the mutation kind, exactly as before.
// --------------------------------------------------------------------------- //
pub(crate) struct Metrics {
    pub(crate) mutations: Counter<u64>,
}

pub(crate) static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("control-plane");
    Metrics {
        mutations: meter.u64_counter("control_mutations").build(),
    }
});

/// Total per-request timeout for both HTTP surfaces (http-request-resilience):
/// operator-tunable via `HTTP_REQUEST_TIMEOUT_SECS` with a finite 30s default —
/// never unbounded (and well above the 5s DB statement cap).
pub(crate) fn request_timeout() -> Duration {
    Duration::from_secs(
        var("HTTP_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
    )
}

/// Bound a router with the resilience layers (http-request-resilience): a
/// request-body cap plus a total per-request timeout answering 408, so a
/// slow/stalled client cannot hold a connection/task indefinitely. The admin
/// bodies are small JSON — cap them so a malformed or hostile caller can't
/// force an unbounded buffer (defense-in-depth).
pub(crate) fn resilient<S>(router: Router<S>, timeout: Duration) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout))
        // Root a trace per admin operation (first-party-telemetry). INFO so it isn't
        // filtered out; the handler's logs correlate to it and it exports when OTLP
        // is enabled. No-op cost when telemetry is off (span still cheap).
        .layer(TraceLayer::new_for_http().make_span_with(DefaultMakeSpan::new().level(Level::INFO)))
}

#[derive(Clone)]
pub(crate) struct App {
    pub(crate) store: Arc<PgRoutingStore>,
    /// Where invalidations are published (RFC C16). pg_notify by default; a
    /// fan-out over pg_notify + NATS when `NATS_URL` is set, so cross-region
    /// subscribers get the signal while in-region pg_notify subscribers keep
    /// theirs. Behind the `InvalidationPublisher` port so the transport is an
    /// adapter swap, never a control-plane change.
    pub(crate) publisher: Arc<dyn InvalidationPublisher>,
    /// Data-driven plan → domain-limit table for the declare quota gate (RFC C5).
    pub(crate) limits: Arc<PlanLimits>,
    /// Data-driven allow-list of backend pools (RFC C15). Loaded from config so a
    /// new pool is a config + edge-cluster change, never a recompile.
    pub(crate) pools: Arc<PoolSet>,
    /// Ownership-proof resolver for TXT verification (RFC C4).
    pub(crate) verifier: Arc<dyn OwnershipProof>,
    /// Challenge token lifetime, seconds (RFC C4).
    pub(crate) challenge_ttl: i64,
    /// How long a domain may stay pending before it expires and frees quota,
    /// seconds (RFC C3). `0` disables expiry.
    pub(crate) pending_ttl: i64,
    /// The admin authentication configuration (admin-action-audit D4/D5):
    /// individually identifiable named tokens, with an explicit legacy-shared
    /// migration mode. Fail-closed — the server refuses to start without an
    /// explicit choice, so it is never silently open.
    pub(crate) auth: AdminAuth,
    /// Per-source rate limit for DENIAL ledger writes only (an unauthenticated
    /// scanner must not flood the ledger); mutation events are never limited.
    pub(crate) denials: Arc<DenialLimiter>,
}

/// How admin callers authenticate (admin-action-audit D4/D5). Every accepted
/// credential resolves to an individually identifiable actor id — a named
/// token's `token_id`, or the reserved `legacy-shared` / `auth-disabled` ids.
#[derive(Clone)]
pub(crate) struct AdminAuth {
    /// Auth explicitly disabled at startup (`CONTROL_AUTH_DISABLED=true`,
    /// trusted-network/dev only): requests pass through as `auth-disabled`.
    pub(crate) disabled: bool,
    /// The named-token verifier (`ADMIN_TOKEN_PEPPER` set). `None` = named
    /// tokens unconfigured; provisioning endpoints then answer 503.
    pub(crate) tokens: Option<Arc<PgAdminTokenStore>>,
    /// The legacy shared token (`CONTROL_AUTH_TOKEN`), honored ONLY while
    /// `legacy_ok` (design D5's migration mode).
    pub(crate) legacy: Option<Arc<str>>,
    /// `ADMIN_LEGACY_TOKEN_OK=true` — the explicit, deprecation-warned gate for
    /// the shared token. Default off; flipping it off is the migration's
    /// completion step (and re-enabling it is the rollback).
    pub(crate) legacy_ok: bool,
}

/// Fixed-window per-source counter bounding DENIAL event writes (design risk:
/// "denial-event flooding of the ledger by an unauthenticated scanner"). Only
/// the ledger WRITE is limited — the 401 itself and its log line always happen.
pub(crate) struct DenialLimiter {
    window: Duration,
    max_per_window: u32,
    state: Mutex<BTreeMap<String, (Instant, u32)>>,
}

impl DenialLimiter {
    /// At most `max_per_window` recorded denials per source per `window`.
    pub(crate) const fn new(window: Duration, max_per_window: u32) -> Self {
        Self { window, max_per_window, state: Mutex::new(BTreeMap::new()) }
    }

    /// Whether a denial from `source` may be recorded now.
    pub(crate) fn allow(&self, source: &str) -> bool {
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

/// Uniform 500 for an unexpected store/adapter error. The underlying error is
/// LOGGED (with full detail for operators) but NEVER returned to the client — a
/// raw `e.to_string()` can leak connection strings, SQL, or internal topology.
pub(crate) fn internal<E: fmt::Display>(e: E) -> Response {
    error!(error = %e, "control-plane error");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "internal_error" }))).into_response()
}

/// Load the plan → limit table from configuration (RFC C5). `ROUTING_PLAN_LIMITS`
/// is a JSON object mapping plan name to an integer cap, or `null` for unbounded
/// (e.g. `{"free":1,"pro":25,"enterprise":null}`). Absent/invalid config falls
/// back to the most conservative table so the gate never fails open.
pub(crate) fn load_plan_limits() -> PlanLimits {
    fn conservative() -> PlanLimits {
        let mut m = BTreeMap::new();
        m.insert("free".to_owned(), DomainLimit::Finite(1));
        PlanLimits::new(m)
    }
    let raw = env("ROUTING_PLAN_LIMITS", "");
    if raw.trim().is_empty() {
        warn!("ROUTING_PLAN_LIMITS unset; using conservative default (free=1)");
        return conservative();
    }
    match serde_json::from_str::<BTreeMap<String, Option<u32>>>(&raw) {
        Ok(map) => {
            let limits = map
                .into_iter()
                .map(|(k, v)| (k, v.map_or(DomainLimit::Unbounded, DomainLimit::Finite)))
                .collect();
            PlanLimits::new(limits)
        }
        Err(e) => {
            error!(error = %e, "invalid ROUTING_PLAN_LIMITS; using conservative default (free=1)");
            conservative()
        }
    }
}

/// Load the backend-pool allow-list from configuration (RFC C15). `ROUTING_POOLS`
/// is a JSON array of pool names (e.g. `["application","api","checkout","assets"]`)
/// that MUST match the edge data plane's `pool_*` cluster set. Absent/invalid
/// config falls back to the established four pools the shipped edge configs carry,
/// so an unconfigured deploy keeps working — always a finite, fail-closed set
/// (an unknown `target_pool` is rejected), never an open "any destination".
pub(crate) fn load_pools() -> PoolSet {
    fn default_pools() -> PoolSet {
        PoolSet::new(
            ["application", "api", "checkout", "assets"]
                .into_iter()
                .map(String::from)
                .collect(),
        )
    }
    let raw = env("ROUTING_POOLS", "");
    if raw.trim().is_empty() {
        warn!("ROUTING_POOLS unset; using default pool set (application, api, checkout, assets)");
        return default_pools();
    }
    match serde_json::from_str::<BTreeSet<String>>(&raw) {
        Ok(set) if !set.is_empty() => PoolSet::new(set),
        Ok(_) => {
            error!("ROUTING_POOLS is empty; using default pool set");
            default_pools()
        }
        Err(e) => {
            error!(error = %e, "invalid ROUTING_POOLS; using default pool set");
            default_pools()
        }
    }
}

impl App {
    /// Publish the invalidation for a domain key (best-effort; logged on failure
    /// since the cache TTL is the backstop).
    pub(crate) async fn invalidate(&self, domain: &str) {
        if let Err(e) = self.publisher.publish(domain).await {
            warn!(error = %e, domain, "notify failed (cache TTL will self-heal)");
        }
    }
}

pub(crate) fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
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
        && ct_eq(presented, legacy)
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
        if let Err(e) = state.store.record_auth_denial(&denial).await {
            warn!(error = %e, "denial event write failed (still denying)");
        }
    }
    (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response()
}

/// Admin-token gate (RFC C16 admin boundary, admin-action-audit D4/D5): every
/// DATA endpoint requires a bearer credential that resolves to an individually
/// identifiable actor — a named token from `routing.admin_tokens` (peppered-HMAC
/// indexed lookup; deterministic HMAC comparison leaks nothing without the
/// pepper) or, during migration only, the legacy shared token (constant-time
/// compare preserved). On success the request carries an [`AuditCtx`] with the
/// actor and transport facts for the store layer's same-transaction audit
/// recording. `/healthz` is intentionally NOT behind this (liveness). When auth
/// is explicitly disabled at startup, requests pass through as `auth-disabled`.
pub(crate) async fn require_auth(State(s): State<App>, mut req: Request, next: Next) -> Response {
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
        // Parse `Authorization: Bearer <token>` with the vetted `headers`
        // typed-header parser (RFC 7235: case-insensitive scheme, correct
        // whitespace handling) rather than a hand-rolled split.
        let bearer = req.headers().typed_get::<Authorization<Bearer>>();
        let resolved = match &bearer {
            Some(auth) => match resolve_actor(&s.auth, auth.token()).await {
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
                had_bearer = bearer.is_some(),
                "unauthorized control-plane request"
            );
            return deny(&s, bearer.is_some(), (source_ip, trace_id)).await;
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

// --------------------------------------------------------------------------- //
// admin-action-audit tests: the operator-assertion boundary and the denial
// rate limiter (pure pieces; the auth flow itself is driven by the e2e suite).
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod audit_gate_tests {
    use super::{
        asserted_operator, header_capped, DenialLimiter, Duration, HeaderMap,
        ASSERTED_OPERATOR_MAX_BYTES,
    };

    #[test]
    fn asserted_operator_is_verbatim_or_rejected() {
        let mut headers = HeaderMap::new();
        // Absent → None (the assertion is optional).
        assert_eq!(asserted_operator(&headers).unwrap(), None);
        // Present → recorded verbatim.
        headers.insert("x-acting-operator", "alice@example.com".parse().unwrap());
        assert_eq!(asserted_operator(&headers).unwrap().as_deref(), Some("alice@example.com"));
        // Over the cap → rejected (400), never truncated (verbatim or nothing).
        let long = "x".repeat(ASSERTED_OPERATOR_MAX_BYTES.saturating_add(1));
        headers.insert("x-acting-operator", long.parse().unwrap());
        assert!(asserted_operator(&headers).is_err(), "over-long assertion is a 400");
        // Empty → treated as absent, not an error.
        headers.insert("x-acting-operator", "".parse().unwrap());
        assert_eq!(asserted_operator(&headers).unwrap(), None);
    }

    #[test]
    fn correlation_headers_are_capped_best_effort() {
        let mut headers = HeaderMap::new();
        assert_eq!(header_capped(&headers, "traceparent", 16), None);
        headers.insert("traceparent", "00-abc-def-01".parse().unwrap());
        assert_eq!(header_capped(&headers, "traceparent", 16).as_deref(), Some("00-abc-def-01"));
        // Over-long correlation is dropped (best-effort), never an error.
        assert_eq!(header_capped(&headers, "traceparent", 4), None);
    }

    #[test]
    fn denial_limiter_bounds_per_source_writes() {
        let limiter = DenialLimiter::new(Duration::from_mins(1), 3);
        for _ in 0..3 {
            assert!(limiter.allow("10.0.0.1"), "under the cap, denials are recorded");
        }
        assert!(!limiter.allow("10.0.0.1"), "the cap stops ledger flooding");
        // Another source has its own window — one scanner can't starve others.
        assert!(limiter.allow("10.0.0.2"), "sources are limited independently");
    }
}

// --------------------------------------------------------------------------- //
// admin-action-audit 5.2: a FAILED denial ledger write must stay a denial —
// never convert into an acceptance, never escalate to a 500.
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod denial_write_failure_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use async_trait::async_trait;

    use router_core::domain::PoolSet;
    use router_core::plan::PlanLimits;
    use router_core::store::{BoxError, InvalidationPublisher};
    use router_core::verify::OwnershipProof;
    use store_postgres::PgRoutingStore;

    use super::{deny, AdminAuth, App, DenialLimiter, Duration, StatusCode};

    struct NoopPublisher;
    #[async_trait]
    impl InvalidationPublisher for NoopPublisher {
        async fn publish(&self, _domain: &str) -> Result<(), BoxError> {
            Ok(())
        }
    }

    struct NoProof;
    #[async_trait]
    impl OwnershipProof for NoProof {
        async fn txt_records(&self, _name: &str) -> Result<Vec<String>, BoxError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn a_failed_denial_write_still_returns_401() {
        // The ledger is unreachable (lazy pool at a closed port), so the denial
        // insert fails — the response must still be the 401 the caller earned.
        let store = Arc::new(
            PgRoutingStore::connect_lazy("postgres://nobody:nothing@127.0.0.1:1/unreachable")
                .expect("lazy handle needs no live database"),
        );
        let app = App {
            store,
            publisher: Arc::new(NoopPublisher),
            limits: Arc::new(PlanLimits::new(BTreeMap::new())),
            pools: Arc::new(PoolSet::new(BTreeSet::new())),
            verifier: Arc::new(NoProof),
            challenge_ttl: 60,
            pending_ttl: 0,
            auth: AdminAuth { disabled: false, tokens: None, legacy: None, legacy_ok: false },
            denials: Arc::new(DenialLimiter::new(Duration::from_mins(1), 30)),
        };
        let response = deny(&app, true, (Some("10.0.0.9".to_owned()), None)).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a failed denial write logs and stays a 401 — never accept, never 500"
        );
    }
}

// --------------------------------------------------------------------------- //
// http-request-resilience tests: exercise the REAL resilience layering both
// servers (:9400 admin, :9401 ops) are built from.
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod resilience_tests {
    use super::{request_timeout, resilient, var, Duration, Router, StatusCode};
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use axum::routing::get;
    use tokio::time::sleep;
    use tower::util::ServiceExt;

    /// A handler that outlives the timeout must be terminated with 408 rather
    /// than pinning the task.
    #[tokio::test]
    async fn slow_request_is_terminated_with_408() {
        let app = resilient(
            Router::new().route(
                "/slow",
                get(|| async {
                    sleep(Duration::from_secs(30)).await;
                    "too late"
                }),
            ),
            Duration::from_millis(100),
        );
        let resp = app
            .oneshot(HttpRequest::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT, "slow handler must yield 408");
    }

    /// A request completing within the timeout is unaffected by the layer.
    #[tokio::test]
    async fn fast_request_is_unaffected_by_the_timeout() {
        let app = resilient(
            Router::new().route("/fast", get(|| async { "ok" })),
            Duration::from_millis(100),
        );
        let resp = app
            .oneshot(HttpRequest::builder().uri("/fast").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "fast handler must pass through");
    }

    /// Unconfigured, the timeout applies a finite safe default — never unbounded.
    /// (Relies on HTTP_REQUEST_TIMEOUT_SECS being unset in the test environment.)
    #[test]
    fn request_timeout_defaults_to_a_finite_30s() {
        if var("HTTP_REQUEST_TIMEOUT_SECS").is_ok() {
            return; // SKIP: the environment overrides the default under test
        }
        assert_eq!(
            request_timeout(),
            Duration::from_secs(30),
            "default request timeout must be the documented finite 30s",
        );
    }
}
