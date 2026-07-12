//! Shared application core: the `App` state, its metrics, config loaders, the
//! admin-token gate, and the HTTP resilience layering every handler module
//! builds on.

use std::collections::{BTreeMap, BTreeSet};
use std::env::var;
use std::fmt;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
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

use router_core::domain::PoolSet;
use router_core::plan::{DomainLimit, PlanLimits};
use router_core::store::InvalidationPublisher;
use router_core::verify::{ct_eq, OwnershipProof};
use store_postgres::PgRoutingStore;

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
    /// Shared admin bearer token required on every data endpoint. `None` ONLY
    /// when auth is explicitly disabled at startup (`CONTROL_AUTH_DISABLED=true`);
    /// the server otherwise refuses to start without a token, so it is never
    /// silently open. The control plane is a trusted-broker admin surface, so a
    /// single shared secret authenticates the caller; `tenant_id` is then trusted.
    pub(crate) auth_token: Option<Arc<str>>,
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

/// Admin-token gate (RFC C16 admin boundary): every DATA endpoint requires
/// `Authorization: Bearer <CONTROL_AUTH_TOKEN>`. The token is compared in
/// constant time. `/healthz` is intentionally NOT behind this (liveness). When
/// `auth_token` is `None` the operator explicitly
/// disabled auth at startup, so requests pass through.
pub(crate) async fn require_auth(State(s): State<App>, req: Request, next: Next) -> Response {
    let Some(expected) = s.auth_token.as_deref() else {
        return next.run(req).await;
    };
    // Parse `Authorization: Bearer <token>` with the vetted `headers` typed-header
    // parser (RFC 7235: case-insensitive scheme, correct whitespace handling)
    // rather than a hand-rolled split. The token itself is then compared in
    // constant time; a present-but-wrong or missing/malformed header both 401.
    let bearer = req.headers().typed_get::<Authorization<Bearer>>();
    match &bearer {
        Some(auth) if ct_eq(auth.token(), expected) => next.run(req).await,
        _ => {
            METRICS.mutations.add(1, &[KeyValue::new("op", "unauthorized")]);
            // Emit an audit line (not only a metric) so a rejected admin attempt is
            // visible in the log trail. Method + path only — never the presented
            // credential. `bearer.is_some()` distinguishes a bad token from a
            // missing/malformed Authorization header.
            warn!(
                method = %req.method(),
                path = %req.uri().path(),
                had_bearer = bearer.is_some(),
                "unauthorized control-plane request"
            );
            (StatusCode::UNAUTHORIZED, Json(json!({ "error": "unauthorized" }))).into_response()
        }
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
