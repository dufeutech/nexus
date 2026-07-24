// --------------------------------------------------------------------------- //
// localhost API: resolve debug (admin), health, metrics.
// --------------------------------------------------------------------------- //
use std::env::var;
use std::time::Duration;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router as AxumRouter};
use tower_http::timeout::TimeoutLayer;

use router_core::normalize::normalize_host;
use opentelemetry::KeyValue;
use std::sync::atomic::Ordering;

use crate::state::{AppState, METRICS};

/// Total per-request timeout for the HTTP surfaces (http-request-resilience):
/// operator-tunable via `HTTP_REQUEST_TIMEOUT_SECS` with a finite 30s default —
/// never unbounded.
pub(crate) fn request_timeout() -> Duration {
    Duration::from_secs(
        var("HTTP_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
    )
}

/// Bound a router with the resilience layers (http-request-resilience): a
/// request-body cap plus a total per-request timeout answering 408 — the
/// externally-reachable /authorize (CA on-demand-TLS ask) must not let a
/// slow client pin a task. The ext_proc gRPC server deliberately does NOT
/// pass through here — a per-request deadline would sever its healthy
/// long-lived streams (the spec's streaming exemption).
pub(crate) fn resilient<S>(router: AxumRouter<S>, timeout: Duration) -> AxumRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        // GET-only API; cap any request body as defense-in-depth (this router
        // otherwise relies on axum's implicit 2 MB extractor limit).
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout))
}

pub(crate) fn router(state: AppState) -> AxumRouter {
    resilient(
        AxumRouter::new()
            .route("/healthz", get(healthz))
            .route("/resolve/{host}", get(resolve))
            .route("/authorize", get(authorize)),
        request_timeout(),
    )
    .with_state(state)
}

#[derive(serde::Deserialize)]
struct AuthorizeQuery {
    domain: Option<String>,
}

/// Per-host certificate-authorization gate (RFC C2 / N1): the on-demand-TLS
/// `ask`. Affirmative (`200`) iff the host is a known, verified, routable
/// domain — decided by the SAME predicate as routing (`resolve`), so a host
/// the gate authorizes is, by construction, one the router will route. Every
/// other case is `403` (fail-closed): not-yet-ready, missing/empty domain,
/// unknown/pending host, or a store error surfaced as an unresolved miss.
async fn authorize(State(s): State<AppState>, Query(q): Query<AuthorizeQuery>) -> impl IntoResponse {
    let domain = q.domain.unwrap_or_default();
    // Fail closed until the plane is ready: deny rather than authorize a cert
    // for a host we cannot yet evaluate. (A not-ready deny is global, not
    // host-specific, so it is NOT remembered in the negative cache.)
    if domain.is_empty() || !s.ready.load(Ordering::Relaxed) {
        METRICS.authorize.add(1, &[KeyValue::new("result", "deny")]);
        return StatusCode::FORBIDDEN;
    }
    // Key on the SAME canonical host the matcher uses, so the negative cache
    // dedupes SNI spellings exactly as routing does; a host normalize refuses
    // outright is denied without touching the cache.
    let key = normalize_host(&domain);
    if key.is_empty() {
        METRICS.authorize.add(1, &[KeyValue::new("result", "deny")]);
        return StatusCode::FORBIDDEN;
    }
    // Remembered refusal (certificate-issuance-authorization): a recently
    // refused host is denied without re-consulting the store or the CA, so
    // repeated connections for the same unknown SNI — and a flood of them —
    // cannot drive unbounded issuance work.
    if s.neg.get(&key).await.is_some() {
        METRICS.authorize.add(1, &[KeyValue::new("result", "deny")]);
        return StatusCode::FORBIDDEN;
    }
    if s.resolve(&domain).await.is_some() {
        METRICS.authorize.add(1, &[KeyValue::new("result", "allow")]);
        StatusCode::OK
    } else {
        // Refused: remember it for a bounded interval (TTL + capacity set at
        // construction) so the next connection for this host is served from
        // memory. A host that later becomes verified is re-evaluated once the
        // entry expires — the gate never caches a *positive*.
        s.neg.insert(key, ()).await;
        METRICS.authorize.add(1, &[KeyValue::new("result", "deny")]);
        StatusCode::FORBIDDEN
    }
}

async fn healthz(State(s): State<AppState>) -> impl IntoResponse {
    let ready = s.ready.load(Ordering::Relaxed);
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(serde_json::json!({ "ready": ready, "cached": s.l1.entry_count() })),
    )
}

async fn resolve(State(s): State<AppState>, Path(host): Path<String>) -> impl IntoResponse {
    match s.resolve(&host).await {
        Some(d) => (StatusCode::OK, Json(serde_json::to_value(&*d).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "no tenant", "host": host })),
        ),
    }
}

// --------------------------------------------------------------------------- //
// http-request-resilience tests: exercise the REAL resilience layering the API
// server uses. The ext_proc gRPC server is exempt BY CONSTRUCTION (no timeout
// layer is ever attached to the tonic server above); the streaming-exemption
// scenario is exercised end-to-end in identity-rs/sidecar.
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod tests {
    use crate::api;
    use crate::state::AppState;
    use crate::test_support::{build_state, FakeStore};
    use std::env::var;
    use std::sync::Arc;
    use std::time::Duration;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::Router as AxumRouter;
    use tokio::time::sleep;
    use tower::util::ServiceExt;

    /// A generous L1 lifetime for the `/authorize`-vs-router tests, which exercise
    /// resolution/negative-caching within one request burst and never test expiry.
    const TEST_TTL: Duration = Duration::from_secs(30);

    /// A handler that outlives the timeout must be terminated with 408 rather
    /// than pinning the task.
    #[tokio::test]
    async fn slow_request_is_terminated_with_408() {
        let app = api::resilient(
            AxumRouter::new().route(
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
        let app = api::resilient(
            AxumRouter::new().route("/fast", get(|| async { "ok" })),
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
            api::request_timeout(),
            Duration::from_secs(30),
            "default request timeout must be the documented finite 30s",
        );
    }

    // ----------------------------------------------------------------------- //
    // domain-host-resolution: /authorize == router host-set parity.
    //
    // The cert gate (`authorize`) and the router (`resolve`) MUST authorize/route
    // the identical host set because they share ONE predicate — `AppState::resolve`.
    // This drives both real HTTP handlers over one state and asserts they agree
    // allow-for-allow / deny-for-deny across an exact hit, a wildcard-covered
    // subdomain, a nested miss, an apex-with-only-a-wildcard, and an unknown host.
    // ----------------------------------------------------------------------- //

    // The in-memory `FakeStore` and the `AppState` builder live in
    // `crate::test_support` (single source of truth), shared with the resolve
    // keep-warm tests.

    /// Fire one GET at a fresh router over `state` and return its status.
    async fn get_status(state: &AppState, uri: &str) -> StatusCode {
        api::router(state.clone())
            .oneshot(HttpRequest::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn authorize_and_router_resolve_the_identical_host_set() {
        // Seed: an exact `shop.example.com` row and a wildcard `example.com` row.
        let store = Arc::new(FakeStore::new([
            (("shop.example.com".to_owned(), false), "ws_exact".to_owned()),
            (("example.com".to_owned(), true), "ws_wild".to_owned()),
        ]));
        let state = build_state(store, TEST_TTL);

        // (host, should_resolve): the router routes exactly these, so the cert gate
        // must authorize exactly these.
        let cases = [
            ("shop.example.com", true),  // exact hit
            ("app.example.com", true),   // wildcard-covered subdomain
            ("a.b.example.com", false),  // nested: two labels below the wildcard → miss
            ("example.com", false),      // apex has only a wildcard row → not covered
            ("nope.other.com", false),   // wholly unknown → fail closed
        ];

        for (host, should_resolve) in cases {
            let routed = get_status(&state, &format!("/resolve/{host}")).await;
            let authorized = get_status(&state, &format!("/authorize?domain={host}")).await;

            // The router routes iff we expect resolution; the gate authorizes iff so.
            let expected_route = if should_resolve { StatusCode::OK } else { StatusCode::NOT_FOUND };
            let expected_auth = if should_resolve { StatusCode::OK } else { StatusCode::FORBIDDEN };
            assert_eq!(routed, expected_route, "router verdict for {host}");
            assert_eq!(authorized, expected_auth, "cert-gate verdict for {host}");

            // Parity, stated directly: the gate authorizes exactly when the router routes.
            assert_eq!(
                authorized == StatusCode::OK,
                routed == StatusCode::OK,
                "/authorize and the router must agree on {host}",
            );
        }
    }

    // ----------------------------------------------------------------------- //
    // certificate-issuance-authorization: refusals are remembered to bound
    // issuance work under load. A flood of connections for the same unknown SNI
    // must collapse to ONE store evaluation — the rest are served the cached
    // refusal — and must never authorize (no CA order is ever placed for it).
    // ----------------------------------------------------------------------- //
    #[tokio::test]
    async fn ask_negative_cache_collapses_repeat_unknown_host_flood() {
        // Empty store → every host is unknown and fails closed.
        let store = Arc::new(FakeStore::empty());
        let state = build_state(store.clone(), TEST_TTL);

        // Hammer the gate with the SAME unknown host many times.
        for _ in 0..50 {
            let status = get_status(&state, "/authorize?domain=attacker.example.com").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "unknown host must fail closed every time");
        }

        // Only the FIRST connection reached the store; every later one was served
        // the remembered refusal. `resolve` makes at most two lookups per
        // evaluation (exact, then wildcard-parent), so a single evaluation is
        // ≤ 2 store lookups — proving the flood did not re-evaluate per connection.
        let n = store.lookups();
        assert!(
            n <= 2,
            "negative cache must collapse a repeat flood to one evaluation; saw {n} store lookups",
        );
    }

    /// A flood across MANY distinct unknown hosts still authorizes none of them —
    /// the gate places zero CA orders for unapproved hostnames, so it cannot
    /// consume the issuance budget reserved for approved ones.
    #[tokio::test]
    async fn ask_distinct_unknown_host_flood_authorizes_nothing() {
        let state = build_state(Arc::new(FakeStore::empty()), TEST_TTL);
        for i in 0..200 {
            let host = format!("junk-{i}.example.com");
            let status = get_status(&state, &format!("/authorize?domain={host}")).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "distinct unknown host {host} must be refused");
        }
    }
}
