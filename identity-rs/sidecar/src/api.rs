//! localhost API: profile (C9), health, metrics (C12).

use std::env::var;
use std::sync::atomic::Ordering;
use std::time::Duration;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use tower_http::timeout::TimeoutLayer;

use crate::state::{AppState, Resolved};

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
/// request-body cap plus a total per-request timeout answering 408, so a
/// slow or stalled client cannot pin a task. The ext_proc gRPC server
/// deliberately does NOT pass through here — a per-request deadline would
/// sever its healthy long-lived streams (the spec's streaming exemption).
pub(crate) fn resilient<S>(router: Router<S>, timeout: Duration) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, timeout))
}

pub(crate) fn router(state: AppState) -> Router {
    // Metrics are served by the exporter's own listener (:9202) so the
    // protobuf/native-histogram content negotiation works; this axum server
    // only carries the profile + health surfaces.
    resilient(
        Router::new()
            .route("/healthz", get(healthz))
            .route("/profile/{sub}", get(profile)),
        request_timeout(),
    )
    .with_state(state)
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
        Json(serde_json::json!({ "ready": ready, "cached": s.cache.entry_count() })),
    )
}

async fn profile(State(s): State<AppState>, Path(sub): Path<String>) -> impl IntoResponse {
    match s.resolve(&sub).await {
        Resolved::Found(p) => (StatusCode::OK, Json(serde_json::to_value(&*p).unwrap())),
        Resolved::Absent => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found", "sub": sub })),
        ),
        Resolved::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "store unavailable", "sub": sub })),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get as axum_get;
    use axum::Router as AxumRouter;
    use tower::util::ServiceExt;

    /// The REAL layering the API server uses, exercised with a handler that
    /// outlives the timeout: the request must be terminated with 408 rather
    /// than pinning the task.
    #[tokio::test]
    async fn slow_request_is_terminated_with_408() {
        let app = resilient(
            AxumRouter::new().route(
                "/slow",
                axum_get(|| async {
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
            AxumRouter::new().route("/fast", axum_get(|| async { "ok" })),
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
