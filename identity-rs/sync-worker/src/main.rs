//! Sync Worker (Rust) — the real-time half of the sync pipeline (RFC C7, §3.4).
//!
//! On startup it self-registers an Actions v2 webhook target + an all-events
//! execution against the `IdP` (owning its own signing key), then for every
//! delivery it: verifies the HMAC signature, maps the event to a Profile via
//! `identity_core::sync` (the SHARED guard — same logic as the reconciler), and
//! applies an idempotent, version-guarded upsert/delete into the KV bucket.
//!
//! No webhook retry exists at the `IdP`, so a dropped delivery leaves KV stale;
//! the Reconciler closes that gap. This worker is the real-time path only.

use std::env::var;
use std::error::Error;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[cfg(not(unix))]
use std::future::pending;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use hmac::{Hmac, Mac};
use metrics::{counter, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use reqwest::header::HOST;
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::sleep;
use tracing::{error, info, warn};

use identity_core::store::ProfileStore;
use identity_core::sync::{apply, classify, Apply, Classify};
use store_postgres::PgProfileStore;

type HmacSha256 = Hmac<Sha256>;
const SIG_HEADER: &str = "zitadel-signature";
/// Replay window for webhook signatures: a signature whose authenticated
/// timestamp is more than this far from now (either direction, for clock skew) is
/// rejected. 5 minutes matches common webhook providers and bounds replay reuse.
const MAX_SIG_AGE_SECS: f64 = 300.0;

#[derive(Clone)]
struct App {
    store: Arc<dyn ProfileStore>,
    signing_key: Arc<String>,
    metrics: PrometheusHandle,
}

fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

// --------------------------------------------------------------------------- //
// Signature verification: header `ZITADEL-Signature: t=<unix>,v1=<hex>`; signed
// bytes are `"<t>." + raw_body`, HMAC-SHA256, keyed by the target's signingKey.
// --------------------------------------------------------------------------- //
fn verify_signature(headers: &HeaderMap, body: &[u8], signing_key: &str) -> bool {
    let Some(sig) = headers.get(SIG_HEADER).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let (mut t, mut v1) = (None, None);
    for part in sig.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            match k.trim() {
                // First occurrence wins: a duplicate key can't override the value
                // that is folded into the signed bytes below.
                "t" if t.is_none() => t = Some(v.trim().to_owned()),
                "v1" if v1.is_none() => v1 = Some(v.trim().to_owned()),
                _ => {}
            }
        }
    }
    let (Some(t), Some(v1)) = (t, v1) else { return false };
    let Ok(expected) = hex::decode(v1) else { return false };
    let Ok(mut mac) = HmacSha256::new_from_slice(signing_key.as_bytes()) else {
        return false;
    };
    mac.update(format!("{t}.").as_bytes());
    mac.update(body);
    if mac.verify_slice(&expected).is_err() {
        return false;
    }
    // Replay guard: the timestamp is authenticated (folded into the HMAC above), so
    // it can't be forged — but a *captured* valid webhook could be replayed forever
    // without a freshness window. Reject signatures whose timestamp is outside
    // ±MAX_SIG_AGE_SECS of now (covers both stale replays and far-future clock skew).
    let Ok(ts) = t.parse::<f64>() else { return false };
    (now_secs() - ts).abs() <= MAX_SIG_AGE_SECS
}

// --------------------------------------------------------------------------- //
async fn webhook(State(s): State<App>, headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    if !verify_signature(&headers, &body, &s.signing_key) {
        counter!("sync_signature_failures_total").increment(1);
        return (StatusCode::UNAUTHORIZED, "invalid signature").into_response();
    }
    let event: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad json").into_response(),
    };

    let (status, result) = match classify(&event) {
        Classify::Ignore => (StatusCode::OK, "ignore-non-user"),
        Classify::NoSubject => (StatusCode::OK, "no-user-id"),
        Classify::Event(ev) => match s.store.get(&ev.sub).await {
            // A read ERROR is NOT "absent": collapsing it to None would skip the
            // stale-write guard and let an older event clobber a newer stored
            // profile. Fail the delivery (503) so the write is not applied blind.
            Err(e) => {
                warn!(error = %e, sub = %ev.sub, "store get failed");
                (StatusCode::SERVICE_UNAVAILABLE, "error-read")
            }
            Ok(existing) => match apply(existing, &ev) {
                Apply::SkipStale => (StatusCode::OK, "skip-stale"),
                // Store write failures return 503 (the IdP does not retry, but a
                // 5xx is honest and the reconciler heals the gap).
                Apply::Delete => match s.store.delete(&ev.sub).await {
                    Ok(()) => (StatusCode::OK, "delete"),
                    Err(e) => {
                        warn!(error = %e, sub = %ev.sub, "store delete failed");
                        (StatusCode::SERVICE_UNAVAILABLE, "error-delete")
                    }
                },
                Apply::Upsert(profile) => match s.store.put(&profile).await {
                    Ok(()) => (StatusCode::OK, "upsert"),
                    Err(e) => {
                        warn!(error = %e, sub = %ev.sub, "store put failed");
                        (StatusCode::SERVICE_UNAVAILABLE, "error-upsert")
                    }
                },
            },
        },
    };

    counter!("sync_events_total", "result" => result).increment(1);
    gauge!("sync_last_event_timestamp_seconds").set(now_secs());
    info!(event_type = %event.get("event_type").and_then(|v| v.as_str()).unwrap_or(""), result, "handled");
    (status, axum::Json(json!({ "result": result }))).into_response()
}

async fn metrics_handler(State(s): State<App>) -> impl IntoResponse {
    s.metrics.render()
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

// --------------------------------------------------------------------------- //
// Register the webhook target + all-events execution; returns the signing key.
// --------------------------------------------------------------------------- //
async fn register_webhook(
    internal_url: &str,
    host: &str,
    pat: &str,
    self_url: &str,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
    let name = format!("sync-worker-{}", SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    let target: Value = client
        .post(format!("{internal_url}/v2/actions/targets"))
        .bearer_auth(pat)
        .header(HOST, host)
        .json(&json!({
            "name": name, "endpoint": self_url, "timeout": "10s",
            "restWebhook": {"interruptOnError": false}
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let target_id = target["id"].as_str().ok_or("no target id")?.to_owned();
    let signing_key = target["signingKey"].as_str().ok_or("no signing key")?.to_owned();
    client
        .put(format!("{internal_url}/v2/actions/executions"))
        .bearer_auth(pat)
        .header(HOST, host)
        .json(&json!({ "condition": {"event": {"all": true}}, "targets": [target_id] }))
        .send()
        .await?
        .error_for_status()?;
    Ok(signing_key)
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

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let level = env("LOG_LEVEL", "info");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    if env("LOG_FORMAT", "") == "json" {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    init_tracing();
    let handle = PrometheusBuilder::new().install_recorder()?;

    let pg_url = env("PROFILE_PG_URL", "postgres://postgres:postgres@postgres:5432/zitadel");
    let internal_url = env("ZITADEL_INTERNAL_URL", "http://zitadel:8080");
    let host = env("ZITADEL_HOST", "localhost:8088");
    let self_url = env("WEBHOOK_SELF_URL", "http://sync-worker:8080/webhook");
    let pat_file = env("PAT_FILE", "/secrets/zitadel-admin-sa.pat");

    let pat = fs::read_to_string(&pat_file)?.trim().to_owned();

    // Wait for Postgres, then for the IdP Actions API (mirrors the prior retry).
    // As an authoritative writer, the sync-worker owns idempotent schema setup.
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
    let store: Arc<dyn ProfileStore> = store;
    let signing_key = loop {
        match register_webhook(&internal_url, &host, &pat, &self_url).await {
            Ok(k) => break k,
            Err(e) => {
                warn!(error = %e, "waiting for IdP Actions API");
                sleep(Duration::from_secs(2)).await;
            }
        }
    };
    info!("webhook registered; signing key acquired; store ready");

    let app = App { store, signing_key: Arc::new(signing_key), metrics: handle };
    let router = Router::new()
        .route("/webhook", post(webhook))
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz))
        .with_state(app);

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    info!("listening on :8080 (/webhook, /metrics, /healthz)");
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
    use axum::http::HeaderValue;
    use hmac::Mac;

    /// Build headers carrying a VALID HMAC signature for `(t, body)` under `key`.
    fn signed(t: &str, body: &[u8], key: &str) -> HeaderMap {
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(format!("{t}.").as_bytes());
        mac.update(body);
        let v1 = hex::encode(mac.finalize().into_bytes());
        let mut h = HeaderMap::new();
        h.insert(SIG_HEADER, HeaderValue::from_str(&format!("t={t},v1={v1}")).unwrap());
        h
    }

    fn ts(offset: i64) -> String {
        (now_secs() as i64 + offset).to_string()
    }

    #[test]
    fn fresh_valid_signature_accepted() {
        let body = b"{}";
        assert!(verify_signature(&signed(&ts(0), body, "k"), body, "k"));
    }

    #[test]
    fn stale_signature_rejected_even_though_hmac_is_valid() {
        // The HMAC is correct, but the timestamp is an hour old -> replay window
        // rejects it. This is the whole point of the freshness guard.
        let body = b"{}";
        assert!(!verify_signature(&signed(&ts(-3600), body, "k"), body, "k"));
    }

    #[test]
    fn far_future_signature_rejected() {
        let body = b"{}";
        assert!(!verify_signature(&signed(&ts(3600), body, "k"), body, "k"));
    }

    #[test]
    fn wrong_key_rejected() {
        let body = b"{}";
        assert!(!verify_signature(&signed(&ts(0), body, "k"), body, "wrong-key"));
    }

    #[test]
    fn tampered_body_rejected() {
        let h = signed(&ts(0), b"{}", "k");
        assert!(!verify_signature(&h, b"{\"x\":1}", "k"));
    }

    #[test]
    fn non_numeric_timestamp_rejected() {
        // A signature whose `t` is not parseable can't be freshness-checked.
        let mut mac = HmacSha256::new_from_slice(b"k").unwrap();
        mac.update(b"notanumber.");
        mac.update(b"{}");
        let v1 = hex::encode(mac.finalize().into_bytes());
        let mut h = HeaderMap::new();
        h.insert(SIG_HEADER, HeaderValue::from_str(&format!("t=notanumber,v1={v1}")).unwrap());
        assert!(!verify_signature(&h, b"{}", "k"));
    }

    #[test]
    fn missing_or_malformed_header_rejected() {
        assert!(!verify_signature(&HeaderMap::new(), b"{}", "k"));
        let mut h = HeaderMap::new();
        h.insert(SIG_HEADER, HeaderValue::from_static("garbage"));
        assert!(!verify_signature(&h, b"{}", "k"));
    }
}
