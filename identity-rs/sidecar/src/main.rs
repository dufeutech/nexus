//! Identity sidecar (Rust) — the identity-plane resolver.
//! Stack: tonic + envoy-types + store-postgres (`PostgreSQL`) + moka + axum.
//!
//! Dual surface over one push-updated Profile cache:
//!   - `ext_proc` gRPC (hot path): read the verified `sub` from `jwt_authn` metadata
//!     Envoy forwards, resolve the Profile, inject trusted x-user-* (C2).
//!   - localhost HTTP profile API: GET /profile/{sub} (C9) + /healthz + /metrics.
//! Cache: the store's resumable change feed pushes updates (C4 — a `seq`-cursor
//! over Postgres LISTEN/NOTIFY); moka TTL is the safety net and `try_get_with`
//! gives a coalesced miss-load (C5); `ext_proc` fails CLOSED with a 503 until the
//! store is reachable + the feed is open (lazy warm, C6 — NOT a full population
//! replay). The token is never parsed here.
//!
//! Hardening: structured logging (tracing), Prometheus metrics (C12), and
//! graceful shutdown on SIGTERM/SIGINT for both servers.

use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(not(unix))]
use std::future::pending;

use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, NativeHistogramConfig, PrometheusBuilder};
use moka::future::Cache;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status, Streaming};
use tracing::{debug, error, info, warn};

use envoy_types::pb::envoy::config::core::v3::{
    header_value_option::HeaderAppendAction, HeaderValue, HeaderValueOption,
};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response, CommonResponse, HeaderMutation, HeadersResponse,
    ImmediateResponse, ProcessingRequest, ProcessingResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;

// The Profile shape lives in the shared core crate; the store is reached through
// the core `ProfileStore` port, implemented by the Postgres adapter.
use identity_core::store::{BoxError, Change, ProfileStore, WatchToken};
use identity_core::Profile;
use store_postgres::PgProfileStore;

const JWT_NS: &str = "envoy.filters.http.jwt_authn";
const PAYLOAD_KEY: &str = "verified";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
struct AppState {
    cache: Cache<String, Arc<Profile>>,
    store: Arc<dyn ProfileStore>,
    ready: Arc<AtomicBool>,
    last_apply_ms: Arc<AtomicU64>, // epoch millis of the last applied change
    warm_ms: Arc<AtomicU64>,       // time-to-warm in ms (0 until ready)
    start: Instant,
}

impl AppState {
    /// Cache-first resolve; on miss/expiry, a single coalesced store read (C5).
    /// At 1B scale this miss-load is a normal steady-state path, not a rare
    /// fallback — the cache holds only the hot working set.
    async fn resolve(&self, sub: &str) -> Option<Arc<Profile>> {
        if let Some(p) = self.cache.get(sub).await {
            counter!("sidecar_cache_hits_total").increment(1);
            return Some(p);
        }
        counter!("sidecar_cache_misses_total").increment(1);
        let store = self.store.clone();
        let key = sub.to_owned();
        self.cache
            .try_get_with(key.clone(), async move {
                match store.get(&key).await {
                    Ok(Some(p)) => Ok(Arc::new(p)),
                    Ok(None) => Err("not_found".to_owned()),
                    Err(e) => Err(e.to_string()),
                }
            })
            .await
            .ok()
    }
}

// --------------------------------------------------------------------------- //
// Metadata extraction (C11): the verified `sub` plus any COARSE roles carried in
// the token. Coarse roles ride in the JWT (zero-latency, portable); revocation-
// sensitive state (suspended/entitlements) is sourced from the live Profile
// instead, so it can change within seconds without a token refresh.
// --------------------------------------------------------------------------- //
fn extract_identity(req: &ProcessingRequest) -> (String, Vec<String>, bool) {
    use envoy_types::pb::google::protobuf::value::Kind;
    let fields = match req
        .metadata_context
        .as_ref()
        .and_then(|md| md.filter_metadata.get(JWT_NS))
    {
        // No verified-credential metadata at all → anonymous.
        Some(ns) => match ns.fields.get(PAYLOAD_KEY).and_then(|v| v.kind.as_ref()) {
            Some(Kind::StructValue(s)) => &s.fields,
            _ => &ns.fields,
        },
        None => return ("anonymous".to_owned(), Vec::new(), true),
    };
    // A verified `sub` is the authority for "authenticated": its presence flips
    // is-anonymous to false. Absence (no sub claim) stays anonymous.
    let (sub, authenticated) = match fields.get("sub").and_then(|v| v.kind.as_ref()) {
        Some(Kind::StringValue(s)) if !s.is_empty() => (s.clone(), true),
        _ => ("anonymous".to_owned(), false),
    };
    let mut roles = Vec::new();
    // A plain `roles` array claim, if present...
    if let Some(Kind::ListValue(l)) = fields.get("roles").and_then(|v| v.kind.as_ref()) {
        for it in &l.values {
            if let Some(Kind::StringValue(s)) = it.kind.as_ref() {
                roles.push(s.clone());
            }
        }
    }
    // ...or the provider's nested project-roles claim (key ends ":roles", a
    // struct whose field names are the role keys).
    if roles.is_empty() {
        for (k, v) in fields {
            if k.ends_with(":roles") {
                if let Some(Kind::StructValue(s)) = v.kind.as_ref() {
                    roles.extend(s.fields.keys().cloned());
                }
            }
        }
    }
    (sub, roles, authenticated)
}

// --------------------------------------------------------------------------- //
// ext_proc response builders.
// --------------------------------------------------------------------------- //
fn header(key: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_owned(),
            raw_value: value.as_bytes().to_vec(),
            ..Default::default()
        }),
        append_action: HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        ..Default::default()
    }
}

fn enrich_response(
    sub: &str,
    token_roles: &[String],
    profile: Option<Arc<Profile>>,
    authenticated: bool,
) -> ProcessingResponse {
    // Trusted auth-state, emitted on EVERY request (incl. the no-credential path)
    // so a backend never has to infer it from the absence of a header. Standards:
    // RFC 6750 bearer presence drives is-anonymous; richer assurance (NIST
    // SP 800-63B AAL, mTLS) can extend `x-auth-method` later. These are stripped
    // from client input (C3) so a client cannot self-assert as authenticated.
    let mut set = vec![
        header("x-auth-anonymous", if authenticated { "false" } else { "true" }),
        header("x-auth-method", if authenticated { "bearer" } else { "none" }),
        header("x-user-id", sub),
    ];
    // Roles are coarse → prefer the token (zero-latency), fall back to the Profile.
    let (roles, roles_source) = if !token_roles.is_empty() {
        (token_roles.join(","), "token")
    } else if let Some(p) = &profile {
        (p.roles.join(","), "profile")
    } else {
        (String::new(), "none")
    };
    set.push(header("x-user-roles", &roles));
    set.push(header("x-user-roles-source", roles_source));
    match &profile {
        Some(p) => {
            set.push(header("x-user-org", p.org_id.as_deref().unwrap_or("")));
            set.push(header("x-user-entitlements", &p.entitlements.join(",")));
            // Revocation-sensitive: ALWAYS from the live Profile, never the token,
            // so a suspension takes effect within seconds without a token refresh.
            set.push(header(
                "x-user-suspended",
                if p.is_suspended { "true" } else { "false" },
            ));
            set.push(header("x-user-enriched-by", "identity-sidecar-rs"));
        }
        None => set.push(header("x-user-enriched-by", "identity-sidecar-rs:miss")),
    }
    let common = CommonResponse {
        header_mutation: Some(HeaderMutation {
            set_headers: set,
            ..Default::default()
        }),
        ..Default::default()
    };
    ProcessingResponse {
        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
            response: Some(common),
        })),
        ..Default::default()
    }
}

fn warming_503() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 503 }),
                body: b"identity plane warming up".to_vec(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

// --------------------------------------------------------------------------- //
// ext_proc service.
// --------------------------------------------------------------------------- //
#[derive(Clone)]
struct Sidecar {
    state: AppState,
}

impl Sidecar {
    async fn handle(&self, req: ProcessingRequest) -> Option<ProcessingResponse> {
        if !matches!(
            req.request,
            Some(processing_request::Request::RequestHeaders(_))
        ) {
            return None;
        }
        let started = Instant::now();
        let (resp, result) = if self.state.ready.load(Ordering::Relaxed) {
            let (sub, token_roles, authenticated) = extract_identity(&req);
            // Don't touch the store for unauthenticated requests: the subject is
            // "anonymous" (no credential), which is never a stored profile — so a
            // lookup is a guaranteed miss that needlessly loads the pool on
            // high-volume anonymous traffic (and is not negatively cached).
            let profile = if authenticated { self.state.resolve(&sub).await } else { None };
            let result = if profile.is_some() { "hit" } else { "miss" };
            // `sub` is a user identifier (PII): keep it out of per-request info
            // logs (enable debug for the subject when diagnosing a specific user).
            debug!(sub = %sub, "enrich subject");
            info!(anonymous = !authenticated, hit = profile.is_some(), token_roles = token_roles.len(), "enrich");
            (enrich_response(&sub, &token_roles, profile, authenticated), result)
        } else {
            warn!("not ready -> 503");
            (warming_503(), "not_ready")
        };
        histogram!("sidecar_ext_proc_duration_seconds")
            .record(started.elapsed().as_secs_f64());
        counter!("sidecar_ext_proc_requests_total", "result" => result).increment(1);
        Some(resp)
    }
}

type RespStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<ProcessingResponse, Status>> + Send>>;

#[tonic::async_trait]
impl ExternalProcessor for Sidecar {
    type ProcessStream = RespStream;

    async fn process(
        &self,
        request: Request<Streaming<ProcessingRequest>>,
    ) -> Result<Response<Self::ProcessStream>, Status> {
        let mut inbound = request.into_inner();
        let me = self.clone();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(msg) = inbound.next().await {
                match msg {
                    Ok(req) => {
                        if let Some(resp) = me.handle(req).await {
                            if tx.send(Ok(resp)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

// --------------------------------------------------------------------------- //
// Change-feed watcher (RFC C4): push live changes into the cache. Lazy warm —
// readiness means "store reachable + feed open" (RFC C6 revised), NOT that the
// whole population is resident; cold subjects load on demand via the miss-load.
// --------------------------------------------------------------------------- //
async fn watch_store(state: AppState) {
    // Resume cursor kept across reconnects so a feed blip replays the gap and
    // no change is missed (resumable feed, RFC C4). In-memory is sufficient: a
    // process restart starts with an empty cache, so there is nothing stale to
    // miss — only mid-process reconnects need to resume.
    let mut resume: Option<WatchToken> = None;
    loop {
        match run_watch(&state, &mut resume).await {
            Ok(()) => warn!("change feed ended; reconnecting"),
            Err(e) => warn!(error = %e, "watch error; retrying"),
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn run_watch(state: &AppState, resume: &mut Option<WatchToken>) -> Result<(), BoxError> {
    let mut stream = state.store.watch(resume.clone()).await?;
    info!(resuming = resume.is_some(), "watching change feed");
    // Store reachable + feed open => ready (lazy warm, no full replay).
    if !state.ready.swap(true, Ordering::Relaxed) {
        let ms = state.start.elapsed().as_millis() as u64;
        state.warm_ms.store(ms, Ordering::Relaxed);
        info!(time_to_warm_ms = ms, "READY");
    }
    while let Some(event) = stream.next().await {
        let event = event?;
        match event.change {
            Change::Upsert(p) => {
                // Bounded cache (RFC §6.3 revised): only refresh entries we are
                // actually serving; cold subjects load on demand. This keeps a
                // resident suspension/role change instant for active users (C11)
                // without pulling the whole population into memory.
                let key = p.sub.clone();
                if state.cache.contains_key(&key) {
                    state.cache.insert(key, Arc::new(*p)).await;
                }
                counter!("sidecar_kv_updates_total", "op" => "upsert").increment(1);
            }
            Change::Delete(sub) => {
                state.cache.invalidate(&sub).await;
                counter!("sidecar_kv_updates_total", "op" => "delete").increment(1);
            }
        }
        // Remember the resume position so a reconnect picks up right here.
        *resume = Some(event.token);
        state.last_apply_ms.store(now_ms(), Ordering::Relaxed);
    }
    Ok(())
}

// --------------------------------------------------------------------------- //
// localhost API: profile (C9), health, metrics (C12).
// --------------------------------------------------------------------------- //
mod api {
    use super::{AppState, Ordering};
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};

    pub(crate) fn router(state: AppState) -> Router {
        // Metrics are served by the exporter's own listener (:9202) so the
        // protobuf/native-histogram content negotiation works; this axum server
        // only carries the profile + health surfaces.
        Router::new()
            .route("/healthz", get(healthz))
            .route("/profile/{sub}", get(profile))
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
            Some(p) => (StatusCode::OK, Json(serde_json::to_value(&*p).unwrap())),
            None => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "not found", "sub": sub })),
            ),
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let json = env::var("LOG_FORMAT").map(|v| v == "json").unwrap_or(false);
    if json {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

/// Resolves when the process receives SIGINT or (on unix) SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_tracing();
    // Explicit-bucket histogram (not a summary) so latency is aggregatable across
    // instances: histogram_quantile(0.99, sum by (le)(rate(..._bucket[5m]))).
    // Buckets span the hot path (cache hit ~tens of µs) through miss-loads (~ms)
    // up to timeouts (~s). Native histograms are the longer-term upgrade once the
    // exporter supports them.
    const LATENCY_BUCKETS: &[f64] = &[
        0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
        0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
    ];
    // Native (exponential) histogram for latency — aggregatable across instances
    // with no bucket-boundary guessing (Prometheus 3.x stores it natively, served
    // over protobuf). set_buckets stays as the classic-text fallback if a scraper
    // doesn't negotiate protobuf. The exporter runs its own listener on :9202 so
    // protobuf content negotiation works; the axum API stays on :9200.
    let native = NativeHistogramConfig::new(1.1, 160, 0.000_001)
        .expect("native histogram config");
    PrometheusBuilder::new()
        .set_buckets(LATENCY_BUCKETS)
        .expect("set histogram buckets")
        .set_native_histogram_for_metric(
            Matcher::Full("sidecar_ext_proc_duration_seconds".to_owned()),
            native,
        )
        .with_http_listener("0.0.0.0:9202".parse::<SocketAddr>().unwrap())
        .install()
        .expect("install prometheus exporter");

    // The sidecar only reads + listens, so this URL needs SELECT + LISTEN, never
    // schema creation. It MUST reach the primary on a session connection — a
    // transaction-mode pooler silently swallows LISTEN (see deploy/README.md).
    let pg_url = env::var("PROFILE_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@postgres:5432/zitadel".into());
    let ttl: u64 = env::var("CACHE_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(43_200);
    let readiness_delay: u64 = env::var("READINESS_DELAY_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let store: Arc<dyn ProfileStore> = loop {
        match PgProfileStore::connect(&pg_url).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                warn!(error = %e, "waiting for Postgres");
                sleep(Duration::from_secs(2)).await;
            }
        }
    };

    let state = AppState {
        // max_capacity is the WORKING-SET bound (RFC §6.3 revised), not the
        // population; cold subjects load on demand and evict normally.
        cache: Cache::builder()
            .max_capacity(500_000)
            .time_to_live(Duration::from_secs(ttl))
            .build(),
        store,
        ready: Arc::new(AtomicBool::new(false)),
        last_apply_ms: Arc::new(AtomicU64::new(0)),
        warm_ms: Arc::new(AtomicU64::new(0)),
        start: Instant::now(),
    };

    // Periodically publish the gauge-style snapshots (the exporter's own listener
    // serves them; there is no per-scrape hook to set them on).
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                gauge!("sidecar_cache_entries").set(st.cache.entry_count() as f64);
                gauge!("sidecar_ready")
                    .set(if st.ready.load(Ordering::Relaxed) { 1.0 } else { 0.0 });
                gauge!("sidecar_kv_last_apply_timestamp_seconds")
                    .set(st.last_apply_ms.load(Ordering::Relaxed) as f64 / 1000.0);
                let wm = st.warm_ms.load(Ordering::Relaxed);
                if wm > 0 {
                    gauge!("sidecar_time_to_warm_seconds").set(wm as f64 / 1000.0);
                }
                sleep(Duration::from_secs(5)).await;
            }
        })
    };
    info!(ttl_s = ttl, readiness_delay_s = readiness_delay, "starting identity-sidecar-rs");

    // Readiness fallback so we can never hang fail-closed forever.
    {
        let st = state.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(readiness_delay + 15)).await;
            if !st.ready.swap(true, Ordering::Relaxed) {
                st.warm_ms
                    .store(st.start.elapsed().as_millis() as u64, Ordering::Relaxed);
                warn!("readiness fallback fired");
            }
        })
    };
    // KV watcher (optionally held to demo the C6 fail-closed window).
    {
        let st = state.clone();
        tokio::spawn(async move {
            if readiness_delay > 0 {
                sleep(Duration::from_secs(readiness_delay)).await;
            }
            watch_store(st).await;
        })
    };

    // Shared shutdown fan-out for both servers.
    let (tx, _r) = watch::channel(false);
    let mut r_http = tx.subscribe();
    let mut r_grpc = tx.subscribe();
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = tx.send(true);
    });

    // Profile/metrics API.
    let http = {
        let app = api::router(state.clone());
        tokio::spawn(async move {
            let listener = TcpListener::bind("0.0.0.0:9200").await.unwrap();
            info!("profile/metrics API on :9200");
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = r_http.changed().await;
                })
                .await;
        })
    };

    // ext_proc gRPC (foreground).
    let addr = "0.0.0.0:50051".parse()?;
    info!("ext_proc listening on :50051");
    if let Err(e) = Server::builder()
        .add_service(ExternalProcessorServer::new(Sidecar { state }))
        .serve_with_shutdown(addr, async move {
            let _ = r_grpc.changed().await;
        })
        .await
    {
        error!(error = %e, "grpc server error");
    }

    let _ = http.await;
    info!("stopped");
    Ok(())
}
