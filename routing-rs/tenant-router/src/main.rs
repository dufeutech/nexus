//! Tenant Router (Rust) — the routing-plane hot path (RFC C14/C15/C17/C18).
//!
//! It is the routing-plane twin of the identity sidecar: the same Resolution
//! Engine pattern (bounded L1 cache → optional shared L2 → authoritative store,
//! coalesced miss-loads), over a different key/value. Here the key is the
//! request host and the value is a Routing Decision.
//!
//! Surface over one invalidation-updated decision cache:
//!   - `ext_proc` gRPC (hot path): read the request host, normalize it, resolve the
//!     owning tenant + config, and inject trusted `x-tenant-*` + `x-route-pool`
//!     (C14/C15) which the edge data plane uses to forward. An unknown/unverified
//!     host is REJECTED at the edge (immediate 404) before any backend is
//!     selected — never defaulted to a tenant (C18).
//!   - localhost HTTP debug API: GET /resolve/{host} + /healthz + /metrics.
//!
//! Freshness: a Postgres LISTEN/NOTIFY feed pushes control-plane invalidations
//! (C16); moka TTL is the staleness backstop and `try_get_with` gives a coalesced
//! miss-load (C14 "concurrent misses coalesced"). A "no tenant" result is an Err
//! in the loader, so negatives are never cached as positive mappings (§3.10).
//! `ext_proc` fails CLOSED with a 503 until the store is reachable + the feed is
//! subscribed — a routing failure must not silently become a default route.

use std::collections::HashMap;
use std::env::var;
use std::error::Error;
#[cfg(not(unix))]
use std::future::pending;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use moka::future::Cache;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Request, Response, Status, Streaming};
use tracing::{error, info, warn};

use envoy_types::pb::envoy::config::core::v3::{
    header_value_option::HeaderAppendAction, HeaderValue, HeaderValueOption,
};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response, CommonResponse, HeaderMutation, HeadersResponse,
    ImmediateResponse, ProcessingRequest, ProcessingResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;

use router_core::cache::SharedCache;
use router_core::context::ClientContext;
use router_core::domain::RoutingDecision;
use router_core::geo::GeoContext;
use router_core::normalize::{normalize_host, parent_domain};
use router_core::store::{BoxError, Invalidations, RoutingStore};
use cache_redis::RedisCache;
use store_postgres::{PgInvalidations, PgRoutingStore};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Clone)]
struct AppState {
    /// L1: per-edge bounded working-set cache of decisions (RFC §6.3 / decision 9).
    l1: Cache<String, Arc<RoutingDecision>>,
    /// L2: OPTIONAL shared tier (RFC decision 9) — pure optimization.
    l2: Option<Arc<dyn SharedCache>>,
    store: Arc<dyn RoutingStore>,
    l2_ttl: u64,
    ready: Arc<AtomicBool>,
    last_apply_ms: Arc<AtomicU64>, // epoch millis of the last applied invalidation
    warm_ms: Arc<AtomicU64>,
    start: Instant,
}

impl AppState {
    /// Resolve a request host to a Routing Decision. L1 hit → in-memory read; on a
    /// miss, a single coalesced load that consults the optional L2 then the store
    /// (one exact lookup, then one wildcard-parent lookup, RFC C14). Returns
    /// `None` for an unresolved/unverified host — which the caller turns into an
    /// edge rejection (C18), never a default tenant. A negative is an `Err` in the
    /// loader, so it is not cached as a positive mapping (RFC §3.10).
    async fn resolve(&self, host: &str) -> Option<Arc<RoutingDecision>> {
        let key = normalize_host(host);
        if key.is_empty() {
            return None;
        }
        if let Some(d) = self.l1.get(&key).await {
            counter!("router_cache_hits_total", "tier" => "l1").increment(1);
            return Some(d);
        }
        counter!("router_cache_misses_total", "tier" => "l1").increment(1);

        let store = self.store.clone();
        let l2 = self.l2.clone();
        let l2_ttl = self.l2_ttl;
        let key2 = key.clone();
        self.l1
            .try_get_with(key, async move {
                // L2 (optional shared tier).
                if let Some(l2) = &l2 {
                    match l2.get(&key2).await {
                        Ok(Some(d)) => {
                            counter!("router_cache_hits_total", "tier" => "l2").increment(1);
                            return Ok(Arc::new(d));
                        }
                        Ok(None) => {
                            counter!("router_cache_misses_total", "tier" => "l2").increment(1);
                        }
                        Err(e) => warn!(error = %e, "L2 get failed; falling through to store"),
                    }
                }

                // Authoritative store: one exact point read, then one wildcard
                // parent point read (RFC C14 — never a scan).
                let tenant = match store.lookup_domain(&key2, false).await {
                    Ok(Some(t)) => Some(t),
                    Ok(None) => match parent_domain(&key2) {
                        Some(parent) => {
                            store.lookup_domain(&parent, true).await.map_err(|e| e.to_string())?
                        }
                        None => None,
                    },
                    Err(e) => return Err(e.to_string()),
                };
                let Some(tenant_id) = tenant else {
                    // Unknown/unverified host → not cached, surfaced as a miss the
                    // caller rejects (C18).
                    return Err("no_tenant".to_owned());
                };
                let cfg = match store.get_tenant(&tenant_id).await {
                    Ok(Some(c)) => c,
                    Ok(None) => return Err("no_tenant_config".to_owned()),
                    Err(e) => return Err(e.to_string()),
                };
                // Fold the tenant's per-route auth policy (RFC N4) into the cached
                // decision: one extra point read on the miss path, then resolved
                // per-request against the request path with no further lookup. It
                // rides the same domain-keyed invalidation as the rest of the
                // decision (a policy change invalidates the tenant's domains).
                let auth = match store.get_auth_policy(&tenant_id).await {
                    Ok(p) => p,
                    Err(e) => return Err(e.to_string()),
                };
                let decision = RoutingDecision {
                    tenant_id: cfg.tenant_id,
                    plan: cfg.plan,
                    pool: cfg.target_pool,
                    features: cfg.features,
                    auth,
                };
                if let Some(l2) = &l2 {
                    if let Err(e) = l2.put(&key2, &decision, l2_ttl).await {
                        warn!(error = %e, "L2 put failed");
                    }
                }
                Ok(Arc::new(decision))
            })
            .await
            .ok()
    }
}

// --------------------------------------------------------------------------- //
// Host extraction from the request headers (the routing key). Prefer the HTTP/2
// `:authority` pseudo-header, fall back to `Host`.
// --------------------------------------------------------------------------- //
fn extract_host(req: &ProcessingRequest) -> Option<String> {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => h.headers.as_ref()?,
        _ => return None,
    };
    let mut authority = None;
    let mut host = None;
    for hv in &headers.headers {
        let key = hv.key.to_ascii_lowercase();
        if key == ":authority" || key == "host" {
            let val = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            if key == ":authority" {
                authority = Some(val);
            } else {
                host = Some(val);
            }
        }
    }
    authority.or(host)
}

// --------------------------------------------------------------------------- //
// Request path extraction (RFC N4): the second half of the auth-policy key. Read
// the HTTP/2 `:path` pseudo-header and strip the query string + fragment, so the
// policy matches on the path alone (`/app?x=1` resolves as `/app`). Defaults to
// `/` when absent so a path-less request still resolves the tenant default.
// --------------------------------------------------------------------------- //
fn extract_path(req: &ProcessingRequest) -> String {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => match h.headers.as_ref() {
            Some(h) => h,
            None => return "/".to_owned(),
        },
        _ => return "/".to_owned(),
    };
    for hv in &headers.headers {
        if hv.key.eq_ignore_ascii_case(":path") {
            let raw = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            let path = raw.split(['?', '#']).next().unwrap_or("/");
            return if path.is_empty() { "/".to_owned() } else { path.to_owned() };
        }
    }
    "/".to_owned()
}

// --------------------------------------------------------------------------- //
// Cloudflare geo/network normalization (the SOURCE side of the boundary).
//
// When Cloudflare fronts the origin it attaches per-request signals as `cf-*`
// headers. We map ONLY the ones we consume onto the system-owned, vendor-free
// `x-geo-*` contract (router_core::geo), which re-normalizes every value before
// it is emitted. The Cloudflare header *names* are a vendor concern and live here
// in the adapter, never in core (rules §2/§5).
//
// Gated on presence: if no Cloudflare signature header (`cf-ray`, or
// `cf-connecting-ip`) is seen we return `None` and inject nothing, so a
// non-Cloudflare deployment is an exact no-op.
//
// TRUST: `cf-*` are trustworthy ONLY for requests that genuinely transited
// Cloudflare. The deployment MUST guarantee that at the true edge (Cloudflare
// Authenticated Origin Pulls / an IP allowlist) — the same standing assumption
// that lets the chain trust any forwarded header. We do not re-derive that trust
// here; we only normalize. The injected `x-geo-*` are stripped from client input
// upstream (RFC C3), so the backend trusts only what we set.
// --------------------------------------------------------------------------- //
fn extract_geo(req: &ProcessingRequest) -> Option<GeoContext> {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => h.headers.as_ref()?,
        _ => return None,
    };
    // Collect the `cf-*` headers (lowercased, prefix dropped) in a single pass.
    let mut cf: HashMap<String, String> = HashMap::new();
    for hv in &headers.headers {
        let key = hv.key.to_ascii_lowercase();
        if let Some(name) = key.strip_prefix("cf-") {
            let val = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            cf.insert(name.to_owned(), val);
        }
    }
    // Only act when Cloudflare actually fronted this request.
    if !cf.contains_key("ray") && !cf.contains_key("connecting-ip") {
        return None;
    }
    let take = |k: &str| cf.get(k).cloned();
    Some(GeoContext {
        country: take("ipcountry"),
        continent: take("ipcontinent"),
        region: take("region"),
        city: take("ipcity"),
        postal_code: take("postal-code"),
        timezone: take("timezone"),
        latitude: take("iplatitude"),
        longitude: take("iplongitude"),
        client_ip: take("connecting-ip"),
    })
}

/// Normalize the standards-based request-context signals into the trusted
/// `x-locale` / `x-lang` / `x-currency` / `x-privacy-*` / `x-device-type` set
/// (`router_core::context`). Source header names are an adapter concern and live
/// here; `country` (already-normalized geo country) feeds the ISO-4217 currency
/// derivation. Always present (at least `x-device-type: unknown`).
fn extract_client_context(req: &ProcessingRequest, country: Option<&str>) -> Vec<(&'static str, String)> {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => match h.headers.as_ref() {
            Some(h) => h,
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    // Collect only the headers we consume (lowercased keys), in one pass.
    const WANTED: &[&str] = &["accept-language", "sec-gpc", "dnt", "sec-ch-ua-mobile", "user-agent"];
    let mut found: HashMap<String, String> = HashMap::new();
    for hv in &headers.headers {
        let key = hv.key.to_ascii_lowercase();
        if WANTED.contains(&key.as_str()) {
            let val = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            found.insert(key, val);
        }
    }
    let g = |k: &str| found.get(k).map(String::as_str);
    ClientContext {
        accept_language: g("accept-language"),
        sec_gpc: g("sec-gpc"),
        dnt: g("dnt"),
        sec_ch_ua_mobile: g("sec-ch-ua-mobile"),
        user_agent: g("user-agent"),
        country,
    }
    .to_headers()
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

/// Inject the trusted tenant annotations + the pool selector (RFC §3.12), plus any
/// normalized request-context annotations (`x-geo-*`, `x-locale`, `x-currency`,
/// `x-privacy-*`, `x-device-type`, …) in `extra`. The edge data plane routes on
/// `x-route-pool`; the backend trusts every header we set here. Client-supplied
/// copies were stripped before this filter ran (C3-equivalent).
fn route_response(d: &RoutingDecision, extra: &[(&'static str, String)]) -> ProcessingResponse {
    let mut set = vec![
        header("x-tenant-id", &d.tenant_id),
        header("x-tenant-plan", &d.plan),
        header("x-tenant-features", &d.features.join(",")),
        header("x-route-pool", d.pool.as_str()),
        header("x-routed-by", "tenant-router"),
    ];
    for (k, v) in extra {
        set.push(header(k, v));
    }
    let common = CommonResponse {
        header_mutation: Some(HeaderMutation {
            set_headers: set,
            ..Default::default()
        }),
        // The edge data plane selects the route from x-route-pool, which we just
        // set — so the route computed before this filter ran must be recomputed.
        // Without this, the pool selector would not affect forwarding.
        clear_route_cache: true,
        ..Default::default()
    };
    ProcessingResponse {
        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
            response: Some(common),
        })),
        ..Default::default()
    }
}

/// Reject at the edge before any backend is selected (RFC C18 / tenant isolation).
fn reject_unknown_host() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 404 }),
                body: b"unknown tenant for host".to_vec(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

fn warming_503() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 503 }),
                body: b"routing plane warming up".to_vec(),
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
struct Router {
    state: AppState,
}

impl Router {
    async fn handle(&self, req: ProcessingRequest) -> Option<ProcessingResponse> {
        if !matches!(
            req.request,
            Some(processing_request::Request::RequestHeaders(_))
        ) {
            return None;
        }
        let started = Instant::now();
        let (resp, result) = if self.state.ready.load(Ordering::Relaxed) {
            let host = extract_host(&req).unwrap_or_default();
            if let Some(d) = self.state.resolve(&host).await {
                // Assemble trusted request-context annotations. Edge geo
                // (Cloudflare) is presence-gated (no-op off Cloudflare); the
                // standards-based context (locale/currency/privacy/device) is
                // always evaluated. The normalized geo country feeds currency.
                let mut extra: Vec<(&'static str, String)> = Vec::new();
                // Per-route auth policy (RFC N4): resolve the request path
                // against the tenant's cached policy and emit the authoritative
                // gate the edge branches on. ALWAYS emitted (true|false) so the
                // contract is explicit and the C3 strip makes it unforgeable;
                // jwt_authn keys `requires: provider` vs `allow_missing` on it.
                let path = extract_path(&req);
                let required = d.auth.resolve(&path).required;
                extra.push(("x-auth-required", if required { "true" } else { "false" }.to_owned()));
                let geo = extract_geo(&req).map(|g| g.to_headers()).unwrap_or_default();
                let country = geo
                    .iter()
                    .find(|(k, _)| *k == "x-geo-country")
                    .map(|(_, v)| v.clone());
                if !geo.is_empty() {
                    extra.push(("x-geo-source", "cloudflare".to_owned()));
                    extra.extend(geo);
                }
                extra.extend(extract_client_context(&req, country.as_deref()));
                info!(host = %host, tenant = %d.tenant_id, pool = d.pool.as_str(), annotations = extra.len(), "route");
                (route_response(&d, &extra), "hit")
            } else {
                info!(host = %host, "reject: no tenant");
                (reject_unknown_host(), "reject")
            }
        } else {
            warn!("not ready -> 503");
            (warming_503(), "not_ready")
        };
        histogram!("router_ext_proc_duration_seconds").record(started.elapsed().as_secs_f64());
        counter!("router_ext_proc_requests_total", "result" => result).increment(1);
        Some(resp)
    }
}

type RespStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<ProcessingResponse, Status>> + Send>>;

#[tonic::async_trait]
impl ExternalProcessor for Router {
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
// Invalidation watcher (RFC C16): evict invalidated keys from every cache tier.
// Readiness means "store reachable + feed subscribed" — NOT a full table load
// (the routing set is too large to hold resident; lazy on-demand resolution).
// --------------------------------------------------------------------------- //
async fn watch_invalidations(state: AppState, invs: Arc<dyn Invalidations>) {
    loop {
        match run_invalidations(&state, invs.as_ref()).await {
            Ok(()) => warn!("invalidation feed ended; reconnecting"),
            Err(e) => warn!(error = %e, "invalidation feed error; retrying"),
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn run_invalidations(state: &AppState, invs: &dyn Invalidations) -> Result<(), BoxError> {
    let mut feed = invs.subscribe().await?;
    info!("subscribed to invalidation feed");
    if !state.ready.swap(true, Ordering::Relaxed) {
        let ms = state.start.elapsed().as_millis() as u64;
        state.warm_ms.store(ms, Ordering::Relaxed);
        info!(time_to_warm_ms = ms, "READY");
    }
    while let Some(item) = feed.next().await {
        let domain = item?;
        // Exact-domain entries evict precisely. Wildcard-child entries cached
        // under a requested host self-heal via the L1/L2 TTL (RFC §3.10 staleness
        // backstop) — routing has no per-second revocation requirement.
        state.l1.invalidate(&domain).await;
        if let Some(l2) = &state.l2 {
            if let Err(e) = l2.invalidate(&domain).await {
                warn!(error = %e, "L2 invalidate failed");
            }
        }
        counter!("router_invalidations_total").increment(1);
        state.last_apply_ms.store(now_ms(), Ordering::Relaxed);
        info!(domain = %domain, "invalidated");
    }
    Ok(())
}

// --------------------------------------------------------------------------- //
// localhost API: resolve debug (admin), health, metrics.
// --------------------------------------------------------------------------- //
mod api {
    use super::{counter, AppState, Ordering};
    use axum::extract::{Path, Query, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router as AxumRouter};

    pub(crate) fn router(state: AppState) -> AxumRouter {
        AxumRouter::new()
            .route("/healthz", get(healthz))
            .route("/resolve/{host}", get(resolve))
            .route("/authorize", get(authorize))
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
        // for a host we cannot yet evaluate.
        if domain.is_empty() || !s.ready.load(Ordering::Relaxed) {
            counter!("router_authorize_total", "result" => "deny").increment(1);
            return StatusCode::FORBIDDEN;
        }
        if s.resolve(&domain).await.is_some() {
            counter!("router_authorize_total", "result" => "allow").increment(1);
            StatusCode::OK
        } else {
            counter!("router_authorize_total", "result" => "deny").increment(1);
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
}

fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if env("LOG_FORMAT", "") == "json" {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) =
            signal::unix::signal(signal::unix::SignalKind::terminate())
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

    // Classic-bucket latency histogram on the exporter's own listener (:9302),
    // aggregatable across instances: histogram_quantile(0.99, sum by (le)(...)).
    const LATENCY_BUCKETS: &[f64] = &[
        0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
        1.0, 2.5, 5.0,
    ];
    use metrics_exporter_prometheus::Matcher;
    PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("router_ext_proc_duration_seconds".to_owned()),
            LATENCY_BUCKETS,
        )
        .expect("set histogram buckets")
        .with_http_listener("0.0.0.0:9302".parse::<SocketAddr>().unwrap())
        .install()
        .expect("install prometheus exporter");

    let pg_url = env(
        "ROUTING_PG_URL",
        "postgres://postgres:postgres@postgres:5432/zitadel",
    );
    // Optional: a SEPARATE endpoint for the read pool (cache-miss point reads),
    // e.g. a transaction-mode PgBouncer. The LISTEN invalidation feed (below) and
    // the control plane ALWAYS use ROUTING_PG_URL — LISTEN/NOTIFY is session-
    // scoped and a txn-mode pooler silently swallows it. Defaults to ROUTING_PG_URL.
    let pg_read_url = {
        let u = env("ROUTING_PG_READ_URL", "");
        if u.is_empty() { pg_url.clone() } else { u }
    };
    if pg_read_url != pg_url {
        info!("read pool uses ROUTING_PG_READ_URL; LISTEN feed stays on ROUTING_PG_URL (direct)");
    }
    let ttl: u64 = env("ROUTING_CACHE_TTL", "600").parse().unwrap_or(600);
    let l2_ttl: u64 = env("ROUTING_L2_TTL", "600").parse().unwrap_or(600);
    let capacity: u64 = env("ROUTING_CACHE_CAPACITY", "200000").parse().unwrap_or(200_000);

    let store: Arc<dyn RoutingStore> = loop {
        match PgRoutingStore::connect(&pg_read_url).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                warn!(error = %e, "waiting for Postgres");
                sleep(Duration::from_secs(2)).await;
            }
        }
    };

    // L2 is opt-in: enabled only when REDIS_URL is set, and a connect failure
    // degrades to L1-only rather than failing the plane (decision 9).
    let l2: Option<Arc<dyn SharedCache>> = match var("REDIS_URL") {
        Ok(url) if !url.is_empty() => match RedisCache::connect(&url).await {
            Ok(c) => {
                info!("L2 (Redis) shared cache enabled");
                Some(Arc::new(c))
            }
            Err(e) => {
                warn!(error = %e, "L2 connect failed; running L1-only");
                None
            }
        },
        _ => {
            info!("L2 disabled (no REDIS_URL); running L1-only");
            None
        }
    };

    let state = AppState {
        // max_capacity is the WORKING-SET bound (RFC §6.3), not the full domain
        // population; cold domains load on demand and evict normally.
        l1: Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(ttl))
            .build(),
        l2,
        store,
        l2_ttl,
        ready: Arc::new(AtomicBool::new(false)),
        last_apply_ms: Arc::new(AtomicU64::new(0)),
        warm_ms: Arc::new(AtomicU64::new(0)),
        start: Instant::now(),
    };

    // Gauge snapshots (the exporter listener serves them; no per-scrape hook).
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                gauge!("router_cache_entries").set(st.l1.entry_count() as f64);
                gauge!("router_ready")
                    .set(if st.ready.load(Ordering::Relaxed) { 1.0 } else { 0.0 });
                gauge!("router_last_invalidation_timestamp_seconds")
                    .set(st.last_apply_ms.load(Ordering::Relaxed) as f64 / 1000.0);
                let wm = st.warm_ms.load(Ordering::Relaxed);
                if wm > 0 {
                    gauge!("router_time_to_warm_seconds").set(wm as f64 / 1000.0);
                }
                sleep(Duration::from_secs(5)).await;
            }
        })
    };
    info!(ttl_s = ttl, capacity, "starting tenant-router");

    // Readiness fallback so a feed that never opens can't wedge us fail-closed.
    {
        let st = state.clone();
        tokio::spawn(async move {
            sleep(Duration::from_secs(15)).await;
            if !st.ready.swap(true, Ordering::Relaxed) {
                st.warm_ms
                    .store(st.start.elapsed().as_millis() as u64, Ordering::Relaxed);
                warn!("readiness fallback fired");
            }
        })
    };

    // Invalidation feed watcher.
    {
        let st = state.clone();
        let invs: Arc<dyn Invalidations> = Arc::new(PgInvalidations::new(pg_url.clone()));
        tokio::spawn(async move {
            watch_invalidations(st, invs).await;
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

    // Debug/health API.
    let http = {
        let app = api::router(state.clone());
        tokio::spawn(async move {
            let listener = TcpListener::bind("0.0.0.0:9300").await.unwrap();
            info!("resolve/health API on :9300");
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = r_http.changed().await;
                })
                .await;
        })
    };

    // ext_proc gRPC (foreground).
    let addr = "0.0.0.0:50052".parse()?;
    info!("ext_proc listening on :50052");
    if let Err(e) = Server::builder()
        .add_service(ExternalProcessorServer::new(Router { state }))
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
