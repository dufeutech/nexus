//! Tenant Router (Rust) — the routing-plane hot path (RFC C14/C15/C17/C18).
//!
//! It is the routing-plane twin of the identity sidecar: the same Resolution
//! Engine pattern (bounded L1 cache → optional shared L2 → authoritative store,
//! coalesced miss-loads), over a different key/value. Here the key is the
//! request host and the value is a Routing Decision.
//!
//! Surface over one invalidation-updated decision cache:
//!   - `ext_proc` gRPC (hot path): read the request host, normalize it, resolve the
//!     owning workspace + config, and inject trusted `x-workspace-*` + `x-route-pool`
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
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use futures::StreamExt;
use moka::future::Cache;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataMap;
use tonic::{transport::Server, Request, Response, Status, Streaming};
use tracing::{error, info, info_span, warn};
// first-party-telemetry: continue the edge-rooted trace on the hot path. The OTel
// machinery lives behind `router_core::telemetry`; here we only touch `tracing`.
use tracing::field::Empty;
use tracing::Instrument as _;
use tracing::Span;
use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::{global, KeyValue};

use envoy_types::pb::envoy::config::core::v3::{
    header_value_option::HeaderAppendAction, HeaderValue, HeaderValueOption,
};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response, CommonResponse, HeaderMutation, HeadersResponse,
    ImmediateResponse, ProcessingRequest, ProcessingResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;

use router_core::telemetry;
use router_core::auth::RouteAuth;
use router_core::cache::SharedCache;
use router_core::context::ClientContext;
use router_core::domain::RoutingDecision;
use router_core::geo::GeoContext;
use router_core::normalize::{normalize_host, parent_domain};
use router_core::store::{BoxError, Invalidations, RoutingStore};
use cache_redis::RedisCache;
use store_postgres::{PgInvalidations, PgRoutingStore};

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): the RED baseline + operational gauges, emitted
// through the OTel meter (push path via router_core::telemetry). Counter names DROP
// the Prometheus `_total` suffix — Prometheus's OTLP receiver re-appends it, so the
// stored series keep their names (router_ext_proc_requests_total, …) and dashboards
// keep working. The duration histogram carries the same explicit buckets as before,
// so `histogram_quantile(0.99, sum by (le) (rate(..._bucket[5m])))` is unchanged.
// --------------------------------------------------------------------------- //
struct Metrics {
    ext_proc_duration: Histogram<f64>,
    ext_proc_requests: Counter<u64>,
    cache_hits: Counter<u64>,
    cache_misses: Counter<u64>,
    invalidations: Counter<u64>,
    authorize: Counter<u64>,
    cache_entries: Gauge<u64>,
    ready: Gauge<u64>,
    last_invalidation: Gauge<f64>,
    time_to_warm: Gauge<f64>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("tenant-router");
    Metrics {
        ext_proc_duration: meter
            .f64_histogram("router_ext_proc_duration_seconds")
            .with_unit("s")
            .with_boundaries(vec![
                0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
                0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build(),
        ext_proc_requests: meter.u64_counter("router_ext_proc_requests").build(),
        cache_hits: meter.u64_counter("router_cache_hits").build(),
        cache_misses: meter.u64_counter("router_cache_misses").build(),
        invalidations: meter.u64_counter("router_invalidations").build(),
        authorize: meter.u64_counter("router_authorize").build(),
        cache_entries: meter.u64_gauge("router_cache_entries").build(),
        ready: meter.u64_gauge("router_ready").build(),
        last_invalidation: meter
            .f64_gauge("router_last_invalidation_timestamp_seconds")
            .build(),
        time_to_warm: meter.f64_gauge("router_time_to_warm_seconds").build(),
    }
});

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
            METRICS.cache_hits.add(1, &[KeyValue::new("tier", "l1")]);
            return Some(d);
        }
        METRICS.cache_misses.add(1, &[KeyValue::new("tier", "l1")]);

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
                            METRICS.cache_hits.add(1, &[KeyValue::new("tier", "l2")]);
                            return Ok(Arc::new(d));
                        }
                        Ok(None) => {
                            METRICS.cache_misses.add(1, &[KeyValue::new("tier", "l2")]);
                        }
                        Err(e) => warn!(error = %e, "L2 get failed; falling through to store"),
                    }
                }

                // Authoritative store: one exact point read, then one wildcard
                // parent point read (RFC C14 — never a scan).
                let workspace = match store.lookup_domain(&key2, false).await {
                    Ok(Some(t)) => Some(t),
                    Ok(None) => match parent_domain(&key2) {
                        Some(parent) => {
                            store.lookup_domain(&parent, true).await.map_err(|e| e.to_string())?
                        }
                        None => None,
                    },
                    Err(e) => return Err(e.to_string()),
                };
                let Some(workspace_id) = workspace else {
                    // Unknown/unverified host → not cached, surfaced as a miss the
                    // caller rejects (C18).
                    return Err("no_tenant".to_owned());
                };
                let cfg = match store.get_workspace(&workspace_id).await {
                    Ok(Some(c)) => c,
                    Ok(None) => return Err("no_tenant_config".to_owned()),
                    Err(e) => return Err(e.to_string()),
                };
                // Fold the workspace's per-route auth policy (RFC N4) into the cached
                // decision: one extra point read on the miss path, then resolved
                // per-request against the request path with no further lookup. It
                // rides the same domain-keyed invalidation as the rest of the
                // decision (a policy change invalidates the workspace's domains).
                let auth = match store.get_auth_policy(&workspace_id).await {
                    Ok(p) => p,
                    Err(e) => return Err(e.to_string()),
                };
                let decision = RoutingDecision {
                    workspace_id: cfg.workspace_id,
                    plan: cfg.plan,
                    pool: cfg.target_pool,
                    features: cfg.features,
                    auth,
                };
                if let Some(l2) = &l2
                    && let Err(e) = l2.put(&key2, &decision, l2_ttl).await
                {
                    warn!(error = %e, "L2 put failed");
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
// --------------------------------------------------------------------------- //
// Trace-context continuation (first-party-telemetry). The edge injects a W3C
// `traceparent` (edge-rooted, carrying its head-sampling flag) into the request
// headers that arrive here. Extract it so the router's processing span parents
// under the edge trace — closing the first-party hole between edge and backend.
// Only the two W3C headers are read (cheap); the sampled flag is honored by the
// ParentBased sampler, so a not-sampled request produces no exported span.
// --------------------------------------------------------------------------- //
// The edge propagates each request's trace context as gRPC METADATA on the ext_proc
// call (it traces the call itself as an egress span). The ext_proc HTTP headers do
// NOT carry `traceparent` at this point — the edge injects that toward the backend
// AFTER the ext_proc filters run — so the gRPC metadata is the correct source. One
// ext_proc gRPC stream per HTTP request, so this metadata is this request's context.
fn trace_metadata(metadata: &MetadataMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in ["traceparent", "tracestate"] {
        if let Some(value) = metadata.get(name).and_then(|value| value.to_str().ok()) {
            out.push((name.to_owned(), value.to_owned()));
        }
    }
    out
}

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
//
// SECURITY: the edge Envoy canonicalizes :path (normalize_path + merge_slashes +
// path_with_escaped_slashes_action: UNESCAPE_AND_FORWARD) BEFORE this ext_proc
// runs, so the path matched against the auth policy is already dot-segment- and
// %2F-normalized and agrees with what the backend receives. This avoids auth-gate
// path confusion (e.g. `/public%2f..%2fadmin`). Do NOT front the tenant-router
// with a proxy that leaves :path un-normalized.
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

/// Inject the trusted workspace annotations + the pool selector (RFC §3.12), plus
/// any normalized request-context annotations (`x-geo-*`, `x-locale`, `x-currency`,
/// `x-privacy-*`, `x-device-type`, …) in `extra`. The edge data plane routes on
/// `x-route-pool`; the backend trusts every header we set here. Client-supplied
/// copies were stripped before this filter ran (C3-equivalent).
//
// The emitted names are the `x-workspace-*` wire contract (task 4.1 cut-over).
// `x-workspace-id` is the domain's RESOLVED workspace; the identity sidecar runs
// after this filter and either re-asserts it (authoritative, member) or strips it
// (non-member), so the value the backend sees is membership-authorized. The C3 edge
// strip removes any client-forged copy before this filter sets the trusted one.
fn route_response(d: &RoutingDecision, extra: &[(&'static str, String)]) -> ProcessingResponse {
    let mut set = vec![
        header("x-workspace-id", &d.workspace_id),
        header("x-workspace-plan", &d.plan),
        header("x-workspace-features", &d.features.join(",")),
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

/// Per-route auth policy signal names (RFC N4). Hop-internal: emitted here,
/// consumed by the edge (`jwt_authn` branches on the boolean; the identity
/// sidecar enforces the phase-2 requirements), all C3-stripped from client
/// input so they are unforgeable.
const HDR_AUTH_REQUIRED: &str = "x-auth-required";
const HDR_AUTH_REQUIRES_ROLE: &str = "x-auth-requires-role";
const HDR_AUTH_REQUIRES_ENTITLEMENT: &str = "x-auth-requires-entitlement";
const HDR_AUTH_MIN_AAL: &str = "x-auth-min-aal";
/// identity-existence-hiding: marks a protected route as account-scoped (reachable
/// without a workspace membership). Emitted ONLY when set — absence IS the
/// fail-closed workspace-scoped state the sidecar gates on.
const HDR_AUTH_ACCOUNT_SCOPED: &str = "x-auth-account-scoped";

/// The auth-policy signals for one resolved route. The boolean gate is ALWAYS
/// emitted (`true`|`false`) so the contract is explicit; the phase-2 requirement
/// signals are emitted ONLY when the resolved rule sets them — on the wire,
/// absence IS the no-requirement state (mirroring the zero-config default).
fn auth_signals(auth: &RouteAuth) -> Vec<(&'static str, String)> {
    let mut signals = vec![(
        HDR_AUTH_REQUIRED,
        if auth.required { "true" } else { "false" }.to_owned(),
    )];
    if let Some(role) = &auth.requires_role {
        signals.push((HDR_AUTH_REQUIRES_ROLE, role.clone()));
    }
    if let Some(entitlement) = &auth.requires_entitlement {
        signals.push((HDR_AUTH_REQUIRES_ENTITLEMENT, entitlement.clone()));
    }
    if let Some(aal) = auth.min_aal {
        signals.push((HDR_AUTH_MIN_AAL, aal.to_string()));
    }
    // identity-existence-hiding: emit account-scoped ONLY when set, so its wire
    // absence is the fail-closed (workspace-scoped, membership-gated) default.
    if auth.account_scoped {
        signals.push((HDR_AUTH_ACCOUNT_SCOPED, "true".to_owned()));
    }
    signals
}

/// Reject at the edge before any backend is selected (RFC C18 / tenant isolation).
/// identity-existence-hiding: the body is the SAME minimal `"not found"` the identity
/// sidecar's non-member `not_found_404()` emits, so an authenticated prober cannot
/// distinguish "tenant does not exist" (this path) from "tenant exists, not a member"
/// (the sidecar path) by response body. Operational detail (which host, why) stays in
/// logs/metrics, never the client-facing body.
fn reject_unknown_host() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 404 }),
                body: b"not found".to_vec(),
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
    async fn handle(
        &self,
        req: ProcessingRequest,
        trace_meta: &[(String, String)],
    ) -> Option<ProcessingResponse> {
        if !matches!(
            req.request,
            Some(processing_request::Request::RequestHeaders(_))
        ) {
            return None;
        }
        // Continue the edge trace: this span parents under the edge-rooted context
        // (or, absent one, roots per the sampler). `result` is recorded on it after
        // resolution for the trace view; the `info!` events inside are trace-stamped
        // by the log appender, giving the two-way logs↔traces pivot.
        let span = info_span!("router.resolve", route.result = Empty, otel.kind = "server");
        telemetry::continue_trace(&span, trace_meta.to_vec());
        self.resolve(req).instrument(span).await
    }

    async fn resolve(&self, req: ProcessingRequest) -> Option<ProcessingResponse> {
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
                // signals the edge acts on — the boolean gate jwt_authn branches
                // on, plus the phase-2 requirement signals the identity sidecar
                // enforces (emitted only when set; see `auth_signals`).
                let path = extract_path(&req);
                extra.extend(auth_signals(&d.auth.resolve(&path)));
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
                info!(host = %host, workspace = %d.workspace_id, pool = d.pool.as_str(), annotations = extra.len(), "route");
                (route_response(&d, &extra), "hit")
            } else {
                // Debug-format (escapes control/ESC bytes): this is the RAW,
                // un-normalized :authority — the reject branch is exactly where a
                // host `normalize_host` refused can carry log-corrupting bytes.
                info!(host = ?host, "reject: no tenant");
                (reject_unknown_host(), "reject")
            }
        } else {
            warn!("not ready -> 503");
            (warming_503(), "not_ready")
        };
        METRICS.ext_proc_duration.record(started.elapsed().as_secs_f64(), &[]);
        METRICS.ext_proc_requests.add(1, &[KeyValue::new("result", result.to_owned())]);
        Span::current().record("route.result", result);
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
        // Capture the edge's trace context from the ext_proc gRPC metadata before
        // consuming the stream; it parents every span for this request.
        let trace_meta = trace_metadata(request.metadata());
        let mut inbound = request.into_inner();
        let me = self.clone();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(msg) = inbound.next().await {
                match msg {
                    Ok(req) => {
                        if let Some(resp) = me.handle(req, &trace_meta).await
                            && tx.send(Ok(resp)).await.is_err()
                        {
                            break;
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
        if let Some(l2) = &state.l2
            && let Err(e) = l2.invalidate(&domain).await
        {
            warn!(error = %e, "L2 invalidate failed");
        }
        METRICS.invalidations.add(1, &[]);
        state.last_apply_ms.store(now_ms(), Ordering::Relaxed);
        info!(domain = %domain, "invalidated");
    }
    Ok(())
}

// --------------------------------------------------------------------------- //
// localhost API: resolve debug (admin), health, metrics.
// --------------------------------------------------------------------------- //
mod api {
    use super::{AppState, KeyValue, Ordering, METRICS};
    use std::env::var;
    use std::time::Duration;
    use axum::extract::{DefaultBodyLimit, Path, Query, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router as AxumRouter};
    use tower_http::timeout::TimeoutLayer;

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
        // for a host we cannot yet evaluate.
        if domain.is_empty() || !s.ready.load(Ordering::Relaxed) {
            METRICS.authorize.add(1, &[KeyValue::new("result", "deny")]);
            return StatusCode::FORBIDDEN;
        }
        if s.resolve(&domain).await.is_some() {
            METRICS.authorize.add(1, &[KeyValue::new("result", "allow")]);
            StatusCode::OK
        } else {
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
}

fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
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
    // Shared telemetry (first-party-telemetry): stdout logs exactly as before, plus
    // OTLP traces/logs/metrics when OTEL_EXPORTER_OTLP_ENDPOINT is set. Hold the
    // guard for the process lifetime so it flushes on shutdown.
    let _telemetry = telemetry::init("tenant-router");
    // Metrics now push via the OTel meter (first-party-telemetry); the old
    // Prometheus exporter listener (:9302) is retired — the collector's metrics
    // pipeline forwards to the store, no per-box scrape job.

    let pg_url = env(
        "ROUTING_PG_URL",
        "postgres://postgres:postgres@postgres:5432/routing",
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
                METRICS.cache_entries.record(st.l1.entry_count(), &[]);
                METRICS.ready.record(u64::from(st.ready.load(Ordering::Relaxed)), &[]);
                METRICS.last_invalidation.record(st.last_apply_ms.load(Ordering::Relaxed) as f64 / 1000.0, &[]);
                let wm = st.warm_ms.load(Ordering::Relaxed);
                if wm > 0 {
                    METRICS.time_to_warm.record(wm as f64 / 1000.0, &[]);
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

// --------------------------------------------------------------------------- //
// http-request-resilience tests: exercise the REAL resilience layering the API
// server uses. The ext_proc gRPC server is exempt BY CONSTRUCTION (no timeout
// layer is ever attached to the tonic server above); the streaming-exemption
// scenario is exercised end-to-end in identity-rs/sidecar.
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod tests {
    use super::{api, auth_signals, sleep, AppState, RouteAuth};
    use std::collections::HashMap;
    use std::env::var;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::Router as AxumRouter;
    use moka::future::Cache;
    use router_core::auth::AuthPolicy;
    use router_core::domain::{Pool, WorkspaceConfig};
    use router_core::store::{BoxError, DomainRecord, RoutingStore};
    use tower::util::ServiceExt;

    /// Spec "Requirements ride the resolved rule": a gated rule emits exactly the
    /// signals it sets, alongside the always-present boolean gate.
    #[test]
    fn gated_rule_emits_only_its_requirement_signals() {
        let auth = RouteAuth {
            required: true,
            requires_role: Some("admin".into()),
            requires_entitlement: None,
            min_aal: Some(2),
            ..RouteAuth::PASS_THROUGH
        };
        let signals = auth_signals(&auth);
        assert_eq!(
            signals,
            vec![
                ("x-auth-required", "true".to_owned()),
                ("x-auth-requires-role", "admin".to_owned()),
                ("x-auth-min-aal", "2".to_owned()),
            ],
        );
    }

    /// identity-existence-hiding: an account-scoped rule emits the extra signal so
    /// the sidecar skips the membership gate; a workspace-scoped rule (the default)
    /// emits nothing extra, so its wire absence is the fail-closed gated state.
    #[test]
    fn account_scoped_rule_emits_its_signal_only_when_set() {
        let account =
            RouteAuth { required: true, account_scoped: true, ..RouteAuth::PASS_THROUGH };
        assert_eq!(
            auth_signals(&account),
            vec![
                ("x-auth-required", "true".to_owned()),
                ("x-auth-account-scoped", "true".to_owned()),
            ],
        );
        let workspace_scoped = RouteAuth { required: true, ..RouteAuth::PASS_THROUGH };
        assert_eq!(
            auth_signals(&workspace_scoped),
            vec![("x-auth-required", "true".to_owned())],
        );
    }

    /// Spec "Phase-1 rules are unchanged": no requirement fields -> only the
    /// boolean gate goes on the wire (absence IS the no-requirement state).
    /// Convergence after a rule change needs no new test: the policy rides the
    /// cached RoutingDecision, which the existing `routing_invalidations`
    /// machinery already drops and reloads.
    #[test]
    fn phase1_rule_emits_only_the_boolean_gate() {
        let public = RouteAuth::PASS_THROUGH;
        assert_eq!(auth_signals(&public), vec![("x-auth-required", "false".to_owned())]);

        let protected = RouteAuth { required: true, ..RouteAuth::PASS_THROUGH };
        assert_eq!(auth_signals(&protected), vec![("x-auth-required", "true".to_owned())]);
    }

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

    /// An in-memory `RoutingStore` answering only the three reads `resolve` makes:
    /// the exact/wildcard domain lookup, the workspace config, and the (pass-through)
    /// auth policy. Every other control-plane method returns a loud `Err` — the
    /// parity test never drives them, and a stray call should fail rather than lie.
    struct FakeStore {
        /// verified `(domain, is_wildcard)` → `workspace_id`.
        domains: HashMap<(String, bool), String>,
    }

    #[async_trait]
    impl RoutingStore for FakeStore {
        async fn lookup_domain(
            &self,
            domain: &str,
            wildcard: bool,
        ) -> Result<Option<String>, BoxError> {
            Ok(self.domains.get(&(domain.to_owned(), wildcard)).cloned())
        }

        async fn get_workspace(
            &self,
            workspace_id: &str,
        ) -> Result<Option<WorkspaceConfig>, BoxError> {
            // Any workspace a domain row points at has a trivial config — the parity
            // test only cares whether resolution succeeds, not the config's contents.
            Ok(Some(WorkspaceConfig {
                workspace_id: workspace_id.to_owned(),
                plan: "free".to_owned(),
                target_pool: Pool::new("application"),
                features: vec![],
                updated_at: None,
            }))
        }

        async fn get_auth_policy(&self, _workspace_id: &str) -> Result<AuthPolicy, BoxError> {
            Ok(AuthPolicy::default())
        }

        // --- control-plane surface: never exercised by the parity test ---------- //
        async fn upsert_workspace(&self, _cfg: &WorkspaceConfig) -> Result<(), BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn upsert_domain(
            &self,
            _domain: &str,
            _workspace_id: &str,
            _wildcard: bool,
            _verified: bool,
        ) -> Result<(), BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn create_pending_domain(
            &self,
            _domain: &str,
            _workspace_id: &str,
        ) -> Result<bool, BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn set_domain_verified(&self, _domain: &str, _verified: bool) -> Result<(), BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn delete_domain(&self, _domain: &str, _wildcard: bool) -> Result<(), BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn domains_for_workspace(
            &self,
            _workspace_id: &str,
        ) -> Result<Vec<String>, BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn get_domain(
            &self,
            _domain: &str,
            _wildcard: bool,
        ) -> Result<Option<DomainRecord>, BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn count_domains_for_workspace(&self, _workspace_id: &str) -> Result<u32, BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn pending_domains(&self) -> Result<Vec<String>, BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn expire_pending_domains(&self, _ttl_secs: i64) -> Result<Vec<String>, BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn upsert_auth_route(
            &self,
            _workspace_id: &str,
            _prefix: &str,
            _auth: &RouteAuth,
        ) -> Result<(), BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
        async fn delete_auth_route(
            &self,
            _workspace_id: &str,
            _prefix: &str,
        ) -> Result<(), BoxError> {
            Err("FakeStore: control-plane surface is not exercised by the \
                 /authorize-vs-router parity test"
                .into())
        }
    }

    /// Build a ready `AppState` over the fake store (L1-only, no L2), so the real
    /// `api::router` handlers resolve through it.
    fn state_over(store: FakeStore) -> AppState {
        AppState {
            l1: Cache::builder().max_capacity(1024).build(),
            l2: None,
            store: Arc::new(store),
            l2_ttl: 60,
            ready: Arc::new(AtomicBool::new(true)),
            last_apply_ms: Arc::new(AtomicU64::new(0)),
            warm_ms: Arc::new(AtomicU64::new(0)),
            start: Instant::now(),
        }
    }

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
        let mut domains = HashMap::new();
        domains.insert(("shop.example.com".to_owned(), false), "ws_exact".to_owned());
        domains.insert(("example.com".to_owned(), true), "ws_wild".to_owned());
        let state = state_over(FakeStore { domains });

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
}
