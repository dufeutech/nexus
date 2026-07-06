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

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(not(unix))]
use std::future::pending;

use moka::future::Cache;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use futures::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataMap;
use tonic::{transport::Server, Request, Response, Status, Streaming};
use tracing::{debug, error, info, info_span, warn};
// first-party-telemetry: continue the edge-rooted trace on the hot path. The OTel
// machinery lives behind `identity_core::telemetry`; here we only touch `tracing`.
use tracing::field::Empty;
use tracing::Instrument as _;
use tracing::Span;
use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::{global, KeyValue};

use envoy_types::pb::envoy::config::core::v3::{
    header_value_option::HeaderAppendAction, HeaderMap, HeaderValue, HeaderValueOption,
};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::{ExternalProcessor, ExternalProcessorServer},
    processing_request, processing_response, CommonResponse, HeaderMutation, HeadersResponse,
    HttpHeaders, ImmediateResponse, ProcessingRequest, ProcessingResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;

// The Profile shape lives in the shared core crate; the store is reached through
// the core `ProfileStore` port, implemented by the Postgres adapter.
use identity_core::telemetry;
use identity_core::store::{BoxError, Change, ProfileStore, WatchToken};
use identity_core::Profile;
use store_postgres::PgProfileStore;

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): the RED baseline + operational gauges, emitted
// through the OTel meter (push path via identity_core::telemetry). Counter names
// DROP the Prometheus `_total` suffix — Prometheus's OTLP receiver re-appends it, so
// the stored series keep their names (sidecar_ext_proc_requests_total, …). The
// duration histogram carries the same explicit buckets as before.
// --------------------------------------------------------------------------- //
struct Metrics {
    ext_proc_duration: Histogram<f64>,
    ext_proc_requests: Counter<u64>,
    cache_hits: Counter<u64>,
    cache_misses: Counter<u64>,
    kv_updates: Counter<u64>,
    cache_entries: Gauge<u64>,
    ready: Gauge<u64>,
    kv_last_apply: Gauge<f64>,
    time_to_warm: Gauge<f64>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("identity-sidecar");
    Metrics {
        ext_proc_duration: meter
            .f64_histogram("sidecar_ext_proc_duration_seconds")
            .with_unit("s")
            .with_boundaries(vec![
                0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
                0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build(),
        ext_proc_requests: meter.u64_counter("sidecar_ext_proc_requests").build(),
        cache_hits: meter.u64_counter("sidecar_cache_hits").build(),
        cache_misses: meter.u64_counter("sidecar_cache_misses").build(),
        kv_updates: meter.u64_counter("sidecar_kv_updates").build(),
        cache_entries: meter.u64_gauge("sidecar_cache_entries").build(),
        ready: meter.u64_gauge("sidecar_ready").build(),
        kv_last_apply: meter
            .f64_gauge("sidecar_kv_last_apply_timestamp_seconds")
            .build(),
        time_to_warm: meter.f64_gauge("sidecar_time_to_warm_seconds").build(),
    }
});

const JWT_NS: &str = "envoy.filters.http.jwt_authn";
const PAYLOAD_KEY: &str = "verified";

/// Version of the edge→backend identity-header contract this sidecar emits, stamped
/// on every enriched request as `x-identity-contract`. It is the single coordination
/// gate for the whole `x-workspace-*`/`x-user-*` family: any drift in that family's
/// shape (a rename, a removed/added field, a changed meaning) is a version bump, so a
/// partially-deployed contract change fails closed instead of feeding the backend
/// headers it silently misreads. A well-formed `vN` request also carries the
/// authoritative acting scope (`x-workspace-id`/`x-user-type`), so the acting-scope
/// guarantee is PART of this version, not a separate sentinel header. SHARED CONTRACT:
/// the number is coordinated cross-repo with the consuming backend/box — bump both
/// sides together.
const IDENTITY_CONTRACT_VERSION: &str = "v1";

/// Per-route requirement signals (N4 phase 2), emitted by the tenant-router from
/// the tenant's resolved auth policy and C3-stripped from client input — trusted
/// by the time they reach this filter. On the wire, absence IS the
/// no-requirement state; this filter enforces them (403) and strips them before
/// the backend (policy detail never leaves the edge).
const HDR_REQUIRES_ROLE: &str = "x-auth-requires-role";
const HDR_REQUIRES_ENTITLEMENT: &str = "x-auth-requires-entitlement";
const HDR_MIN_AAL: &str = "x-auth-min-aal";

/// Method→assurance-level ordering (N4 phase 2): the single owner of "how strong
/// is this authentication method". Data-driven via `SIDECAR_AAL_LEVELS`
/// (`method=level[,method=level…]`) so richer methods (MFA/passkey) slot in
/// without a rebuild once `x-auth-method` distinguishes them; a method missing
/// from the map fails any min-AAL requirement (closed), never defaults up.
const DEFAULT_AAL_LEVELS: &str = "none=0,bearer=1";

fn parse_aal_levels(spec: &str) -> HashMap<String, u8> {
    spec.split(',')
        .filter_map(|pair| {
            let (method, level) = pair.split_once('=')?;
            Some((method.trim().to_ascii_lowercase(), level.trim().parse().ok()?))
        })
        .collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Clone)]
struct AppState {
    cache: Cache<String, Arc<Profile>>,
    store: Arc<dyn ProfileStore>,
    ready: Arc<AtomicBool>,
    last_apply_ms: Arc<AtomicU64>, // epoch millis of the last applied change
    warm_ms: Arc<AtomicU64>,       // time-to-warm in ms (0 until ready)
    start: Instant,
    /// Security/availability trade for the case where an authenticated request's
    /// profile CANNOT be read (store down / never connected). `false` (default)
    /// fails CLOSED — block with 503 rather than serve a request whose
    /// revocation-sensitive state (`is_suspended`) is unknown, which would let a
    /// suspended user back in during a Postgres outage. `true` restores the prior
    /// availability-first behavior (enrich without a profile). A genuinely absent
    /// profile (no row) is NOT this case and never fails closed.
    fail_open: bool,
    /// The method→AAL ordering the min-AAL requirement compares against
    /// (`SIDECAR_AAL_LEVELS`, default [`DEFAULT_AAL_LEVELS`]).
    aal_levels: Arc<HashMap<String, u8>>,
}

/// The outcome of resolving a subject's profile — distinguishes "no row" (a
/// legitimate authenticated-but-unprofiled user) from "could not read" (store
/// unavailable), which the fail-closed rule depends on.
enum Resolved {
    Found(Arc<Profile>),
    Absent,
    Unavailable,
}

impl AppState {
    /// Cache-first resolve; on miss/expiry, a single coalesced store read (C5).
    /// At 1B scale this miss-load is a normal steady-state path, not a rare
    /// fallback — the cache holds only the hot working set.
    async fn resolve(&self, sub: &str) -> Resolved {
        if let Some(p) = self.cache.get(sub).await {
            METRICS.cache_hits.add(1, &[]);
            return Resolved::Found(p);
        }
        METRICS.cache_misses.add(1, &[]);
        let store = self.store.clone();
        let key = sub.to_owned();
        // try_get_with does not cache the error, so a transient store failure is
        // retried on the next request rather than negatively cached. The
        // "not_found" sentinel is the only non-error "absent" signal.
        match self
            .cache
            .try_get_with(key.clone(), async move {
                match store.get(&key).await {
                    Ok(Some(p)) => Ok(Arc::new(p)),
                    Ok(None) => Err("not_found".to_owned()),
                    Err(e) => Err(e.to_string()),
                }
            })
            .await
        {
            Ok(p) => Resolved::Found(p),
            Err(e) if e.as_str() == "not_found" => Resolved::Absent,
            Err(e) => {
                warn!(error = %e, "profile store read failed");
                Resolved::Unavailable
            }
        }
    }
}

/// The fail-closed rule, isolated so it is unit-testable without a store: an
/// authenticated request whose profile is store-UNAVAILABLE must be blocked
/// unless fail-open is configured. Anonymous requests, found profiles, and
/// genuinely absent profiles never fail closed.
const fn must_fail_closed(authenticated: bool, unavailable: bool, fail_open: bool) -> bool {
    authenticated && unavailable && !fail_open
}

// --------------------------------------------------------------------------- //
// Metadata extraction (C11): the verified `sub` and whether the request is
// authenticated. The token answers ONLY "who am I" — the `roles` claim is
// deliberately NOT read (nexus-native-authorization spec R1): roles, entitlements,
// and suspension are nexus-authored and sourced from the live Profile via the
// AuthzResolver, so a provider-asserted role confers nothing and a grant/revoke
// takes effect within seconds without a token refresh.
// --------------------------------------------------------------------------- //
fn extract_identity(req: &ProcessingRequest) -> (String, bool) {
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
        None => return ("anonymous".to_owned(), true),
    };
    // A verified `sub` is the authority for "authenticated": its presence flips
    // is-anonymous to false. Absence (no sub claim) stays anonymous. No authorization
    // claim (`roles`/`:roles`) is read here — authorization is nexus-sourced (R1).
    match fields.get("sub").and_then(|v| v.kind.as_ref()) {
        Some(Kind::StringValue(s)) if !s.is_empty() => (s.clone(), true),
        _ => ("anonymous".to_owned(), false),
    }
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

/// Read one request header by (case-insensitive) name from the ext_proc
/// `HttpHeaders` payload. Envoy carries the value in `raw_value` (bytes) on modern
/// wire versions and the legacy `value` (string) otherwise — accept either. An
/// empty value is treated as absent.
fn find_header(map: &HeaderMap, name: &str) -> Option<String> {
    map.headers
        .iter()
        .find(|h| h.key.eq_ignore_ascii_case(name))
        .and_then(|h| {
            if h.raw_value.is_empty() {
                Some(h.value.clone())
            } else {
                String::from_utf8(h.raw_value.clone()).ok()
            }
        })
        .filter(|v| !v.is_empty())
}

/// The edge propagates each request's trace context as gRPC METADATA on the ext_proc
/// call (it traces the call itself as an egress span). The ext_proc HTTP headers do
/// NOT carry `traceparent` at this point — the edge injects that toward the backend
/// AFTER the ext_proc filters run — so the gRPC metadata is the correct source. One
/// ext_proc gRPC stream per HTTP request, so this metadata is this request's context.
fn trace_metadata(metadata: &MetadataMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in ["traceparent", "tracestate"] {
        if let Some(value) = metadata.get(name).and_then(|value| value.to_str().ok()) {
            out.push((name.to_owned(), value.to_owned()));
        }
    }
    out
}

/// The workspace the request is acting in, as resolved by the routing plane and
/// carried on a TRUSTED header (never a client-forged value — the edge strips the
/// client's copy and the routing stage overwrites it authoritatively, C3). Prefer
/// the post-cut-over `x-workspace-id`; fall back to the routing plane's current
/// `x-tenant-id` so this works both before and after the header rename (task 4.1).
/// `None` when the request carries no resolved workspace (e.g. a public route) — no
/// acting scope is then authorized.
fn extract_acting_workspace(req: &ProcessingRequest) -> Option<String> {
    let Some(processing_request::Request::RequestHeaders(HttpHeaders { headers: Some(map), .. })) =
        &req.request
    else {
        return None;
    };
    find_header(map, "x-workspace-id").or_else(|| find_header(map, "x-tenant-id"))
}

/// The per-route requirements resolved by the tenant-router for THIS request,
/// read from its trusted signals. `min_aal` is kept raw: an unparseable value is
/// a requirement we cannot evaluate, which must DENY (fail-closed), not vanish.
#[derive(Default)]
struct RouteRequirements {
    role: Option<String>,
    entitlement: Option<String>,
    min_aal: Option<String>,
}

impl RouteRequirements {
    const fn any(&self) -> bool {
        self.role.is_some() || self.entitlement.is_some() || self.min_aal.is_some()
    }
}

fn extract_requirements(req: &ProcessingRequest) -> RouteRequirements {
    let Some(processing_request::Request::RequestHeaders(HttpHeaders { headers: Some(map), .. })) =
        &req.request
    else {
        return RouteRequirements::default();
    };
    RouteRequirements {
        role: find_header(map, HDR_REQUIRES_ROLE),
        entitlement: find_header(map, HDR_REQUIRES_ENTITLEMENT),
        min_aal: find_header(map, HDR_MIN_AAL),
    }
}

/// The N4 phase-2 authorization comparison, isolated for unit tests: EVERY
/// resolved requirement must be satisfied by the enrichment this filter itself
/// computed (never by request headers). A requirement that cannot be evaluated —
/// no enrichment to compare, an unmapped method, an unparseable level — DENIES,
/// so degraded state can never open a gated route.
fn authorize_route(
    reqs: &RouteRequirements,
    roles: &[String],
    entitlements: Option<&[String]>,
    method_level: Option<u8>,
) -> Result<(), &'static str> {
    if let Some(role) = &reqs.role
        && !roles.iter().any(|r| r == role)
    {
        return Err("role");
    }
    if let Some(needed) = &reqs.entitlement {
        match entitlements {
            Some(list) if list.iter().any(|e| e == needed) => {}
            _ => return Err("entitlement"),
        }
    }
    if let Some(min) = &reqs.min_aal {
        let Ok(min) = min.parse::<u8>() else {
            return Err("min_aal_unparseable");
        };
        match method_level {
            Some(level) if level >= min => {}
            _ => return Err("aal"),
        }
    }
    Ok(())
}

/// Gather the comparison inputs from the in-process enrichment state and run
/// [`authorize_route`]. Roles and entitlements are **nexus-authored** (spec R1):
/// sourced ONLY from the live Profile (the AuthzResolver's backing), never the
/// token — so an absent Profile means no roles/entitlements (deny-by-default). The
/// method mirrors the emitted `x-auth-method`.
fn enforce_route_requirements(
    reqs: &RouteRequirements,
    profile: Option<&Arc<Profile>>,
    authenticated: bool,
    aal_levels: &HashMap<String, u8>,
) -> Result<(), &'static str> {
    if !reqs.any() {
        return Ok(());
    }
    let roles: &[String] = profile.map_or(&[], |p| &p.roles);
    let entitlements = profile.map(|p| p.entitlements.as_slice());
    let method = if authenticated { "bearer" } else { "none" };
    authorize_route(reqs, roles, entitlements, aal_levels.get(method).copied())
}

fn enrich_response(
    sub: &str,
    profile: Option<Arc<Profile>>,
    authenticated: bool,
    acting_workspace: Option<&str>,
) -> ProcessingResponse {
    // Trusted auth-state, emitted on EVERY request (incl. the no-credential path)
    // so a backend never has to infer it from the absence of a header. Standards:
    // RFC 6750 bearer presence drives is-anonymous; richer assurance (NIST
    // SP 800-63B AAL, mTLS) can extend `x-auth-method` later. These are stripped
    // from client input (C3) so a client cannot self-assert as authenticated.
    let mut set = vec![
        // The contract stamp: a DRIFT/version signal telling the backend which
        // shape of the x-workspace-*/x-user-* family this edge emits — NOT proof
        // of edge origin (that guarantee is edge-origin-trust origin enforcement:
        // backends are reachable only via the edge). Authored on EVERY enriched
        // request; since it is always in `set` (OverwriteIfExistsOrAdd) it needs
        // no entry in `remove` — the overwrite is order-independent, and the edge
        // C3 strip already discards any client copy.
        header("x-identity-contract", IDENTITY_CONTRACT_VERSION),
        header("x-auth-anonymous", if authenticated { "false" } else { "true" }),
        header("x-auth-method", if authenticated { "bearer" } else { "none" }),
        header("x-user-id", sub),
    ];
    // Roles are NEXUS-AUTHORED (spec R1): sourced ONLY from the live Profile (the
    // AuthzResolver's backing), NEVER the token — so a grant/revoke takes effect
    // within seconds without a token refresh, and a provider-asserted role confers
    // nothing. Absent Profile → empty roles (deny-by-default). Always authored
    // (OverwriteIfExistsOrAdd), so a client copy is overwritten. `x-user-roles-source`
    // is retired — the source is always nexus now.
    let roles = profile.as_ref().map_or_else(String::new, |p| p.roles.join(","));
    set.push(header("x-user-roles", &roles));
    // Defense-in-depth strip (RFC C3, belt-and-suspenders vs. the edge strip):
    // the sidecar removes any client-supplied identity header it does NOT itself
    // author on THIS path, so a forged value can't reach the backend even if the
    // sidecar is somehow reached without the stripping edge in front. Headers we
    // DO set below are overwritten authoritatively (OverwriteIfExistsOrAdd), so
    // they are deliberately kept OUT of this remove list — that keeps the result
    // independent of Envoy's set-vs-remove apply order (a header in both lists
    // could otherwise be wiped after we set it).
    // `x-auth-required` is consumed by jwt_authn upstream and never authored
    // here, so it is always stripped before forwarding to the backend. The
    // phase-2 requirement signals are consumed by THIS filter's gate and are
    // policy detail no backend needs — stripped the same way (design D5).
    let mut remove = vec![
        "x-auth-required".to_owned(),
        HDR_REQUIRES_ROLE.to_owned(),
        HDR_REQUIRES_ENTITLEMENT.to_owned(),
        HDR_MIN_AAL.to_owned(),
    ];
    // The nexus-owned acting scope (workspace-tenancy 3.2). Authored ONLY from a
    // LIVE membership check of the resolved workspace against the Profile — never
    // from the token — so a revoked/changed membership takes effect within seconds
    // (like suspension). A non-member, an absent profile, or no resolved workspace
    // authors nothing and STRIPS any client/forged copy, so the sidecar can never
    // let an unauthorized acting scope reach the backend (fail-closed; the
    // reject-vs-anonymous-vs-signup policy for a non-member is the backend's, per
    // the surface). `x-user-type`/`x-user-role` are the matched relationship's, not
    // a global role; the plural `x-user-roles` above stays the coarse token/profile
    // roles.
    let acting = acting_workspace
        .zip(profile.as_ref())
        .and_then(|(ws, p)| p.resolve_membership(ws));
    if let Some(m) = &acting {
        set.push(header("x-workspace-id", &m.workspace_id));
        set.push(header("x-user-type", m.member_type.as_str()));
        set.push(header("x-user-role", &m.role));
    } else {
        remove.push("x-workspace-id".to_owned());
        remove.push("x-user-type".to_owned());
        remove.push("x-user-role".to_owned());
    }
    // `x-user-org` is retired (workspace-tenancy): the fixed home org is no longer
    // an authorization input, so it is NEVER authored and ALWAYS stripped from
    // client input, on every path.
    remove.push("x-user-org".to_owned());
    if let Some(p) = &profile {
        set.push(header("x-user-entitlements", &p.entitlements.join(",")));
        // Revocation-sensitive: ALWAYS from the live Profile, never the token,
        // so a suspension takes effect within seconds without a token refresh.
        set.push(header(
            "x-user-suspended",
            if p.is_suspended { "true" } else { "false" },
        ));
        set.push(header("x-user-enriched-by", "identity-sidecar-rs"));
    } else {
        // No profile: this response does NOT author entitlements/suspended, so
        // strip any client copies. Suspension especially — an absent
        // x-user-suspended must mean "unknown", never a client-asserted "false"
        // that would slip a suspended user through.
        remove.push("x-user-entitlements".to_owned());
        remove.push("x-user-suspended".to_owned());
        set.push(header("x-user-enriched-by", "identity-sidecar-rs:miss"));
    }
    let common = CommonResponse {
        header_mutation: Some(HeaderMutation {
            set_headers: set,
            remove_headers: remove,
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

fn immediate_503(body: &'static str) -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 503 }),
                body: body.as_bytes().to_vec(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

fn warming_503() -> ProcessingResponse {
    immediate_503("identity plane warming up")
}

/// Fail-closed block: the request is authenticated but the subject's profile
/// (incl. its revocation-sensitive `is_suspended`) could not be read. Refuse
/// rather than serve a trust decision we cannot make (see `AppState::fail_open`).
fn unavailable_503() -> ProcessingResponse {
    immediate_503("identity store unavailable")
}

/// N4 phase-2 rejection: the route's resolved requirements are not satisfied by
/// this request's enrichment. The body deliberately names no requirement — the
/// policy detail stays at the edge.
fn forbidden_403() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 403 }),
                body: b"forbidden".to_vec(),
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
        // so the enrichment stage appears between the routing and backend spans (no
        // first-party hole). `enrich.result` is recorded after; the `info!`/`debug!`
        // events inside are trace-stamped for the two-way logs↔traces pivot.
        let span = info_span!("identity.enrich", enrich.result = Empty, otel.kind = "server");
        telemetry::continue_trace(&span, trace_meta.to_vec());
        self.enrich(req).instrument(span).await
    }

    async fn enrich(&self, req: ProcessingRequest) -> Option<ProcessingResponse> {
        let started = Instant::now();
        let (resp, result) = if self.state.ready.load(Ordering::Relaxed) {
            'decide: {
                let (sub, authenticated) = extract_identity(&req);
                // The workspace this request acts in, from the trusted routing header.
                // Threaded into enrich so the membership check authorizes the SAME
                // workspace the router resolved (not a client-chosen one).
                let acting_workspace = extract_acting_workspace(&req);
                let ws = acting_workspace.as_deref();
                // The per-route requirements the tenant-router resolved (N4 phase 2).
                let requirements = extract_requirements(&req);
                // `sub` is a user identifier (PII): keep it out of per-request info
                // logs (enable debug for the subject when diagnosing a specific user).
                debug!(sub = %sub, "enrich subject");
                let (profile, result) = if authenticated {
                    match self.state.resolve(&sub).await {
                        Resolved::Found(p) => {
                            info!(anonymous = false, hit = true, "enrich");
                            (Some(p), "hit")
                        }
                        // Authenticated but no profile row yet — a legitimate state
                        // (deny-by-default, spec R2); enrich without authz fields.
                        Resolved::Absent => {
                            info!(anonymous = false, hit = false, "enrich");
                            (None, "miss")
                        }
                        // Store unreadable → suspension state is UNKNOWN. Fail closed
                        // by default so a suspended user can't slip through during a
                        // store outage; SIDECAR_FAIL_OPEN trades back to availability.
                        Resolved::Unavailable => {
                            if must_fail_closed(true, true, self.state.fail_open) {
                                warn!("store unavailable for authenticated request -> 503 (fail-closed)");
                                break 'decide (unavailable_503(), "unavailable_closed");
                            }
                            warn!("store unavailable for authenticated request -> enrich without profile (fail-open)");
                            (None, "unavailable_open")
                        }
                    }
                } else {
                    // Don't touch the store for unauthenticated requests: the subject
                    // is "anonymous" (no credential), which is never a stored profile —
                    // so a lookup is a guaranteed miss that needlessly loads the pool on
                    // high-volume anonymous traffic (and is not negatively cached).
                    info!(anonymous = true, "enrich");
                    (None, "anonymous")
                };
                // N4 phase-2 gate: every resolved requirement must be satisfied by
                // the enrichment computed above, else 403 before the backend.
                // jwt_authn upstream owns the anonymous-on-protected-route 401; an
                // anonymous request carrying requirement signals means something
                // upstream is misconfigured, and it denies here (fail-closed).
                if let Err(reason) = enforce_route_requirements(
                    &requirements,
                    profile.as_ref(),
                    authenticated,
                    &self.state.aal_levels,
                ) {
                    info!(reason, "route requirements unsatisfied -> 403");
                    break 'decide (forbidden_403(), "forbidden");
                }
                (enrich_response(&sub, profile, authenticated, ws), result)
            }
        } else {
            warn!("not ready -> 503");
            (warming_503(), "not_ready")
        };
        METRICS.ext_proc_duration.record(started.elapsed().as_secs_f64(), &[]);
        METRICS.ext_proc_requests.add(1, &[KeyValue::new("result", result.to_owned())]);
        Span::current().record("enrich.result", result);
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
                METRICS.kv_updates.add(1, &[KeyValue::new("op", "upsert")]);
            }
            Change::Delete(sub) => {
                state.cache.invalidate(&sub).await;
                METRICS.kv_updates.add(1, &[KeyValue::new("op", "delete")]);
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
    use super::{AppState, Ordering, Resolved};
    use std::env::var;
    use std::time::Duration;
    use axum::extract::{DefaultBodyLimit, Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
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
}

/// Resolves when the process receives SIGINT or (on unix) SIGTERM.
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
    // Shared telemetry (first-party-telemetry): stdout logs as before, plus OTLP
    // traces/logs/metrics when OTEL_EXPORTER_OTLP_ENDPOINT is set. Held for the
    // process lifetime so it flushes on shutdown.
    let _telemetry = telemetry::init("identity-sidecar");
    // Metrics now push via the OTel meter (first-party-telemetry); the old
    // Prometheus exporter listener (:9202) is retired. The duration histogram keeps
    // the same explicit buckets (see METRICS), so the p99 query is unchanged; the
    // native-histogram exposition is superseded by the OTLP push path.

    // The sidecar only reads + listens, so this URL needs SELECT + LISTEN, never
    // schema creation. It MUST reach the primary on a session connection — a
    // transaction-mode pooler silently swallows LISTEN (see deploy/README.md).
    let pg_url = env::var("PROFILE_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@postgres:5432/identitydb".into());
    let ttl: u64 = env::var("CACHE_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(43_200);
    let readiness_delay: u64 = env::var("READINESS_DELAY_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    // Default fail-CLOSED: when an authenticated request's profile can't be read,
    // block rather than serve it without its suspension state (see AppState).
    let fail_open = env::var("SIDECAR_FAIL_OPEN")
        .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
    let aal_levels = parse_aal_levels(
        &env::var("SIDECAR_AAL_LEVELS").unwrap_or_else(|_| DEFAULT_AAL_LEVELS.to_owned()),
    );

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
        fail_open,
        aal_levels: Arc::new(aal_levels),
    };

    // Periodically publish the gauge-style snapshots (the exporter's own listener
    // serves them; there is no per-scrape hook to set them on).
    {
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                METRICS.cache_entries.record(st.cache.entry_count(), &[]);
                METRICS.ready.record(u64::from(st.ready.load(Ordering::Relaxed)), &[]);
                METRICS.kv_last_apply.record(st.last_apply_ms.load(Ordering::Relaxed) as f64 / 1000.0, &[]);
                let wm = st.warm_ms.load(Ordering::Relaxed);
                if wm > 0 {
                    METRICS.time_to_warm.record(wm as f64 / 1000.0, &[]);
                }
                sleep(Duration::from_secs(5)).await;
            }
        })
    };
    info!(ttl_s = ttl, readiness_delay_s = readiness_delay, fail_open, "starting identity-sidecar-rs");

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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, reason = "test helpers legitimately panic on the impossible branch")]
    use super::*;
    use identity_core::{MemberType, Membership};
    use std::collections::HashMap;

    /// A Profile holding one workspace membership, for the resolution matrix.
    fn member_profile(ws: &str, ty: MemberType, role: &str) -> Arc<Profile> {
        Arc::new(Profile {
            sub: "u1".into(),
            memberships: vec![Membership {
                workspace_id: ws.into(),
                member_type: ty,
                role: role.into(),
                entitlements: vec![],
            }],
            ..Default::default()
        })
    }

    /// Collect the response's set headers into a map for assertions.
    fn set_headers(resp: &ProcessingResponse) -> HashMap<String, String> {
        let Some(processing_response::Response::RequestHeaders(h)) = &resp.response else {
            panic!("expected RequestHeaders response");
        };
        h.response
            .as_ref()
            .and_then(|c| c.header_mutation.as_ref())
            .map(|m| {
                m.set_headers
                    .iter()
                    .filter_map(|opt| opt.header.as_ref())
                    .map(|hv| {
                        (hv.key.clone(), String::from_utf8_lossy(&hv.raw_value).into_owned())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Collect the response's removed header names.
    fn remove_headers(resp: &ProcessingResponse) -> Vec<String> {
        let Some(processing_response::Response::RequestHeaders(h)) = &resp.response else {
            panic!("expected RequestHeaders response");
        };
        h.response
            .as_ref()
            .and_then(|c| c.header_mutation.as_ref())
            .map(|m| m.remove_headers.clone())
            .unwrap_or_default()
    }

    #[test]
    fn strips_unauthored_identity_headers_defense_in_depth() {
        // x-auth-required is consumed by jwt_authn upstream and is never authored
        // by the sidecar -> always stripped before the backend, on every path.
        let some = enrich_response(
            "u1",
            Some(Arc::new(Profile { sub: "u1".into(), ..Default::default() })),
            true,
            None,
        );
        let r_some = remove_headers(&some);
        assert!(r_some.contains(&"x-auth-required".to_owned()));
        // On the profile-present path the sidecar AUTHORS entitlements/suspended, so
        // it must NOT also remove them (that would risk wiping the value it just set,
        // depending on Envoy's apply order).
        assert!(!r_some.contains(&"x-user-suspended".to_owned()));
        // `x-user-org` is retired: never authored, so ALWAYS stripped — even on the
        // profile-present path.
        assert!(r_some.contains(&"x-user-org".to_owned()));
        // No acting workspace resolved -> no membership -> the acting scope is
        // stripped, never asserted.
        for h in ["x-workspace-id", "x-user-type", "x-user-role"] {
            assert!(r_some.contains(&h.to_owned()), "non-member must strip {h}");
        }

        // On a profile MISS the sidecar authors none of those, so any client copy
        // must be stripped — suspension especially (absent == unknown).
        let miss = enrich_response("u1", None, true, None);
        let r_miss = remove_headers(&miss);
        for h in ["x-auth-required", "x-user-org", "x-user-entitlements", "x-user-suspended"] {
            assert!(r_miss.contains(&h.to_owned()), "miss path must strip {h}");
        }
        // And it must still not ASSERT a suspension on the miss path.
        assert!(!set_headers(&miss).contains_key("x-user-suspended"));
    }

    fn is_immediate_503(resp: &ProcessingResponse) -> bool {
        matches!(
            &resp.response,
            Some(processing_response::Response::ImmediateResponse(r))
                if r.status.as_ref().map(|s| s.code) == Some(503)
        )
    }

    #[test]
    fn fail_closed_only_for_authenticated_unavailable_when_not_open() {
        // The one and only case that blocks: authenticated + store unavailable +
        // fail-open disabled.
        assert!(must_fail_closed(true, true, false));
        // Fail-open configured → never block.
        assert!(!must_fail_closed(true, true, true));
        // Anonymous never blocks (it never touches the store).
        assert!(!must_fail_closed(false, true, false));
        // Store readable (found/absent) never blocks.
        assert!(!must_fail_closed(true, false, false));
    }

    #[test]
    fn enrich_emits_live_suspension_only_from_profile() {
        let suspended = Arc::new(Profile {
            sub: "u1".into(),
            is_suspended: true,
            ..Default::default()
        });
        let h = set_headers(&enrich_response("u1", Some(suspended), true, None));
        assert_eq!(h.get("x-user-suspended").map(String::as_str), Some("true"));
        assert_eq!(h.get("x-auth-anonymous").map(String::as_str), Some("false"));

        // A profile MISS (no row) must NOT assert a suspension either way — the
        // header is simply absent, which is exactly why a store outage that
        // collapses to "miss" is dangerous and must instead fail closed.
        let h_miss = set_headers(&enrich_response("u1", None, true, None));
        assert!(!h_miss.contains_key("x-user-suspended"));
    }

    #[test]
    fn unavailable_503_is_a_blocking_503() {
        assert!(is_immediate_503(&unavailable_503()));
        assert!(is_immediate_503(&warming_503()));
    }

    /// Build a RequestHeaders ext_proc message carrying the given headers.
    fn req_with_headers(pairs: &[(&str, &str)]) -> ProcessingRequest {
        ProcessingRequest {
            request: Some(processing_request::Request::RequestHeaders(HttpHeaders {
                headers: Some(HeaderMap {
                    headers: pairs
                        .iter()
                        .map(|(k, v)| HeaderValue {
                            key: (*k).to_owned(),
                            raw_value: v.as_bytes().to_vec(),
                            ..Default::default()
                        })
                        .collect(),
                }),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn member_gets_authoritative_workspace_scope() {
        // Member of the resolved workspace -> authoritative scope is emitted and
        // NOT in the strip list (it was authored).
        let resp = enrich_response(
            "u1",
            Some(member_profile("ws_1", MemberType::Staff, "admin")),
            true,
            Some("ws_1"),
        );
        let h = set_headers(&resp);
        assert_eq!(h.get("x-workspace-id").map(String::as_str), Some("ws_1"));
        assert_eq!(h.get("x-user-type").map(String::as_str), Some("staff"));
        assert_eq!(h.get("x-user-role").map(String::as_str), Some("admin"));
        let r = remove_headers(&resp);
        for hh in ["x-workspace-id", "x-user-type", "x-user-role"] {
            assert!(!r.contains(&hh.to_owned()), "authored {hh} must not be stripped");
        }
    }

    #[test]
    fn member_type_and_role_are_workspace_scoped() {
        // Customer of ws_2 resolves to the customer type + the ws-scoped role.
        let resp = enrich_response(
            "u1",
            Some(member_profile("ws_2", MemberType::Customer, "buyer")),
            true,
            Some("ws_2"),
        );
        let h = set_headers(&resp);
        assert_eq!(h.get("x-user-type").map(String::as_str), Some("customer"));
        assert_eq!(h.get("x-user-role").map(String::as_str), Some("buyer"));
    }

    #[test]
    fn non_member_of_acting_workspace_is_fail_closed() {
        // Member of ws_1, but the request resolves to a DIFFERENT workspace -> no
        // authoritative scope, and any forged copy is stripped (fail-closed).
        let resp = enrich_response(
            "u1",
            Some(member_profile("ws_1", MemberType::Staff, "admin")),
            true,
            Some("ws_other"),
        );
        assert!(!set_headers(&resp).contains_key("x-workspace-id"));
        let r = remove_headers(&resp);
        for hh in ["x-workspace-id", "x-user-type", "x-user-role"] {
            assert!(r.contains(&hh.to_owned()), "non-member must strip {hh}");
        }
    }

    #[test]
    fn contract_stamp_is_emitted_on_every_enriched_path() {
        // The contract stamp proves the identity headers came from the trusted edge.
        // It is authored on EVERY forwarded path — member, non-member, profile miss,
        // and anonymous — so the backend can reject an absent stamp as a bypass.
        let cases = [
            // (label, response)
            (
                "member",
                enrich_response(
                    "u1",
                    Some(member_profile("ws_1", MemberType::Staff, "admin")),
                    true,
                    Some("ws_1"),
                ),
            ),
            (
                "non_member",
                enrich_response(
                    "u1",
                    Some(member_profile("ws_1", MemberType::Staff, "admin")),
                    true,
                    Some("ws_other"),
                ),
            ),
            ("miss", enrich_response("u1", None, true, None)),
            ("anonymous", enrich_response("anonymous", None, false, None)),
        ];
        for (label, resp) in &cases {
            let h = set_headers(resp);
            assert_eq!(
                h.get("x-identity-contract").map(String::as_str),
                Some("v1"),
                "{label} path must stamp the contract version",
            );
            // Always authored -> must never appear in the strip list (order-independent).
            assert!(
                !remove_headers(resp).contains(&"x-identity-contract".to_owned()),
                "{label} path must not strip the authored contract stamp",
            );
        }
    }

    #[test]
    fn acting_workspace_prefers_x_workspace_id_then_x_tenant_id() {
        // The post-cut-over authoritative name wins over the routing plane's current
        // x-tenant-id.
        let both = req_with_headers(&[("x-tenant-id", "ws_routing"), ("x-workspace-id", "ws_new")]);
        assert_eq!(extract_acting_workspace(&both).as_deref(), Some("ws_new"));
        // Falls back to the routing plane's current header before the rename.
        let legacy = req_with_headers(&[("X-Tenant-Id", "ws_routing")]);
        assert_eq!(extract_acting_workspace(&legacy).as_deref(), Some("ws_routing"));
        // An empty value is treated as absent (no acting workspace).
        let empty = req_with_headers(&[("x-workspace-id", "")]);
        assert_eq!(extract_acting_workspace(&empty), None);
    }

    // ---- N4 phase-2 route requirements (edge-role-entitlement-gate) ---------- //

    /// A profile carrying coarse roles + entitlements for the gate matrix.
    fn gated_profile(roles: &[&str], entitlements: &[&str]) -> Arc<Profile> {
        Arc::new(Profile {
            sub: "u1".into(),
            roles: roles.iter().map(|s| (*s).to_owned()).collect(),
            entitlements: entitlements.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        })
    }

    fn levels() -> HashMap<String, u8> {
        parse_aal_levels(DEFAULT_AAL_LEVELS)
    }

    fn reqs(role: Option<&str>, ent: Option<&str>, aal: Option<&str>) -> RouteRequirements {
        RouteRequirements {
            role: role.map(str::to_owned),
            entitlement: ent.map(str::to_owned),
            min_aal: aal.map(str::to_owned),
        }
    }

    /// Spec "Satisfied requirements pass to the backend" + "Phase-1 parity".
    #[test]
    fn satisfied_requirements_pass() {
        let p = gated_profile(&["admin"], &["pro"]);
        assert_eq!(
            enforce_route_requirements(
                &reqs(Some("admin"), Some("pro"), Some("1")),
                Some(&p),
                true,
                &levels(),
            ),
            Ok(()),
        );
        // No signals -> no enforcement, regardless of enrichment state.
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, None), None, false, &levels()),
            Ok(()),
        );
    }

    /// Spec "Missing role is rejected" — roles are nexus-authored only (spec R1), so
    /// only a role on the Profile satisfies a role requirement; there is no token
    /// path (see `role_claiming_token_confers_nothing`).
    #[test]
    fn missing_role_is_denied_nexus_roles_only() {
        let viewer = gated_profile(&["viewer"], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), Some(&viewer), true, &levels()),
            Err("role"),
        );
        // The same requirement satisfied by a NEXUS-AUTHORED role on the Profile.
        let admin = gated_profile(&["admin"], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), Some(&admin), true, &levels()),
            Ok(()),
        );
    }

    /// Spec "Missing entitlement is rejected (plan gate)".
    #[test]
    fn missing_entitlement_is_denied() {
        let p = gated_profile(&[], &["free"]);
        assert_eq!(
            enforce_route_requirements(&reqs(None, Some("pro"), None), Some(&p), true, &levels()),
            Err("entitlement"),
        );
    }

    /// Spec "Insufficient assurance level is rejected": bearer maps to 1 in the
    /// default ordering, so a min of 2 denies; an unparseable minimum also denies.
    #[test]
    fn insufficient_or_unparseable_aal_is_denied() {
        let p = gated_profile(&[], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("2")), Some(&p), true, &levels()),
            Err("aal"),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("1")), Some(&p), true, &levels()),
            Ok(()),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("high")), Some(&p), true, &levels()),
            Err("min_aal_unparseable"),
        );
    }

    /// Spec "Requirement with absent enrichment fails closed": no profile means
    /// an entitlement requirement cannot be evaluated -> deny, never pass. The
    /// anonymous case (upstream misconfiguration — jwt_authn should have 401'd)
    /// also denies: no roles, and "none" maps below any positive minimum.
    #[test]
    fn requirement_with_absent_enrichment_fails_closed() {
        assert_eq!(
            enforce_route_requirements(&reqs(None, Some("pro"), None), None, true, &levels()),
            Err("entitlement"),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), None, false, &levels()),
            Err("role"),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("1")), None, false, &levels()),
            Err("aal"),
        );
        // A method absent from the ordering can satisfy nothing (fail-closed).
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("1")), None, true, &HashMap::new()),
            Err("aal"),
        );
    }

    #[test]
    fn requirement_signals_are_read_and_stripped() {
        // The tenant-router's trusted signals parse out of the request…
        let req = req_with_headers(&[
            ("x-auth-requires-role", "admin"),
            ("x-auth-min-aal", "2"),
        ]);
        let r = extract_requirements(&req);
        assert_eq!(r.role.as_deref(), Some("admin"));
        assert_eq!(r.entitlement, None);
        assert_eq!(r.min_aal.as_deref(), Some("2"));
        // …and every forwarded response strips them (policy detail never
        // reaches the backend), alongside the phase-1 boolean.
        let resp = enrich_response("u1", None, true, None);
        let removed = remove_headers(&resp);
        for h in ["x-auth-required", "x-auth-requires-role", "x-auth-requires-entitlement", "x-auth-min-aal"] {
            assert!(removed.contains(&h.to_owned()), "must strip {h}");
        }
    }

    /// Spec R1 / task 8.1: a role-claiming token confers nothing. Roles are
    /// nexus-authored only — sourced from the Profile, never the token. A subject
    /// nexus holds no roles for gets an empty `x-user-roles` and is refused a
    /// role-gated route; even a Profile role that isn't the required one denies.
    /// (Structurally there is NO token→roles path: `extract_identity` reads no roles
    /// claim and `enrich_response`/`enforce_route_requirements` take no token roles.)
    #[test]
    fn role_claiming_token_confers_nothing() {
        // No nexus Profile → deny-by-default: empty roles header, role route refused.
        let miss = enrich_response("u1", None, true, None);
        assert_eq!(set_headers(&miss).get("x-user-roles").map(String::as_str), Some(""));
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), None, true, &levels()),
            Err("role"),
        );
        // A Profile with only a different nexus role still denies the admin route.
        let viewer = gated_profile(&["viewer"], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), Some(&viewer), true, &levels()),
            Err("role"),
        );
        // The emitted roles are exactly the nexus-authored set, nothing else.
        let h = set_headers(&enrich_response("u1", Some(viewer), true, None));
        assert_eq!(h.get("x-user-roles").map(String::as_str), Some("viewer"));
    }

    #[test]
    fn aal_levels_parse_with_default_and_override() {
        let d = levels();
        assert_eq!(d.get("none").copied(), Some(0));
        assert_eq!(d.get("bearer").copied(), Some(1));
        // An override adds methods and skips malformed pairs instead of failing.
        let custom = parse_aal_levels("none=0, Bearer=1, mfa=2, bogus, empty=");
        assert_eq!(custom.get("bearer").copied(), Some(1));
        assert_eq!(custom.get("mfa").copied(), Some(2));
        assert_eq!(custom.len(), 3);
    }

    #[test]
    fn forbidden_403_is_an_immediate_403() {
        matches!(
            &forbidden_403().response,
            Some(processing_response::Response::ImmediateResponse(r))
                if r.status.as_ref().map(|s| s.code) == Some(403)
        )
        .then_some(())
        .expect("expected an immediate 403");
    }

    // ---- http-request-resilience -------------------------------------------- //

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
        let app = api::resilient(
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
        let app = api::resilient(
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
        if env::var("HTTP_REQUEST_TIMEOUT_SECS").is_ok() {
            return; // SKIP: the environment overrides the default under test
        }
        assert_eq!(
            api::request_timeout(),
            Duration::from_secs(30),
            "default request timeout must be the documented finite 30s",
        );
    }

    /// The ext_proc gRPC stream is EXEMPT from the per-request timeout: one
    /// stream serves a trusted Envoy connection for its lifetime, so it must
    /// stay open well past the bound the HTTP surfaces enforce and keep
    /// processing messages. Serves the REAL tonic service construction main()
    /// uses, on an ephemeral port.
    #[tokio::test]
    async fn ext_proc_stream_survives_past_the_http_request_timeout() {
        use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_client::ExternalProcessorClient;
        use futures::stream::pending as pending_stream;
        use identity_core::store::ChangeFeed;
        use tokio_stream::wrappers::TcpListenerStream;

        /// Store stub: the anonymous enrich path never reads it; watch never yields.
        struct NoStore;
        #[tonic::async_trait]
        impl ProfileStore for NoStore {
            async fn get(&self, _sub: &str) -> Result<Option<Profile>, BoxError> {
                Ok(None)
            }
            async fn put(&self, _profile: &Profile) -> Result<(), BoxError> {
                Ok(())
            }
            async fn delete(&self, _sub: &str) -> Result<(), BoxError> {
                Ok(())
            }
            async fn scan_all(&self) -> Result<Vec<Profile>, BoxError> {
                Ok(vec![])
            }
            async fn watch(&self, _after: Option<WatchToken>) -> Result<ChangeFeed, BoxError> {
                Ok(Box::pin(pending_stream()))
            }
        }

        let state = AppState {
            cache: Cache::new(16),
            store: Arc::new(NoStore),
            ready: Arc::new(AtomicBool::new(true)),
            last_apply_ms: Arc::new(AtomicU64::new(0)),
            warm_ms: Arc::new(AtomicU64::new(0)),
            start: Instant::now(),
            fail_open: false,
            aal_levels: Arc::new(parse_aal_levels(DEFAULT_AAL_LEVELS)),
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        drop(tokio::spawn(async move {
            Server::builder()
                .add_service(ExternalProcessorServer::new(Sidecar { state }))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        }));

        let mut client = loop {
            match ExternalProcessorClient::connect(format!("http://{addr}")).await {
                Ok(conn) => break conn,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        };

        // Much tighter than the 30s production default, to keep the test fast:
        // the stream must outlive this HTTP-surface bound with room to spare.
        let http_timeout = Duration::from_millis(300);

        let (tx, rx) = mpsc::channel::<ProcessingRequest>(4);
        let mut stream = client
            .process(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        let headers_msg = || ProcessingRequest {
            request: Some(processing_request::Request::RequestHeaders(HttpHeaders::default())),
            ..Default::default()
        };

        tx.send(headers_msg()).await.unwrap();
        assert!(
            stream.message().await.unwrap().is_some(),
            "the stream must process its first message",
        );

        // Hold the stream open well past the per-request timeout the HTTP
        // surfaces enforce — no deadline may fire on the gRPC stream.
        sleep(http_timeout * 4).await;

        tx.send(headers_msg()).await.unwrap();
        assert!(
            stream.message().await.unwrap().is_some(),
            "the stream must still process messages after outliving the HTTP request timeout",
        );
    }
}
