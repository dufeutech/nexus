//! Control Plane (Rust) — the routing-plane admin surface (RFC C16, §3.13).
//!
//! It manages domains (add, remove, verify ownership) and tenants (create, set
//! plan/features/target pool) in the authoritative routing store, and on EVERY
//! mutation publishes the affected normalized domain key(s) on the invalidation
//! feed so resolvers converge promptly (RFC C16). It is NOT on the request hot
//! path and is reachable on an administrative boundary only.
//!
//! Domain ownership is explicit: a domain is created `verified = false` and only
//! a verify call makes it resolve on protected routes (RFC C16 / §3.13) — an
//! unverified domain never routes.

use std::collections::{BTreeMap, BTreeSet};
use std::env::var;
use std::error::Error;
use std::fmt;
#[cfg(not(unix))]
use std::future::pending;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::StatusCode;
use headers::authorization::Bearer;
use headers::{Authorization, HeaderMapExt};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use tower_http::timeout::TimeoutLayer;
// first-party-telemetry: a per-request span at INFO so admin operations root their
// own trace (DEBUG default would be filtered out and never exported).
use tower_http::trace::{DefaultMakeSpan, TraceLayer};
use tracing::Level;
use opentelemetry::metrics::Counter;
use opentelemetry::{global, KeyValue};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};

use dns_resolver::DnsOwnershipProof;
use router_core::telemetry;
use router_core::auth::RouteAuth;
use router_core::domain::{PoolSet, WorkspaceConfig};
use router_core::normalize::normalize_host;
use router_core::plan::{DomainLimit, PlanLimits};
use router_core::store::{
    BoxError, ChallengeStore, Membership, MembershipStore, OwnershipStore, RoutingStore,
    MEMBER_TYPES,
};
use router_core::verify::{challenge_name, ct_eq, token_matches, OwnershipProof};
use store_postgres::{LeaderLease, PgRoutingStore};

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): every control mutation is counted through the
// OTel meter (push path via router_core::telemetry). The counter name DROPS the
// Prometheus `_total` suffix — Prometheus's OTLP receiver re-appends it, so the
// stored series keeps its name (control_mutations_total) and dashboards keep
// working. The `op` label carries the mutation kind, exactly as before.
// --------------------------------------------------------------------------- //
struct Metrics {
    mutations: Counter<u64>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("control-plane");
    Metrics {
        mutations: meter.u64_counter("control_mutations").build(),
    }
});

/// Stable advisory-lock id electing the single verification-poll leader (RFC C4).
const VERIFY_POLL_LOCK_KEY: i64 = 9_204_001;

/// Total per-request timeout for both HTTP surfaces (http-request-resilience):
/// operator-tunable via `HTTP_REQUEST_TIMEOUT_SECS` with a finite 30s default —
/// never unbounded (and well above the 5s DB statement cap).
fn request_timeout() -> Duration {
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
fn resilient<S>(router: Router<S>, timeout: Duration) -> Router<S>
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
struct App {
    store: Arc<PgRoutingStore>,
    /// Data-driven plan → domain-limit table for the declare quota gate (RFC C5).
    limits: Arc<PlanLimits>,
    /// Data-driven allow-list of backend pools (RFC C15). Loaded from config so a
    /// new pool is a config + edge-cluster change, never a recompile.
    pools: Arc<PoolSet>,
    /// Ownership-proof resolver for TXT verification (RFC C4).
    verifier: Arc<dyn OwnershipProof>,
    /// Challenge token lifetime, seconds (RFC C4).
    challenge_ttl: i64,
    /// How long a domain may stay pending before it expires and frees quota,
    /// seconds (RFC C3). `0` disables expiry.
    pending_ttl: i64,
    /// Shared admin bearer token required on every data endpoint. `None` ONLY
    /// when auth is explicitly disabled at startup (`CONTROL_AUTH_DISABLED=true`);
    /// the server otherwise refuses to start without a token, so it is never
    /// silently open. The control plane is a trusted-broker admin surface, so a
    /// single shared secret authenticates the caller; `tenant_id` is then trusted.
    auth_token: Option<Arc<str>>,
}

/// Uniform 500 for an unexpected store/adapter error. The underlying error is
/// LOGGED (with full detail for operators) but NEVER returned to the client — a
/// raw `e.to_string()` can leak connection strings, SQL, or internal topology.
fn internal<E: fmt::Display>(e: E) -> Response {
    error!(error = %e, "control-plane error");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "internal_error" }))).into_response()
}

/// Load the plan → limit table from configuration (RFC C5). `ROUTING_PLAN_LIMITS`
/// is a JSON object mapping plan name to an integer cap, or `null` for unbounded
/// (e.g. `{"free":1,"pro":25,"enterprise":null}`). Absent/invalid config falls
/// back to the most conservative table so the gate never fails open.
fn load_plan_limits() -> PlanLimits {
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
fn load_pools() -> PoolSet {
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
    async fn invalidate(&self, domain: &str) {
        if let Err(e) = self.store.notify_invalidation(domain).await {
            warn!(error = %e, domain, "notify failed (cache TTL will self-heal)");
        }
    }
}

fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
}

/// Admin-token gate (RFC C16 admin boundary): every DATA endpoint requires
/// `Authorization: Bearer <CONTROL_AUTH_TOKEN>`. The token is compared in
/// constant time. `/healthz` is intentionally NOT behind this (liveness). When
/// `auth_token` is `None` the operator explicitly
/// disabled auth at startup, so requests pass through.
async fn require_auth(State(s): State<App>, req: Request, next: Next) -> Response {
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
// Tenants — DEPRECATED alias of Workspaces (nexus-owned-workspace-tenancy, 2.2).
// The `/tenants*` routes + this account-less `tenant_id` body are frozen for the
// running broker/e2e during cut-over; new callers use `/workspaces*` (which also
// carries `account_id` + membership). Removed in a later archive step. The handler
// maps `tenant_id` → the store's `workspace_id` (the same identifier).
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
struct TenantBody {
    tenant_id: String,
    #[serde(default = "default_plan")]
    plan: String,
    target_pool: String,
    #[serde(default)]
    features: Vec<String>,
}

fn default_plan() -> String {
    "free".to_owned()
}

async fn upsert_tenant(State(s): State<App>, Json(body): Json<TenantBody>) -> impl IntoResponse {
    // Validate against the data-driven allow-list (RFC C15): reject an unknown pool
    // rather than invent a destination. The error lists the configured pools so a
    // typo/missing-config is obvious without a redeploy.
    let Some(pool) = s.pools.parse(&body.target_pool) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid target_pool",
                "value": body.target_pool,
                "allowed": s.pools.names(),
            })),
        )
            .into_response();
    };
    // Migration seam: the store/core now speak `workspace_id`, but this HTTP body
    // is still the legacy `tenant_id` field (the `/tenants` API rename is task 2.2).
    // The value is the same workspace identifier — map it across here.
    let cfg = WorkspaceConfig {
        workspace_id: body.tenant_id.clone(),
        plan: body.plan,
        target_pool: pool,
        features: body.features,
        updated_at: None,
    };
    if let Err(e) = s.store.upsert_workspace(&cfg).await {
        return internal(e);
    }
    // A workspace change affects all of its domains — invalidate each precisely so
    // both the L1 (per-edge) and L2 (shared) tiers converge by domain key.
    match s.store.domains_for_workspace(&body.tenant_id).await {
        Ok(domains) => {
            for d in &domains {
                s.invalidate(d).await;
            }
            METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_tenant")]);
            info!(tenant = ?body.tenant_id, invalidated = domains.len(), "tenant upserted");
        }
        Err(e) => warn!(error = %e, "domains_for_tenant failed; relying on TTL"),
    }
    (StatusCode::OK, Json(json!({ "result": "ok", "tenant_id": body.tenant_id }))).into_response()
}

async fn get_tenant(State(s): State<App>, Path(id): Path<String>) -> impl IntoResponse {
    match s.store.get_workspace(&id).await {
        Ok(Some(cfg)) => (StatusCode::OK, Json(serde_json::to_value(cfg).unwrap())).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found", "tenant_id": id })))
            .into_response(),
        Err(e) => internal(e),
    }
}

// --------------------------------------------------------------------------- //
// Domains
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
struct DomainBody {
    domain: String,
    tenant_id: String,
    #[serde(default)]
    wildcard: bool,
}

async fn upsert_domain(State(s): State<App>, Json(body): Json<DomainBody>) -> impl IntoResponse {
    // Normalize at the boundary so the stored key matches the resolver's key.
    let domain = normalize_host(&body.domain);
    // A domain is ALWAYS created unverified here: routing-affecting verification
    // is granted only by the DNS ownership-proof path (declare → verify, RFC C4).
    // A client-supplied `verified:true` is NOT honored — accepting it would let
    // any caller make an unproven domain route, defeating the proof system. To
    // mark a domain verified, publish the TXT proof and call /verify.
    const VERIFIED: bool = false;
    if let Err(e) = s
        .store
        .upsert_domain(&domain, &body.tenant_id, body.wildcard, VERIFIED)
        .await
    {
        return internal(e);
    }
    s.invalidate(&domain).await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_domain")]);
    info!(domain = %domain, tenant = ?body.tenant_id, wildcard = body.wildcard, verified = VERIFIED, "domain upserted");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "domain": domain, "verified": VERIFIED })),
    )
        .into_response()
}

// --------------------------------------------------------------------------- //
// Self-service lifecycle: declare (quota) + verify (ownership proof) — RFC C3/C4.
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
struct DeclareBody {
    tenant_id: String,
    domain: String,
}

/// Declare a domain under a tenant (RFC C3 / N2a): quota-gated, creates a pending
/// row, and returns the DNS record the tenant must publish to prove ownership.
/// Idempotent: re-declaring a pending domain returns the SAME challenge.
async fn declare_domain(State(s): State<App>, Json(body): Json<DeclareBody>) -> Response {
    let domain = normalize_host(&body.domain);
    // Must be a real (sub)domain — a bare label cannot be ownership-proven.
    if domain.is_empty() || !domain.contains('.') {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_domain", "domain": domain })))
            .into_response();
    }

    match s.store.get_domain(&domain, false).await {
        // Owned (verified or pending) by another workspace — never grant a second claim.
        Ok(Some(rec)) if rec.workspace_id != body.tenant_id => {
            return (StatusCode::CONFLICT, Json(json!({ "error": "domain_taken", "domain": domain })))
                .into_response();
        }
        // Already verified for this tenant — nothing to challenge.
        Ok(Some(rec)) if rec.verified => {
            return (StatusCode::OK, Json(json!({ "result": "ok", "domain": domain, "verified": true })))
                .into_response();
        }
        // Pending for this tenant — fall through to the idempotent challenge.
        Ok(Some(_)) => {}
        // New domain — enforce the plan quota before creating it.
        Ok(None) => {
            // Sweep abandoned pending declares first so the used count excludes
            // expired-pending at declare time (RFC C3 boundary). Best-effort: a
            // sweep error only risks counting a stale slot until the next poll.
            if s.pending_ttl > 0
                && let Err(e) = s.store.expire_pending_domains(s.pending_ttl).await
            {
                warn!(error = %e, "declare: pending sweep failed (count may be stale)");
            }
            let plan = match s.store.get_workspace(&body.tenant_id).await {
                Ok(Some(cfg)) => cfg.plan,
                Ok(None) => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "unknown_tenant", "tenant_id": body.tenant_id })),
                    )
                        .into_response();
                }
                Err(e) => return internal(e),
            };
            let used = match s.store.count_domains_for_workspace(&body.tenant_id).await {
                Ok(n) => n,
                Err(e) => return internal(e),
            };
            if let Err(q) = s.limits.check(&plan, used) {
                METRICS.mutations.add(1, &[KeyValue::new("op", "declare_quota_exceeded")]);
                // 402: a billing/plan limit ("upgrade to proceed"), not an auth
                // failure — clients MUST NOT treat it as a credential problem.
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(json!({ "error": "quota_exceeded", "plan": q.plan, "limit": q.limit, "used": q.used })),
                )
                    .into_response();
            }
            // Create the PENDING (unverified) row atomically. A pending domain
            // never routes, so NO invalidation is published (RFC C6: only
            // outcome-changing mutations announce on the feed). `create_pending_domain`
            // is INSERT ... ON CONFLICT DO NOTHING, so it never reassigns ownership:
            // if a concurrent declare for the same domain won the race between our
            // ownership check above and here, our insert is a no-op and we resolve
            // the conflict by re-reading the current owner (closes the declare TOCTOU).
            match s.store.create_pending_domain(&domain, &body.tenant_id).await {
                Ok(true) => {}
                Ok(false) => {
                    match s.store.get_domain(&domain, false).await {
                        // Another workspace claimed it first — never a second claim.
                        Ok(Some(rec)) if rec.workspace_id != body.tenant_id => {
                            return (
                                StatusCode::CONFLICT,
                                Json(json!({ "error": "domain_taken", "domain": domain })),
                            )
                                .into_response();
                        }
                        // Ours now (idempotent concurrent re-declare) — fall through
                        // to the shared challenge mint below.
                        Ok(_) => {}
                        Err(e) => return internal(e),
                    }
                }
                Err(e) => return internal(e),
            }
        }
        Err(e) => return internal(e),
    }

    let ch = match s.store.mint_or_get_challenge(&domain, &body.tenant_id, s.challenge_ttl).await {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    METRICS.mutations.add(1, &[KeyValue::new("op", "declare_domain")]);
    info!(domain = %domain, tenant = ?body.tenant_id, "domain declared (pending)");
    (
        StatusCode::OK,
        Json(json!({
            "result": "ok",
            "domain": domain,
            "verified": false,
            "dns_record": { "name": challenge_name(&domain), "type": "TXT", "value": ch.token },
        })),
    )
        .into_response()
}

/// The result of attempting to verify one domain — shared by the endpoint and the
/// background poll so they apply the same fail-closed rule.
enum VerifyOutcome {
    Verified,
    AlreadyVerified,
    NoChallenge,
    Expired,
    ProofNotFound,
    Transient(BoxError),
    Error(BoxError),
}

/// Verify a single domain by ownership proof (RFC C4 / N2b): resolve the
/// challenge TXT, match the live token, then (atomically for observers) set
/// verified + announce on the one invalidation feed + retire the challenge.
async fn verify_one(s: &App, domain: &str) -> VerifyOutcome {
    let ch = match s.store.get_challenge(domain).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            // No live challenge: either already verified (challenge retired) or
            // never declared.
            return match s.store.get_domain(domain, false).await {
                Ok(Some(rec)) if rec.verified => VerifyOutcome::AlreadyVerified,
                Ok(_) => VerifyOutcome::NoChallenge,
                Err(e) => VerifyOutcome::Error(e),
            };
        }
        Err(e) => return VerifyOutcome::Error(e),
    };
    if ch.expired {
        return VerifyOutcome::Expired; // re-issuable by re-declaring (RFC C4).
    }
    let records = match s.verifier.txt_records(&challenge_name(domain)).await {
        Ok(r) => r,
        Err(e) => return VerifyOutcome::Transient(e), // stays pending; never a disproof.
    };
    if !token_matches(&records, &ch.token) {
        return VerifyOutcome::ProofNotFound;
    }
    if let Err(e) = s.store.set_domain_verified(domain, true).await {
        return VerifyOutcome::Error(e);
    }
    // Now routable → MUST announce on the invalidation feed (RFC C6).
    s.invalidate(domain).await;
    if let Err(e) = s.store.delete_challenge(domain).await {
        // Non-fatal: the domain is verified; a stale challenge cascades away with
        // the domain and cannot re-grant anything.
        warn!(error = %e, domain, "challenge retire failed (non-fatal)");
    }
    METRICS.mutations.add(1, &[KeyValue::new("op", "verify_domain")]);
    info!(domain, "domain verified via ownership proof");
    VerifyOutcome::Verified
}

/// Tenant-triggered "check now" (RFC C4): verify by ownership proof.
async fn verify_domain(State(s): State<App>, Path(domain): Path<String>) -> Response {
    let domain = normalize_host(&domain);
    match verify_one(&s, &domain).await {
        VerifyOutcome::Verified => {
            (StatusCode::OK, Json(json!({ "result": "ok", "domain": domain, "verified": true })))
                .into_response()
        }
        VerifyOutcome::AlreadyVerified => (
            StatusCode::OK,
            Json(json!({ "result": "ok", "domain": domain, "verified": true, "already": true })),
        )
            .into_response(),
        VerifyOutcome::NoChallenge => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no_challenge", "domain": domain })),
        )
            .into_response(),
        VerifyOutcome::Expired => (
            StatusCode::GONE,
            Json(json!({ "error": "challenge_expired", "domain": domain })),
        )
            .into_response(),
        VerifyOutcome::ProofNotFound => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({ "error": "proof_not_found", "domain": domain })),
        )
            .into_response(),
        VerifyOutcome::Transient(e) => {
            warn!(error = %e, domain = %domain, "verify: transient resolution failure");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "resolution_failed", "domain": domain })),
            )
                .into_response()
        }
        VerifyOutcome::Error(e) => internal(e),
    }
}

/// Periodic verification of pending domains (RFC C4): converges domains whose
/// owners have published the proof without a manual "check now". Best-effort —
/// failures leave the domain pending for the next pass.
async fn verification_poll(app: App, interval_secs: u64) {
    let mut tick = interval(Duration::from_secs(interval_secs));
    let mut lease: Option<LeaderLease> = None;
    loop {
        tick.tick().await;

        // Singleton across replicas (RFC C4): only the advisory-lock holder polls,
        // so 2+ control-plane instances don't all resolve DNS for every pending
        // domain. At one replica this wins the lock instantly — zero cost. A lost
        // lease (dead connection) is re-acquired here, giving automatic failover.
        let mut have_leader = false;
        if let Some(l) = lease.as_mut() {
            have_leader = l.alive().await;
        }
        if !have_leader {
            lease = None;
            match app.store.try_acquire_leader(VERIFY_POLL_LOCK_KEY).await {
                Ok(Some(l)) => {
                    info!("acquired verification-poll leadership");
                    lease = Some(l);
                    have_leader = true;
                }
                Ok(None) => {} // another instance leads this round
                Err(e) => warn!(error = %e, "verification poll: leader acquire failed"),
            }
        }
        if !have_leader {
            continue;
        }

        // Expire abandoned declares first: frees quota and removes them from this
        // pass's work set (RFC C3). No invalidation — pending never routed.
        if app.pending_ttl > 0 {
            match app.store.expire_pending_domains(app.pending_ttl).await {
                Ok(expired) if !expired.is_empty() => {
                    METRICS
                        .mutations
                        .add(expired.len() as u64, &[KeyValue::new("op", "expire_pending")]);
                    info!(count = expired.len(), "verification poll: expired pending domains");
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "verification poll: pending sweep failed"),
            }
        }
        let pending = match app.store.pending_domains().await {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "verification poll: listing pending domains failed");
                continue;
            }
        };
        for domain in pending {
            if matches!(verify_one(&app, &domain).await, VerifyOutcome::Verified) {
                info!(domain = %domain, "verification poll: domain converged");
            }
        }
    }
}

#[derive(Deserialize)]
struct DeleteDomainQuery {
    /// Which row of the `(domain, is_wildcard)` pair to drop. Defaults to the
    /// exact (non-wildcard) row, which is what self-service domains always are.
    #[serde(default)]
    wildcard: bool,
}

async fn delete_domain(
    State(s): State<App>,
    Path(domain): Path<String>,
    Query(q): Query<DeleteDomainQuery>,
) -> impl IntoResponse {
    let domain = normalize_host(&domain);
    if let Err(e) = s.store.delete_domain(&domain, q.wildcard).await {
        return internal(e);
    }
    s.invalidate(&domain).await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "delete_domain")]);
    info!(domain = %domain, "domain deleted");
    (StatusCode::OK, Json(json!({ "result": "ok", "domain": domain }))).into_response()
}

// --------------------------------------------------------------------------- //
// Per-route auth policy (RFC N4): CRUD over a tenant's path-prefix rules. A
// change re-protects live traffic, so every mutation invalidates ALL the tenant's
// domains (same precise per-domain invalidation as a tenant-config change) so the
// routers reload the policy promptly over the one invalidation feed (RFC C16).
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
struct AuthRouteBody {
    path_prefix: String,
    auth_required: bool,
    /// Phase-2 requirements (N4): optional; any of them present demands
    /// `auth_required = true` (validated at write time — see the handler).
    #[serde(default)]
    requires_role: Option<String>,
    #[serde(default)]
    requires_entitlement: Option<String>,
    #[serde(default)]
    min_aal: Option<u8>,
    /// identity-existence-hiding: mark a protected route as account-scoped
    /// (reachable without a workspace membership, e.g. `/me`). Default `false`
    /// (workspace-scoped, membership-gated) — the fail-closed existence-hiding
    /// posture. Only meaningful when `auth_required = true`.
    #[serde(default)]
    account_scoped: bool,
}

#[derive(Deserialize)]
struct AuthRouteDelete {
    path_prefix: String,
}

impl App {
    /// Invalidate every domain a tenant owns — the precise convergence signal for
    /// a change that affects all of the tenant's routes (policy or config).
    async fn invalidate_tenant(&self, tenant_id: &str, op: &'static str) {
        match self.store.domains_for_workspace(tenant_id).await {
            Ok(domains) => {
                for d in &domains {
                    self.invalidate(d).await;
                }
                info!(tenant = ?tenant_id, op, invalidated = domains.len(), "tenant invalidated");
            }
            Err(e) => warn!(error = %e, "domains_for_tenant failed; relying on TTL"),
        }
    }

    /// Reject a path prefix that is not rooted at `/` — the policy matches request
    /// paths, which always begin with `/`, so a non-rooted prefix can never match.
    fn valid_prefix(prefix: &str) -> bool {
        prefix.starts_with('/')
    }

    /// A rule combining a phase-2 requirement with `auth_required = false` is
    /// contradictory (requirements imply authentication): the gate would leak
    /// authorization policy as 403s to callers who were never asked to log in.
    /// Rejected at write time so such a rule never enters the store.
    const fn inconsistent_requirements(auth: &RouteAuth) -> bool {
        auth.has_requirements() && !auth.required
    }
}

async fn upsert_auth_route(
    State(s): State<App>,
    Path(tenant_id): Path<String>,
    Json(body): Json<AuthRouteBody>,
) -> Response {
    if !App::valid_prefix(&body.path_prefix) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_prefix", "path_prefix": body.path_prefix, "hint": "must start with '/'" })),
        )
            .into_response();
    }
    let auth = RouteAuth {
        required: body.auth_required,
        requires_role: body.requires_role.clone(),
        requires_entitlement: body.requires_entitlement.clone(),
        min_aal: body.min_aal,
        account_scoped: body.account_scoped,
    };
    if App::inconsistent_requirements(&auth) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "requirements_need_auth",
                "path_prefix": body.path_prefix,
                "hint": "a rule with requires_role/requires_entitlement/min_aal must set auth_required = true",
            })),
        )
            .into_response();
    }
    // The FK would reject an unknown workspace as a 500; check first for a clean 404.
    match s.store.get_workspace(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown_tenant", "tenant_id": tenant_id })))
                .into_response();
        }
        Err(e) => return internal(e),
    }
    if let Err(e) = s.store.upsert_auth_route(&tenant_id, &body.path_prefix, &auth).await {
        return internal(e);
    }
    s.invalidate_tenant(&tenant_id, "upsert_auth_route").await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_auth_route")]);
    (
        StatusCode::OK,
        Json(json!({
            "result": "ok",
            "tenant_id": tenant_id,
            "path_prefix": body.path_prefix,
            "auth_required": auth.required,
            "requires_role": auth.requires_role,
            "requires_entitlement": auth.requires_entitlement,
            "min_aal": auth.min_aal,
        })),
    )
        .into_response()
}

async fn delete_auth_route(
    State(s): State<App>,
    Path(tenant_id): Path<String>,
    Json(body): Json<AuthRouteDelete>,
) -> Response {
    if let Err(e) = s.store.delete_auth_route(&tenant_id, &body.path_prefix).await {
        return internal(e);
    }
    s.invalidate_tenant(&tenant_id, "delete_auth_route").await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "delete_auth_route")]);
    (StatusCode::OK, Json(json!({ "result": "ok", "tenant_id": tenant_id, "path_prefix": body.path_prefix })))
        .into_response()
}

async fn list_auth_routes(State(s): State<App>, Path(tenant_id): Path<String>) -> Response {
    match s.store.get_auth_policy(&tenant_id).await {
        Ok(policy) => {
            let routes: Vec<_> = policy
                .rules()
                .iter()
                .map(|r| {
                    json!({
                        "path_prefix": r.prefix,
                        "auth_required": r.auth.required,
                        "requires_role": r.auth.requires_role,
                        "requires_entitlement": r.auth.requires_entitlement,
                        "min_aal": r.auth.min_aal,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "tenant_id": tenant_id, "routes": routes }))).into_response()
        }
        Err(e) => internal(e),
    }
}

// --------------------------------------------------------------------------- //
// Accounts (ownership container) — nexus-owned-workspace-tenancy 2.1
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
struct AccountBody {
    account_id: String,
    /// The user this account is provisioned for — becomes its `owner` member.
    owner_sub: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    payer_ref: Option<String>,
}

/// Provision an account and its owner member (2.1). Idempotent: on repeat (e.g. a
/// re-run of first-signup provisioning) the account is left as-is and the owner
/// membership is re-asserted, so it is safe to call unconditionally on signup.
/// Trusted-broker model: the authenticated caller supplies the ids and owner sub.
async fn provision_account(State(s): State<App>, Json(body): Json<AccountBody>) -> Response {
    let created = match s
        .store
        .create_account(&body.account_id, &body.name, body.payer_ref.as_deref())
        .await
    {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    if let Err(e) = s.store.add_account_member(&body.account_id, &body.owner_sub, "owner").await {
        return internal(e);
    }
    METRICS.mutations.add(1, &[KeyValue::new("op", "provision_account")]);
    info!(account = %body.account_id, owner = %body.owner_sub, created, "account provisioned");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "account_id": body.account_id, "created": created })),
    )
        .into_response()
}

async fn get_account(State(s): State<App>, Path(id): Path<String>) -> Response {
    let account = match s.store.get_account(&id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "not found", "account_id": id })))
                .into_response();
        }
        Err(e) => return internal(e),
    };
    let members = match s.store.account_members(&id).await {
        Ok(m) => m,
        Err(e) => return internal(e),
    };
    (StatusCode::OK, Json(json!({ "account": account, "members": members }))).into_response()
}

// --------------------------------------------------------------------------- //
// Workspaces (the stable-ID routing pivot) — nexus-owned-workspace-tenancy 2.2
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
struct WorkspaceBody {
    workspace_id: String,
    /// Owning account. Supplied at create; OMITTED on a config-only update leaves
    /// ownership unchanged. An ownership CHANGE goes through `/transfer`, never here.
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default = "default_plan")]
    plan: String,
    target_pool: String,
    #[serde(default)]
    features: Vec<String>,
}

async fn upsert_workspace(State(s): State<App>, Json(body): Json<WorkspaceBody>) -> Response {
    // Same pool allow-list validation as the legacy alias (RFC C15, fail-closed).
    let Some(pool) = s.pools.parse(&body.target_pool) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid target_pool",
                "value": body.target_pool,
                "allowed": s.pools.names(),
            })),
        )
            .into_response();
    };
    // If an account was supplied, it MUST exist — check first so the FK surfaces as
    // a clean 404 instead of a raw 500.
    if let Some(account_id) = &body.account_id {
        match s.store.get_account(account_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({ "error": "unknown_account", "account_id": account_id })),
                )
                    .into_response();
            }
            Err(e) => return internal(e),
        }
    }
    let cfg = WorkspaceConfig {
        workspace_id: body.workspace_id.clone(),
        plan: body.plan,
        target_pool: pool,
        features: body.features,
        updated_at: None,
    };
    if let Err(e) = s.store.upsert_workspace(&cfg).await {
        return internal(e);
    }
    // Assign ownership at create time (no staff reset — a new workspace has none).
    if let Some(account_id) = &body.account_id {
        match s.store.set_workspace_account(&body.workspace_id, account_id).await {
            Ok(true) => {}
            // We just upserted the row, so a no-match is unexpected — log, don't fail.
            Ok(false) => warn!(workspace = %body.workspace_id, "ownership set matched no row"),
            Err(e) => return internal(e),
        }
    }
    // A workspace change affects all of its domains — invalidate each precisely.
    match s.store.domains_for_workspace(&body.workspace_id).await {
        Ok(domains) => {
            for d in &domains {
                s.invalidate(d).await;
            }
            METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_workspace")]);
            info!(workspace = %body.workspace_id, invalidated = domains.len(), "workspace upserted");
        }
        Err(e) => warn!(error = %e, "domains_for_workspace failed; relying on TTL"),
    }
    (StatusCode::OK, Json(json!({ "result": "ok", "workspace_id": body.workspace_id }))).into_response()
}

async fn get_workspace(State(s): State<App>, Path(id): Path<String>) -> Response {
    match s.store.get_workspace(&id).await {
        Ok(Some(cfg)) => (StatusCode::OK, Json(serde_json::to_value(cfg).unwrap())).into_response(),
        Ok(None) => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": "not found", "workspace_id": id })))
                .into_response()
        }
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
struct TransferBody {
    /// The new owning account. Must already exist.
    account_id: String,
}

/// Transfer a workspace to a different account (2.4). Repoints ownership and resets
/// staff atomically (customers, domains, and data ride through unchanged).
async fn transfer_workspace(
    State(s): State<App>,
    Path(workspace_id): Path<String>,
    Json(body): Json<TransferBody>,
) -> Response {
    // Target account must exist — clean 404 rather than a raw FK 500.
    match s.store.get_account(&body.account_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown_account", "account_id": body.account_id })),
            )
                .into_response();
        }
        Err(e) => return internal(e),
    }
    let staff_removed = match s.store.transfer_workspace(&workspace_id, &body.account_id).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown_workspace", "workspace_id": workspace_id })),
            )
                .into_response();
        }
        Err(e) => return internal(e),
    };
    METRICS.mutations.add(1, &[KeyValue::new("op", "transfer_workspace")]);
    info!(workspace = %workspace_id, new_account = %body.account_id, staff_removed, "workspace transferred");
    (
        StatusCode::OK,
        Json(json!({
            "result": "ok",
            "workspace_id": workspace_id,
            "account_id": body.account_id,
            "staff_removed": staff_removed,
        })),
    )
        .into_response()
}

// --------------------------------------------------------------------------- //
// Memberships (the live authz source of record) — nexus-owned-workspace-tenancy 2.3
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
struct MembershipBody {
    user_sub: String,
    /// `"staff"` or `"customer"` — validated against `MEMBER_TYPES`.
    member_type: String,
    #[serde(default = "default_member_role")]
    role: String,
    #[serde(default = "default_status")]
    status: String,
}

fn default_member_role() -> String {
    "member".to_owned()
}

fn default_status() -> String {
    "active".to_owned()
}

/// Grant or update a workspace membership (2.3). Writes the source-of-record row;
/// the identity plane picks the change up via the change feed to resolve the acting
/// workspace scope (the feed wiring lands with the identity-plane stage).
async fn upsert_membership(
    State(s): State<App>,
    Path(workspace_id): Path<String>,
    Json(body): Json<MembershipBody>,
) -> Response {
    if !MEMBER_TYPES.contains(&body.member_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_member_type", "value": body.member_type, "allowed": MEMBER_TYPES })),
        )
            .into_response();
    }
    // Unknown workspace → clean 404 (the FK would otherwise surface as a 500).
    match s.store.get_workspace(&workspace_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown_workspace", "workspace_id": workspace_id })),
            )
                .into_response();
        }
        Err(e) => return internal(e),
    }
    let m = Membership {
        user_sub: body.user_sub,
        workspace_id: workspace_id.clone(),
        member_type: body.member_type,
        role: body.role,
        status: body.status,
    };
    if let Err(e) = s.store.upsert_membership(&m).await {
        return internal(e);
    }
    // Best-effort signal to the identity plane's membership-sync worker. A failed
    // notify must NOT fail the committed write — the reconcile backstop heals it.
    if let Err(e) = s.store.notify_membership_change(&m.user_sub).await {
        warn!(error = %e, user = %m.user_sub, "membership-change notify failed; backstop will heal");
    }
    METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_membership")]);
    info!(workspace = %workspace_id, user = %m.user_sub, member_type = %m.member_type, "membership granted");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "workspace_id": workspace_id, "user_sub": m.user_sub })),
    )
        .into_response()
}

async fn delete_membership(
    State(s): State<App>,
    Path((workspace_id, user_sub)): Path<(String, String)>,
) -> Response {
    if let Err(e) = s.store.delete_membership(&user_sub, &workspace_id).await {
        return internal(e);
    }
    // Best-effort signal (see upsert_membership) — the consumer re-reads the
    // subject's remaining memberships, so a revoke propagates without the workspace.
    if let Err(e) = s.store.notify_membership_change(&user_sub).await {
        warn!(error = %e, user = %user_sub, "membership-change notify failed; backstop will heal");
    }
    METRICS.mutations.add(1, &[KeyValue::new("op", "delete_membership")]);
    (StatusCode::OK, Json(json!({ "result": "ok", "workspace_id": workspace_id, "user_sub": user_sub })))
        .into_response()
}

async fn list_memberships(State(s): State<App>, Path(workspace_id): Path<String>) -> Response {
    match s.store.memberships_for_workspace(&workspace_id).await {
        Ok(memberships) => {
            (StatusCode::OK, Json(json!({ "workspace_id": workspace_id, "memberships": memberships })))
                .into_response()
        }
        Err(e) => internal(e),
    }
}

// --------------------------------------------------------------------------- //
async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
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
    tokio::select! { () = ctrl_c => {}, () = term => {} }
    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Shared telemetry (first-party-telemetry): honors RUST_LOG/LOG_LEVEL/LOG_FORMAT
    // exactly as before, plus OTLP export when the endpoint env is set. Held for the
    // process lifetime to flush on shutdown.
    let _telemetry = telemetry::init("control-plane");
    // Metrics now push via the OTel meter (first-party-telemetry); the old Prometheus
    // /metrics scrape endpoint is retired — the collector's metrics pipeline forwards
    // to the store, so there is no per-box scrape job.

    let pg_url = env(
        "ROUTING_PG_URL",
        "postgres://postgres:postgres@postgres:5432/routing",
    );

    // Connect + own the idempotent schema bootstrap (the router only reads).
    let store = loop {
        match PgRoutingStore::connect(&pg_url).await {
            Ok(s) => match s.init_schema().await {
                Ok(()) => break Arc::new(s),
                Err(e) => warn!(error = %e, "schema init failed; retrying"),
            },
            Err(e) => warn!(error = %e, "waiting for Postgres"),
        }
        sleep(Duration::from_secs(2)).await;
    };
    info!("routing schema ready");

    let challenge_ttl: i64 = env("ROUTING_CHALLENGE_TTL", "86400").parse().unwrap_or(86400);
    // Default 7 days; a domain unverified past this expires and frees quota.
    let pending_ttl: i64 = env("ROUTING_PENDING_TTL", "604800").parse().unwrap_or(604800);

    // Admin-token gate, fail-closed: refuse to start without an explicit choice.
    // Either supply CONTROL_AUTH_TOKEN (non-empty) or opt out with
    // CONTROL_AUTH_DISABLED=true (trusted-network/dev only). This makes "ran with
    // no auth" an explicit decision rather than a silent default.
    let auth_disabled = matches!(
        env("CONTROL_AUTH_DISABLED", "").trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    );
    let token = env("CONTROL_AUTH_TOKEN", "");
    let auth_token = match (auth_disabled, token.trim().is_empty()) {
        (true, _) => {
            warn!("CONTROL_AUTH_DISABLED=true — control plane admin endpoints are UNAUTHENTICATED");
            None
        }
        (false, false) => Some(Arc::from(token.as_str())),
        (false, true) => {
            error!("CONTROL_AUTH_TOKEN is unset; refusing to start open. Set it, or set CONTROL_AUTH_DISABLED=true to run without auth.");
            return Err("missing CONTROL_AUTH_TOKEN".into());
        }
    };

    let app = App {
        store,
        limits: Arc::new(load_plan_limits()),
        pools: Arc::new(load_pools()),
        verifier: Arc::new(DnsOwnershipProof::public()),
        challenge_ttl,
        pending_ttl,
        auth_token,
    };

    // Background verification poll for pending domains (RFC C4). Disabled when the
    // interval is 0 (verification then happens only on tenant-triggered check).
    let poll_secs: u64 = env("ROUTING_VERIFY_POLL", "300").parse().unwrap_or(300);
    if poll_secs > 0 {
        let poll_app = app.clone();
        tokio::spawn(async move { verification_poll(poll_app, poll_secs).await });
        info!(interval_s = poll_secs, "verification poll enabled");
    }

    // Data endpoints — all behind the admin-token gate (route_layer so an unknown
    // path 404s without first demanding a token).
    let data = Router::new()
        // Accounts + Workspaces + Memberships (nexus-owned-workspace-tenancy).
        .route("/accounts", post(provision_account))
        .route("/accounts/{id}", get(get_account))
        .route("/workspaces", post(upsert_workspace))
        .route("/workspaces/{id}", get(get_workspace))
        .route("/workspaces/{id}/transfer", post(transfer_workspace))
        .route(
            "/workspaces/{id}/members",
            get(list_memberships).put(upsert_membership),
        )
        .route("/workspaces/{id}/members/{sub}", delete(delete_membership))
        .route(
            "/workspaces/{id}/auth-routes",
            get(list_auth_routes).put(upsert_auth_route).delete(delete_auth_route),
        )
        // Domains (workspace-keyed via the same handlers).
        .route("/domains", post(upsert_domain))
        .route("/domains/declare", post(declare_domain))
        .route("/domains/{domain}/verify", post(verify_domain))
        .route("/domains/{domain}", delete(delete_domain))
        // DEPRECATED `/tenants*` aliases (account-less) — frozen for the broker/e2e
        // during cut-over; new callers use `/workspaces*` above.
        .route("/tenants", post(upsert_tenant))
        .route("/tenants/{id}", get(get_tenant))
        .route(
            "/tenants/{id}/auth-routes",
            get(list_auth_routes)
                .put(upsert_auth_route)
                .delete(delete_auth_route),
        )
        .route_layer(middleware::from_fn_with_state(app.clone(), require_auth));

    // Admin API (:9400) — the data endpoints behind the token gate, plus /healthz
    // for liveness. Metrics are no longer scraped here (or anywhere): they push via
    // the OTel meter (first-party-telemetry), so no /metrics endpoint exists and the
    // NetworkPolicy keeps the admin port broker-only with no scrape hole to punch.
    let req_timeout = request_timeout();

    let admin = resilient(
        data
            // Liveness stays open (no token), kept on the admin port so existing
            // tooling/healthchecks that target :9400 keep working.
            .route("/healthz", get(healthz)),
        req_timeout,
    )
    .with_state(app.clone());

    // Ops surface (:9401) — /healthz for kubelet probes. Carries nothing sensitive
    // and no mutation, so the NetworkPolicy can open it to the node (for probes)
    // without exposing the admin API. (No body cap needed on GET-only ops, so only
    // the timeout layer applies.)
    let ops = Router::new()
        .route("/healthz", get(healthz))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, req_timeout))
        .with_state(app);

    let admin_listener = TcpListener::bind("0.0.0.0:9400").await?;
    let ops_listener = TcpListener::bind("0.0.0.0:9401").await?;
    info!(
        "control plane: admin on :9400 (/accounts, /workspaces[+/members,/transfer,/auth-routes], \
         /domains, /domains/declare, /tenants[deprecated], /healthz); \
         ops on :9401 (/healthz)"
    );
    // Serve both concurrently; either erroring (or a shutdown signal) brings the
    // process down so the kubelet restarts it cleanly.
    let admin_srv = axum::serve(admin_listener, admin).with_graceful_shutdown(shutdown_signal());
    let ops_srv = axum::serve(ops_listener, ops).with_graceful_shutdown(shutdown_signal());
    if let Err(e) = tokio::try_join!(admin_srv, ops_srv) {
        error!(error = %e, "server error");
    }
    info!("stopped");
    Ok(())
}

#[cfg(test)]
mod auth_route_validation_tests {
    use super::{App, RouteAuth};

    /// Spec "Inconsistent rule is rejected at write time": any requirement field
    /// with `auth_required = false` is the rejected combination; the same fields
    /// with `auth_required = true`, or no fields at all, are accepted.
    /// (Persistence + NOTIFY of an accepted rule is covered by the store
    /// integration round-trip and the shared `invalidate_tenant` path.)
    #[test]
    fn requirement_with_anonymous_route_is_inconsistent() {
        let anonymous_gated = RouteAuth {
            required: false,
            requires_role: Some("admin".into()),
            ..RouteAuth::PASS_THROUGH
        };
        assert!(App::inconsistent_requirements(&anonymous_gated));

        let authed_gated = RouteAuth {
            required: true,
            min_aal: Some(2),
            ..RouteAuth::PASS_THROUGH
        };
        assert!(!App::inconsistent_requirements(&authed_gated));

        let phase1_public = RouteAuth::PASS_THROUGH;
        assert!(!App::inconsistent_requirements(&phase1_public));
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
