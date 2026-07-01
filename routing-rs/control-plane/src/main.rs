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
use metrics::counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::{interval, sleep};
use tracing::{error, info, warn};

use dns_resolver::DnsOwnershipProof;
use router_core::domain::{PoolSet, TenantConfig};
use router_core::normalize::normalize_host;
use router_core::plan::{DomainLimit, PlanLimits};
use router_core::store::{BoxError, ChallengeStore, RoutingStore};
use router_core::verify::{challenge_name, ct_eq, token_matches, OwnershipProof};
use store_postgres::{LeaderLease, PgRoutingStore};

/// Stable advisory-lock id electing the single verification-poll leader (RFC C4).
const VERIFY_POLL_LOCK_KEY: i64 = 9_204_001;

#[derive(Clone)]
struct App {
    store: Arc<PgRoutingStore>,
    metrics: PrometheusHandle,
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
/// constant time. `/healthz` and `/metrics` are intentionally NOT behind this
/// (liveness + scrape). When `auth_token` is `None` the operator explicitly
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
            counter!("control_mutations_total", "op" => "unauthorized").increment(1);
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
// Tenants
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
    let cfg = TenantConfig {
        tenant_id: body.tenant_id.clone(),
        plan: body.plan,
        target_pool: pool,
        features: body.features,
        updated_at: None,
    };
    if let Err(e) = s.store.upsert_tenant(&cfg).await {
        return internal(e);
    }
    // A tenant change affects all of its domains — invalidate each precisely so
    // both the L1 (per-edge) and L2 (shared) tiers converge by domain key.
    match s.store.domains_for_tenant(&body.tenant_id).await {
        Ok(domains) => {
            for d in &domains {
                s.invalidate(d).await;
            }
            counter!("control_mutations_total", "op" => "upsert_tenant").increment(1);
            info!(tenant = ?body.tenant_id, invalidated = domains.len(), "tenant upserted");
        }
        Err(e) => warn!(error = %e, "domains_for_tenant failed; relying on TTL"),
    }
    (StatusCode::OK, Json(json!({ "result": "ok", "tenant_id": body.tenant_id }))).into_response()
}

async fn get_tenant(State(s): State<App>, Path(id): Path<String>) -> impl IntoResponse {
    match s.store.get_tenant(&id).await {
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
    counter!("control_mutations_total", "op" => "upsert_domain").increment(1);
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
        // Owned (verified or pending) by another tenant — never grant a second claim.
        Ok(Some(rec)) if rec.tenant_id != body.tenant_id => {
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
            if s.pending_ttl > 0 {
                if let Err(e) = s.store.expire_pending_domains(s.pending_ttl).await {
                    warn!(error = %e, "declare: pending sweep failed (count may be stale)");
                }
            }
            let plan = match s.store.get_tenant(&body.tenant_id).await {
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
            let used = match s.store.count_domains_for_tenant(&body.tenant_id).await {
                Ok(n) => n,
                Err(e) => return internal(e),
            };
            if let Err(q) = s.limits.check(&plan, used) {
                counter!("control_mutations_total", "op" => "declare_quota_exceeded").increment(1);
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
                        // Another tenant claimed it first — never a second claim.
                        Ok(Some(rec)) if rec.tenant_id != body.tenant_id => {
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
    counter!("control_mutations_total", "op" => "declare_domain").increment(1);
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
    counter!("control_mutations_total", "op" => "verify_domain").increment(1);
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
                    counter!("control_mutations_total", "op" => "expire_pending")
                        .increment(expired.len() as u64);
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
    counter!("control_mutations_total", "op" => "delete_domain").increment(1);
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
}

#[derive(Deserialize)]
struct AuthRouteDelete {
    path_prefix: String,
}

impl App {
    /// Invalidate every domain a tenant owns — the precise convergence signal for
    /// a change that affects all of the tenant's routes (policy or config).
    async fn invalidate_tenant(&self, tenant_id: &str, op: &'static str) {
        match self.store.domains_for_tenant(tenant_id).await {
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
    // The FK would reject an unknown tenant as a 500; check first for a clean 404.
    match s.store.get_tenant(&tenant_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown_tenant", "tenant_id": tenant_id })))
                .into_response();
        }
        Err(e) => return internal(e),
    }
    if let Err(e) = s.store.upsert_auth_route(&tenant_id, &body.path_prefix, body.auth_required).await {
        return internal(e);
    }
    s.invalidate_tenant(&tenant_id, "upsert_auth_route").await;
    counter!("control_mutations_total", "op" => "upsert_auth_route").increment(1);
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "tenant_id": tenant_id, "path_prefix": body.path_prefix, "auth_required": body.auth_required })),
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
    counter!("control_mutations_total", "op" => "delete_auth_route").increment(1);
    (StatusCode::OK, Json(json!({ "result": "ok", "tenant_id": tenant_id, "path_prefix": body.path_prefix })))
        .into_response()
}

async fn list_auth_routes(State(s): State<App>, Path(tenant_id): Path<String>) -> Response {
    match s.store.get_auth_policy(&tenant_id).await {
        Ok(policy) => {
            let routes: Vec<_> = policy
                .rules()
                .iter()
                .map(|r| json!({ "path_prefix": r.prefix, "auth_required": r.auth.required }))
                .collect();
            (StatusCode::OK, Json(json!({ "tenant_id": tenant_id, "routes": routes }))).into_response()
        }
        Err(e) => internal(e),
    }
}

// --------------------------------------------------------------------------- //
async fn metrics_handler(State(s): State<App>) -> impl IntoResponse {
    s.metrics.render()
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
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
    init_tracing();
    let metrics = PrometheusBuilder::new().install_recorder()?;

    let pg_url = env(
        "ROUTING_PG_URL",
        "postgres://postgres:postgres@postgres:5432/zitadel",
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
        metrics,
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
        .route("/tenants", post(upsert_tenant))
        .route("/tenants/{id}", get(get_tenant))
        .route("/domains", post(upsert_domain))
        .route("/domains/declare", post(declare_domain))
        .route("/domains/{domain}/verify", post(verify_domain))
        .route("/domains/{domain}", delete(delete_domain))
        .route(
            "/tenants/{id}/auth-routes",
            get(list_auth_routes)
                .put(upsert_auth_route)
                .delete(delete_auth_route),
        )
        .route_layer(middleware::from_fn_with_state(app.clone(), require_auth));

    // Admin API (:9400) — the data endpoints behind the token gate, plus /healthz
    // for liveness. /metrics is deliberately NOT served here: it would share the
    // port with the admin API, and an L4 NetworkPolicy cannot allow a scrape peer
    // to reach /metrics WITHOUT also granting it the admin endpoints — punching a
    // hole in the broker-only guarantee (RFC C16) for every metrics peer. /metrics
    // moves to the separate ops port below so the policy can gate the two
    // independently (admin = broker-only; ops = scrapers + kubelet).
    // Per-request timeout for both servers (returns 408): bounds a slow/stalled
    // client so it cannot hold a connection/task indefinitely. Operator-tunable via
    // HTTP_REQUEST_TIMEOUT_SECS; default 30s (well above the 5s DB statement cap).
    let req_timeout = Duration::from_secs(
        var("HTTP_REQUEST_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
    );

    let admin = data
        // Liveness stays open (no token), kept on the admin port so existing
        // tooling/healthchecks that target :9400 keep working.
        .route("/healthz", get(healthz))
        // These are small JSON admin bodies; cap the request body so a malformed
        // or hostile caller can't force an unbounded buffer (defense-in-depth).
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, req_timeout))
        .with_state(app.clone());

    // Ops surface (:9401) — /metrics for scrapers and /healthz for kubelet probes.
    // Carries nothing sensitive and no mutation, so the NetworkPolicy can open it
    // to Prometheus (and the node, for probes) without exposing the admin API.
    let ops = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, req_timeout))
        .with_state(app);

    let admin_listener = TcpListener::bind("0.0.0.0:9400").await?;
    let ops_listener = TcpListener::bind("0.0.0.0:9401").await?;
    info!(
        "control plane: admin on :9400 (/tenants, /tenants/:id/auth-routes, /domains, /domains/declare, /healthz); \
         ops on :9401 (/metrics, /healthz)"
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
