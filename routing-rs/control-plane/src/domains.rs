//! Domains: create/upsert, the self-service declare + verify (ownership proof)
//! lifecycle, the background verification poll, and delete.

use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use opentelemetry::KeyValue;
use serde::Deserialize;
use serde_json::json;
use tokio::time::interval;
use tracing::{info, warn};

use router_core::audit::{AuditCtx, ACTOR_SYSTEM_VERIFY_POLL};
use router_core::normalize::normalize_host;
use router_core::store::{BoxError, ChallengeStore, DomainUpsert, RoutingStore};
use router_core::verify::{challenge_name, token_matches};
use store_postgres::LeaderLease;

use crate::app::{internal, App, METRICS};

/// Stable advisory-lock id electing the single verification-poll leader (RFC C4).
const VERIFY_POLL_LOCK_KEY: i64 = 9_204_001;

// --------------------------------------------------------------------------- //
// Domains
// --------------------------------------------------------------------------- //
#[derive(Deserialize)]
pub(crate) struct DomainBody {
    domain: String,
    workspace_id: String,
    #[serde(default)]
    wildcard: bool,
}

pub(crate) async fn upsert_domain(
    State(s): State<App>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<DomainBody>,
) -> impl IntoResponse {
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
        .upsert_domain(
            &DomainUpsert {
                domain: &domain,
                workspace_id: &body.workspace_id,
                wildcard: body.wildcard,
                verified: VERIFIED,
            },
            &actx,
        )
        .await
    {
        return internal(e);
    }
    s.invalidate(&domain).await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "upsert_domain")]);
    info!(domain = %domain, tenant = ?body.workspace_id, wildcard = body.wildcard, verified = VERIFIED, "domain upserted");
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
pub(crate) struct DeclareBody {
    workspace_id: String,
    domain: String,
}

/// Declare a domain under a tenant (RFC C3 / N2a): quota-gated, creates a pending
/// row, and returns the DNS record the tenant must publish to prove ownership.
/// Idempotent: re-declaring a pending domain returns the SAME challenge.
pub(crate) async fn declare_domain(
    State(s): State<App>,
    Extension(actx): Extension<AuditCtx>,
    Json(body): Json<DeclareBody>,
) -> Response {
    let domain = normalize_host(&body.domain);
    // Must be a real (sub)domain — a bare label cannot be ownership-proven.
    if domain.is_empty() || !domain.contains('.') {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_domain", "domain": domain })))
            .into_response();
    }

    match s.store.get_domain(&domain, false).await {
        // Owned (verified or pending) by another workspace — never grant a second claim.
        Ok(Some(rec)) if rec.workspace_id != body.workspace_id => {
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
            let plan = match s.store.get_workspace(&body.workspace_id).await {
                Ok(Some(cfg)) => cfg.plan,
                Ok(None) => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({ "error": "unknown_workspace", "workspace_id": body.workspace_id })),
                    )
                        .into_response();
                }
                Err(e) => return internal(e),
            };
            let used = match s.store.count_domains_for_workspace(&body.workspace_id).await {
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
            match s.store.create_pending_domain(&domain, &body.workspace_id, &actx).await {
                Ok(true) => {}
                Ok(false) => {
                    match s.store.get_domain(&domain, false).await {
                        // Another workspace claimed it first — never a second claim.
                        Ok(Some(rec)) if rec.workspace_id != body.workspace_id => {
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

    let ch = match s.store.mint_or_get_challenge(&domain, &body.workspace_id, s.challenge_ttl).await {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    METRICS.mutations.add(1, &[KeyValue::new("op", "declare_domain")]);
    info!(domain = %domain, tenant = ?body.workspace_id, "domain declared (pending)");
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
/// `actx` attributes the resulting `domain.verify` audit event — the caller's
/// token on the endpoint path, the reserved system actor on the poll path.
async fn verify_one(s: &App, domain: &str, actx: &AuditCtx) -> VerifyOutcome {
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
    if let Err(e) = s.store.set_domain_verified(domain, true, actx).await {
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
pub(crate) async fn verify_domain(
    State(s): State<App>,
    Path(domain): Path<String>,
    Extension(actx): Extension<AuditCtx>,
) -> Response {
    let domain = normalize_host(&domain);
    match verify_one(&s, &domain, &actx).await {
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
pub(crate) async fn verification_poll(app: App, interval_secs: u64) {
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
        // The poll is a system mutation, not an HTTP caller — its `domain.verify`
        // events carry the reserved system actor (admin-action-audit).
        let poll_actx = AuditCtx::system(ACTOR_SYSTEM_VERIFY_POLL);
        for domain in pending {
            if matches!(verify_one(&app, &domain, &poll_actx).await, VerifyOutcome::Verified) {
                info!(domain = %domain, "verification poll: domain converged");
            }
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct DeleteDomainQuery {
    /// Which row of the `(domain, is_wildcard)` pair to drop. Defaults to the
    /// exact (non-wildcard) row, which is what self-service domains always are.
    #[serde(default)]
    wildcard: bool,
}

pub(crate) async fn delete_domain(
    State(s): State<App>,
    Path(domain): Path<String>,
    Query(q): Query<DeleteDomainQuery>,
    Extension(actx): Extension<AuditCtx>,
) -> impl IntoResponse {
    let domain = normalize_host(&domain);
    if let Err(e) = s.store.delete_domain(&domain, q.wildcard, &actx).await {
        return internal(e);
    }
    s.invalidate(&domain).await;
    METRICS.mutations.add(1, &[KeyValue::new("op", "delete_domain")]);
    info!(domain = %domain, "domain deleted");
    (StatusCode::OK, Json(json!({ "result": "ok", "domain": domain }))).into_response()
}
