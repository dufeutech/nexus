//! Control Plane (Rust) — the routing-plane admin surface (RFC C16, §3.13).
//!
//! It manages domains (add, remove, verify ownership) and accounts/workspaces
//! (create with server-minted ids, reconfigure) in the authoritative routing
//! store, and on EVERY
//! mutation publishes the affected normalized domain key(s) on the invalidation
//! feed so resolvers converge promptly (RFC C16). It is NOT on the request hot
//! path and is reachable on an administrative boundary only.
//!
//! Domain ownership is explicit: a domain is created `verified = false` and only
//! a verify call makes it resolve on protected routes (RFC C16 / §3.13) — an
//! unverified domain never routes.

mod app;
mod auth_routes;
mod domains;
mod tenancy;

use std::error::Error;
#[cfg(not(unix))]
use std::future::pending;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::Router;
use tower_http::timeout::TimeoutLayer;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::time::sleep;
use tracing::{error, info, warn};

use dns_resolver::DnsOwnershipProof;
use router_core::telemetry;
use router_core::store::{FanoutPublisher, InvalidationPublisher};
use invalidations_nats::NatsPublisher;
use store_postgres::PgRoutingStore;

use crate::app::{env, load_plan_limits, load_pools, request_timeout, require_auth, resilient, App};
use crate::auth_routes::{delete_auth_route, list_auth_routes, upsert_auth_route};
use crate::domains::{declare_domain, delete_domain, upsert_domain, verification_poll, verify_domain};
use crate::tenancy::{
    create_workspace, delete_membership, get_account, get_workspace, list_memberships,
    provision_account, transfer_workspace, update_workspace, upsert_membership,
};

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

    // Invalidation transport (RFC C16). Always publish via pg_notify (the store);
    // when NATS_URL is set, fan out to NATS too so cross-region subscribers get
    // the signal without in-region pg_notify subscribers losing theirs. A NATS
    // connect failure degrades to pg_notify-only (best-effort — the TTL backstop
    // heals a lost cross-region signal), never failing startup.
    let publisher: Arc<dyn InvalidationPublisher> = {
        let pg: Arc<dyn InvalidationPublisher> = Arc::clone(&store) as Arc<dyn InvalidationPublisher>;
        match env("NATS_URL", "") {
            url if !url.is_empty() => match NatsPublisher::connect(&url).await {
                Ok(nats) => {
                    info!("invalidation publisher: pg_notify + NATS (cross-region fan-out)");
                    Arc::new(FanoutPublisher::new(vec![pg, Arc::new(nats)]))
                }
                Err(e) => {
                    warn!(error = %e, "NATS publisher connect failed; publishing pg_notify only");
                    pg
                }
            },
            _ => {
                info!("invalidation publisher: pg_notify (single-server, default)");
                pg
            }
        }
    };

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
        publisher,
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
        .route("/workspaces", post(create_workspace))
        .route("/workspaces/{id}", get(get_workspace).put(update_workspace))
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
         /domains, /domains/declare, /healthz); \
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
