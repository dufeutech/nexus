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

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use metrics::counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info, warn};

use router_core::domain::{Pool, TenantConfig};
use router_core::normalize::normalize_host;
use router_core::store::RoutingStore;
use store_postgres::PgRoutingStore;

#[derive(Clone)]
struct App {
    store: Arc<PgRoutingStore>,
    metrics: PrometheusHandle,
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
    std::env::var(key).unwrap_or_else(|_| default.to_string())
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
    "free".to_string()
}

async fn upsert_tenant(State(s): State<App>, Json(body): Json<TenantBody>) -> impl IntoResponse {
    let Some(pool) = Pool::parse(&body.target_pool) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid target_pool", "value": body.target_pool })),
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
        error!(error = %e, "upsert_tenant failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
            .into_response();
    }
    // A tenant change affects all of its domains — invalidate each precisely so
    // both the L1 (per-edge) and L2 (shared) tiers converge by domain key.
    match s.store.domains_for_tenant(&body.tenant_id).await {
        Ok(domains) => {
            for d in &domains {
                s.invalidate(d).await;
            }
            counter!("control_mutations_total", "op" => "upsert_tenant").increment(1);
            info!(tenant = %body.tenant_id, invalidated = domains.len(), "tenant upserted");
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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
            .into_response(),
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
    #[serde(default)]
    verified: bool,
}

async fn upsert_domain(State(s): State<App>, Json(body): Json<DomainBody>) -> impl IntoResponse {
    // Normalize at the boundary so the stored key matches the resolver's key.
    let domain = normalize_host(&body.domain);
    if let Err(e) = s
        .store
        .upsert_domain(&domain, &body.tenant_id, body.wildcard, body.verified)
        .await
    {
        error!(error = %e, "upsert_domain failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
            .into_response();
    }
    s.invalidate(&domain).await;
    counter!("control_mutations_total", "op" => "upsert_domain").increment(1);
    info!(domain = %domain, tenant = %body.tenant_id, wildcard = body.wildcard, verified = body.verified, "domain upserted");
    (
        StatusCode::OK,
        Json(json!({ "result": "ok", "domain": domain, "verified": body.verified })),
    )
        .into_response()
}

async fn verify_domain(State(s): State<App>, Path(domain): Path<String>) -> impl IntoResponse {
    let domain = normalize_host(&domain);
    if let Err(e) = s.store.set_domain_verified(&domain, true).await {
        error!(error = %e, "verify failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
            .into_response();
    }
    s.invalidate(&domain).await;
    counter!("control_mutations_total", "op" => "verify_domain").increment(1);
    info!(domain = %domain, "domain verified");
    (StatusCode::OK, Json(json!({ "result": "ok", "domain": domain, "verified": true }))).into_response()
}

async fn delete_domain(State(s): State<App>, Path(domain): Path<String>) -> impl IntoResponse {
    let domain = normalize_host(&domain);
    if let Err(e) = s.store.delete_domain(&domain).await {
        error!(error = %e, "delete failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": e.to_string() })))
            .into_response();
    }
    s.invalidate(&domain).await;
    counter!("control_mutations_total", "op" => "delete_domain").increment(1);
    info!(domain = %domain, "domain deleted");
    (StatusCode::OK, Json(json!({ "result": "ok", "domain": domain }))).into_response()
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
        let _ = tokio::signal::ctrl_c().await;
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
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    };
    info!("routing schema ready");

    let app = App { store, metrics };
    let router = Router::new()
        .route("/tenants", post(upsert_tenant))
        .route("/tenants/{id}", get(get_tenant))
        .route("/domains", post(upsert_domain))
        .route("/domains/{domain}/verify", post(verify_domain))
        .route("/domains/{domain}", axum::routing::delete(delete_domain))
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(healthz))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9400").await?;
    info!("control plane on :9400 (/tenants, /domains, /metrics, /healthz)");
    if let Err(e) = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        error!(error = %e, "server error");
    }
    info!("stopped");
    Ok(())
}
