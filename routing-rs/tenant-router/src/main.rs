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

mod state;
mod extract;
mod strip;
mod response;
mod serve;
mod api;
#[cfg(test)]
mod test_support;

use std::collections::HashSet;
use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::env::var;

use moka::future::Cache;
use tokio::net::TcpListener;
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, warn};
use tonic::transport::Server;

use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_server::ExternalProcessorServer;

use router_core::telemetry;
use router_core::cache::SharedCache;
use router_core::store::{Invalidations, RoutingStore};
use cache_redis::RedisCache;
use invalidations_nats::NatsInvalidations;
use store_postgres::{PgInvalidations, PgRoutingStore};

use crate::state::{refresh_point, AppState, METRICS};
use crate::serve::{env, shutdown_signal, watch_invalidations, Router};

/// Build the Tokio runtime, sizing the worker pool from `TOKIO_WORKER_THREADS`
/// (hot-path-rps-optimization). Unset keeps Tokio's default of one worker per logical core,
/// which oversubscribes CPU when this plane is co-located with the edge and the identity
/// plane; set it to the container's core allotment so the runtimes stop fighting for cores.
fn build_runtime() -> io::Result<Runtime> {
    let mut builder = Builder::new_multi_thread();
    builder.enable_all();
    if let Some(threads) = var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
    {
        builder.worker_threads(threads);
    }
    builder.build()
}

fn main() -> Result<(), Box<dyn Error>> {
    build_runtime()?.block_on(run())
}

async fn run() -> Result<(), Box<dyn Error>> {
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
    // Negative-authorization cache for the `ask` gate. TTL is short so a host that
    // becomes verified is re-evaluated promptly; capacity bounds the memory a
    // flood of distinct unknown SNIs can pin (LRU eviction past the bound).
    let neg_ttl: u64 = env("AUTHORIZE_NEG_TTL", "30").parse().unwrap_or(30);
    let neg_capacity: u64 = env("AUTHORIZE_NEG_CAPACITY", "100000").parse().unwrap_or(100_000);

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
        neg: Cache::builder()
            .max_capacity(neg_capacity)
            .time_to_live(Duration::from_secs(neg_ttl))
            .build(),
        store,
        l2_ttl,
        // Keep-warm refresh point derived from the L1 lifetime (D2): refresh a
        // resident, actively-read entry once it is halfway to expiry, leaving ample
        // margin to complete the refresh off the request path before hard expiry.
        refresh_after: refresh_point(Duration::from_secs(ttl)),
        refreshing: Arc::new(Mutex::new(HashSet::new())),
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

    // Invalidation feed watcher. Transport is selected by config: NATS_URL set
    // routes invalidations over NATS (cross-region delivery, track D); absent it
    // stays on the default pg_notify feed. Both sit behind the `Invalidations`
    // port, so this is the only line that changes and rollback is unsetting the
    // env var. NATS is core (fire-and-forget) — a dropped signal self-heals within
    // ROUTING_CACHE_TTL, exactly as the pg_notify path already tolerates.
    {
        let st = state.clone();
        let invs: Arc<dyn Invalidations> = match var("NATS_URL") {
            Ok(url) if !url.is_empty() => {
                info!("invalidation transport: NATS (cross-region)");
                Arc::new(NatsInvalidations::new(url))
            }
            _ => {
                info!("invalidation transport: pg_notify (single-server, default)");
                Arc::new(PgInvalidations::new(pg_url.clone()))
            }
        };
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
