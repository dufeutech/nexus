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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::future::Cache;
use rustls::crypto::ring;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::sleep;
use tonic::transport::Server;
use tracing::{error, info, warn};

use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_server::ExternalProcessorServer;

// The Profile shape lives in the shared core crate; the store is reached through
// the core `ProfileStore` port, implemented by the Postgres adapter.
use identity_core::telemetry;
use identity_core::store::ProfileStore;
use store_postgres::PgProfileStore;

// identity-contract-signing: the ES256 signer adapter (mints the signed
// x-identity-contract token) and the dedicated JWKS listener that publishes the
// public keys for boxes to verify against.
mod jwks;
mod signer;
// automate-signing-key-rotation: managed key custody + automated rotation. The
// `KeyProvider` port (keyprovider) isolates where signing keys come from; the OpenBao
// Transit adapter (transit, Mode B local signing) is the production source; the rotation
// manager (rotation) drives cut-over + generates the published JWKS + enforces the
// two-key overlap window. The manual `SIGNING_KEY_PATH` PEM stays a break-glass fallback.
mod keyprovider;
mod rotation;
mod transit;

// The identity-plane resolver, split by surface: shared state + resolution
// (`state`), request extraction (`extract`), the enrichment core (`enrich`), the
// ext_proc gRPC surface + watchers (`serve`), the localhost profile API (`api`), and
// the startup wiring (`bootstrap`). `main()` only wires them together.
mod state;
mod extract;
mod enrich;
mod authz;
mod serve;
mod api;
mod bootstrap;

use crate::state::{parse_aal_levels, AppState, DEFAULT_AAL_LEVELS, METRICS};
use crate::serve::{
    shutdown_signal, watch_platform_services, watch_store, watch_workspace_plans, Sidecar,
};
use crate::bootstrap::{build_api_key_auth, build_policy_pdp, build_signing};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // automate-signing-key-rotation: the OpenBao Transit client (vaultrs) uses rustls
    // WITHOUT a bundled crypto provider (so we don't pull aws-lc-sys / cmake), so install
    // the in-tree `ring` provider as the process default before any TLS is built. `Err`
    // means one was already installed — benign, so it is ignored.
    drop(ring::default_provider().install_default());
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
    let pdp = build_policy_pdp();

    let store: Arc<dyn ProfileStore> = loop {
        match PgProfileStore::connect(&pg_url).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                warn!(error = %e, "waiting for Postgres");
                sleep(Duration::from_secs(2)).await;
            }
        }
    };

    // Platform-service registry (normalized-principal): when `PLATFORM_PG_RO_URL` is
    // set, spawn the resident-snapshot watcher and hand its live receiver to the state.
    // Unset ⇒ platform-service authentication is OFF (only the human path resolves).
    // The watcher connects+retries on its own (non-blocking), so a slow/absent platform
    // DB never blocks the human path at startup; the map starts EMPTY (fail closed)
    // until the first load lands. `platform.services` lives alongside the identity store
    // in the lab, so the URL defaults to the identity DB.
    let platform = env::var("PLATFORM_PG_RO_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .map(|url| {
            let poll = Duration::from_secs(
                env::var("PLATFORM_POLL_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30),
            );
            let (tx, rx) = watch::channel(Arc::new(HashMap::new()));
            tokio::spawn(watch_platform_services(url, poll, tx));
            info!("platform-service authentication ENABLED (resident registry)");
            rx
        });
    if platform.is_none() {
        info!("PLATFORM_PG_RO_URL unset -> platform-service authentication OFF (human path only)");
    }

    // Workspace plan-tier projection (workspace-plan-tier): when `ROUTING_PG_RO_URL` is set
    // (the same routing RO role the membership-sync worker reads with), spawn the resident
    // plan-snapshot watcher and hand its live receiver to the state. Unset ⇒ no plan is ever
    // emitted (`x-workspace-plan`/the `plan` claim omitted, fail-soft — never a 503). The
    // watcher connects+retries on its own (non-blocking), so a slow/absent routing DB never
    // blocks enrichment at startup; the map starts EMPTY (every workspace omits its plan)
    // until the first load lands.
    let plans = env::var("ROUTING_PG_RO_URL")
        .ok()
        .filter(|u| !u.is_empty())
        .map(|url| {
            let poll = Duration::from_secs(
                env::var("WORKSPACE_PLAN_POLL_SECONDS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30),
            );
            let (tx, rx) = watch::channel(Arc::new(HashMap::new()));
            tokio::spawn(watch_workspace_plans(url, poll, tx));
            info!("workspace plan-tier projection ENABLED (resident snapshot)");
            rx
        });
    if plans.is_none() {
        info!("ROUTING_PG_RO_URL unset -> workspace plan-tier projection OFF (plan omitted)");
    }

    // customer-api-keys: api-key authentication is ON only when BOTH the read-only key
    // store URL and the HMAC pepper are configured. The store defaults to identitydb (the
    // api_keys table lives alongside identity.profiles), which the profile store already
    // gated on being up — so a single connect attempt here normally succeeds. A missing
    // pepper (can't verify secrets) or a failed connect disables the path (fail closed to
    // the human/service paths), never runs it half-configured.
    let api_keys = build_api_key_auth().await;
    if api_keys.is_none() {
        info!("customer-api-key authentication OFF (APIKEY_PG_RO_URL/APIKEY_HMAC_PEPPER unset)");
    }

    // identity-contract-signing + automate-signing-key-rotation: resolve the signer +
    // JWKS publication once (OpenBao Transit managed rotation, else break-glass PEM, else
    // off). Fails fast only on a genuine misconfiguration of the break-glass PEM itself.
    let signing = build_signing().await?;

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
        // The swap-able active signer resolved above (Transit-managed or break-glass
        // PEM); `None` when signing is deliberately off (anonymous still served).
        signer: signing.signer,
        platform,
        plans,
        api_keys,
        pdp,
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

    // Dedicated public JWKS listener (identity-contract-signing) — SEPARATE from the
    // internal :9200 profile API so publishing the public keys never exposes
    // `/profile/{sub}`. Subscribed to the shutdown fan-out BEFORE `tx` moves into the
    // signal task below; only started when a JWKS document is configured.
    if let Some(doc) = signing.jwks {
        let jwks_addr = env::var("JWKS_LISTEN").unwrap_or_else(|_| "0.0.0.0:9210".to_owned());
        let mut r_jwks = tx.subscribe();
        let app = jwks::router(doc);
        drop(tokio::spawn(async move {
            match TcpListener::bind(&jwks_addr).await {
                Ok(listener) => {
                    info!(addr = %jwks_addr, path = jwks::JWKS_PATH, "JWKS listener up");
                    let _ = axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            let _ = r_jwks.changed().await;
                        })
                        .await;
                }
                Err(e) => error!(error = %e, addr = %jwks_addr, "failed to bind JWKS listener"),
            }
        }));
    }

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
mod test_support;
