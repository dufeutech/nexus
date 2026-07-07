//! membership-sync — projects routing-plane membership changes into the identity
//! `Profile.memberships` the sidecar resolves against.
//!
//! The routing control plane owns the membership source of record (a SEPARATE
//! database in production) and emits a best-effort `pg_notify` on every
//! upsert/delete. This worker:
//!   1. LISTENs on that channel and, per signal, RE-READS the subject's
//!      source-of-record memberships and read-merge-writes them into the subject's
//!      Profile (the identity change feed then refreshes the sidecar within
//!      seconds). It never trusts the signal payload as authoritative — the payload
//!      is only the affected `user_sub`.
//!   2. Runs a periodic BACKSTOP pass that re-derives every subject's memberships
//!      from the source of record, healing a missed NOTIFY and backfilling on first
//!      run (no separate ETL).
//!
//! Identity stays the SOLE writer of profiles; the only cross-plane coupling is the
//! read-only routing connection this worker holds (least privilege). See the
//! `membership-profile-propagation` change design.

use std::env::var;
use std::error::Error;
#[cfg(not(unix))]
use std::future::pending;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use opentelemetry::global;
use opentelemetry::metrics::{Counter, Gauge};
use sqlx::postgres::PgListener;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, info_span, warn};
// first-party-telemetry: each background pass / signal roots its own trace.
use tracing::Instrument as _;

use identity_core::telemetry;
use identity_core::projection::{backstop_pass, sync_subject};
use identity_core::store::{BoxError, ProfileStore};
use identity_core::SourceMembershipReader;
use store_postgres::{PgProfileStore, PgSourceMembershipReader};

/// The routing-plane NOTIFY channel carrying membership changes. This is a
/// cross-plane wire contract shared with `routing-rs/store-postgres`
/// (`MEMBERSHIP_CHANNEL`) — like the `x-workspace-*` header names, the string is
/// duplicated across the two independently-deployed planes by necessity; keep them
/// in lockstep.
const MEMBERSHIP_CHANNEL: &str = "routing_membership_changes";

fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
}
fn env_num<T: FromStr>(key: &str, default: T) -> T {
    var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// A minimal `/healthz` surface so the kubelet has a real liveness/readiness probe
/// target. This worker's actual job is a Postgres `LISTEN` + a periodic backstop — it
/// binds no request surface of its own, so a `tcpSocket` probe against a
/// never-bound port would CrashLoop a functionally healthy worker. `/healthz`
/// returning 200 means the process reached the serving stage and its async runtime is
/// responsive (a hung runtime stops answering -> liveness fails -> restart). Metrics
/// are PUSHED via OTLP (first-party-telemetry), never scraped here.
async fn serve_health(port: u16, mut shutdown: watch::Receiver<bool>) {
    let app = Router::new().route("/healthz", get(|| async { (StatusCode::OK, "ok") }));
    let addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => listener,
        Err(e) => {
            error!(error = %e, addr, "health surface bind failed");
            return;
        }
    };
    info!(addr, "health surface on /healthz");
    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
        })
        .await
    {
        error!(error = %e, "health surface error");
    }
}

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): emitted through the OTel meter (push path via
// identity_core::telemetry). Counter names DROP the Prometheus `_total` suffix —
// Prometheus's OTLP receiver re-appends it, so the stored series keep their names
// (membership_sync_subject_syncs_total, …) and dashboards keep working. The gauge
// keeps its exact name.
// --------------------------------------------------------------------------- //
struct Metrics {
    subject_syncs: Counter<u64>,
    backstop_passes: Counter<u64>,
    signals: Counter<u64>,
    errors: Counter<u64>,
    last_backstop_subjects: Gauge<u64>,
}

static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("membership-sync");
    Metrics {
        subject_syncs: meter.u64_counter("membership_sync_subject_syncs").build(),
        backstop_passes: meter.u64_counter("membership_sync_backstop_passes").build(),
        signals: meter.u64_counter("membership_sync_signals").build(),
        errors: meter.u64_counter("membership_sync_errors").build(),
        last_backstop_subjects: meter.u64_gauge("membership_sync_last_backstop_subjects").build(),
    }
});

/// Run one backstop pass (the convergence logic lives in `identity_core`) and emit
/// metrics/logs around it.
#[tracing::instrument(skip_all, name = "membership.backstop", fields(otel.kind = "internal"))]
async fn run_backstop(
    reader: &dyn SourceMembershipReader,
    store: &dyn ProfileStore,
) -> Result<(), BoxError> {
    let stats = backstop_pass(reader, store).await?;
    METRICS.subject_syncs.add(stats.written as u64, &[]);
    METRICS.backstop_passes.add(1, &[]);
    METRICS.last_backstop_subjects.record(stats.subjects as u64, &[]);
    info!(subjects = stats.subjects, written = stats.written, "backstop pass");
    Ok(())
}

/// LISTEN loop: drain membership-change signals, syncing the named subject. Returns
/// only on a listener error (the caller re-establishes the listener).
async fn listen_once(
    listener: &mut PgListener,
    reader: &dyn SourceMembershipReader,
    store: &dyn ProfileStore,
) -> Result<(), BoxError> {
    loop {
        let notification = listener.recv().await?;
        let sub = notification.payload().to_owned();
        METRICS.signals.add(1, &[]);
        // Root a trace per signal so its sync logs correlate (sub omitted from the
        // span — a user id stays out of telemetry attributes per the hygiene rule).
        let span = info_span!("membership.signal", otel.kind = "internal");
        match sync_subject(reader, store, &sub).instrument(span).await {
            Ok(true) => METRICS.subject_syncs.add(1, &[]),
            Ok(false) => {}
            Err(e) => {
                METRICS.errors.add(1, &[]);
                warn!(error = %e, %sub, "signal subject sync failed; backstop will heal");
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Shared telemetry (first-party-telemetry): honors RUST_LOG/LOG_LEVEL/LOG_FORMAT
    // as before, plus OTLP export when the endpoint env is set. Each backstop/signal
    // pass roots its own trace; held for the process lifetime.
    let _telemetry = telemetry::init("membership-sync");
    // Metrics now push via the OTel meter (first-party-telemetry); the old
    // Prometheus exporter listener is retired — the collector's metrics pipeline
    // forwards to the store, no per-box scrape job.

    let profile_url = env("PROFILE_PG_URL", "postgres://postgres:postgres@postgres:5432/identitydb");
    // Read-only routing connection (least privilege: SELECT on routing.memberships +
    // LISTEN). A SEPARATE database from the identity store in production.
    let routing_url = env("ROUTING_PG_RO_URL", "postgres://postgres:postgres@postgres:5432/routing");
    let backstop_interval = Duration::from_secs(env_num("MEMBERSHIP_BACKSTOP_INTERVAL", 600_u64));
    // Health surface port — the kubelet's liveness/readiness probe target (default
    // 9000, matching the chart's containerPort/Service). The worker has no request
    // surface of its own, so this is purely a probe endpoint.
    let health_port: u16 = env_num("HEALTH_PORT", 9000_u16);

    // Connect (with retry) to both planes. This worker is a profile writer, so it
    // owns idempotent identity-schema setup before the first backfill.
    let store: Arc<PgProfileStore> = loop {
        match PgProfileStore::connect(&profile_url).await {
            Ok(s) => match s.init_schema().await {
                Ok(()) => break Arc::new(s),
                Err(e) => warn!(error = %e, "identity schema init failed; retrying"),
            },
            Err(e) => warn!(error = %e, "waiting for identity Postgres"),
        }
        sleep(Duration::from_secs(2)).await;
    };
    let store: Arc<dyn ProfileStore> = store;

    let reader: Arc<dyn SourceMembershipReader> = loop {
        match PgSourceMembershipReader::connect(&routing_url).await {
            Ok(r) => break Arc::new(r),
            Err(e) => {
                warn!(error = %e, "waiting for routing Postgres (read-only)");
                sleep(Duration::from_secs(2)).await;
            }
        }
    };
    info!(backstop_interval_s = backstop_interval.as_secs(), "started");

    let (tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = tx.send(true);
    });

    // Bring the health surface up as soon as both stores are connected — BEFORE the
    // (potentially long) initial backstop — so the kubelet sees a healthy worker
    // immediately instead of CrashLooping it while it converges.
    tokio::spawn(serve_health(health_port, rx.clone()));

    // Backfill/heal immediately on startup, before we depend on live signals.
    if let Err(e) = run_backstop(reader.as_ref(), store.as_ref()).await {
        METRICS.errors.add(1, &[]);
        error!(error = %e, "initial backstop pass failed");
    }

    // Periodic backstop.
    let backstop = {
        let reader = Arc::clone(&reader);
        let store = Arc::clone(&store);
        let mut rx = rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = sleep(backstop_interval) => {
                        if let Err(e) = run_backstop(reader.as_ref(), store.as_ref()).await {
                            METRICS.errors.add(1, &[]);
                            error!(error = %e, "backstop pass failed");
                        }
                    }
                    _ = rx.changed() => break,
                }
            }
        })
    };

    // Real-time LISTEN loop with reconnect. A dropped connection re-establishes the
    // listener; the backstop covers anything missed while it was down.
    loop {
        tokio::select! {
            _ = rx.changed() => break,
            result = run_listener(&routing_url, reader.as_ref(), store.as_ref()) => {
                if let Err(e) = result {
                    METRICS.errors.add(1, &[]);
                    warn!(error = %e, "listener dropped; reconnecting");
                }
                // Brief backoff before reconnecting so a hard failure doesn't spin.
                tokio::select! {
                    () = sleep(Duration::from_secs(2)) => {}
                    _ = rx.changed() => break,
                }
            }
        }
    }

    backstop.abort();
    info!("shutdown signal received; stopped");
    Ok(())
}

/// Open a listener on the routing channel and drain it until it errors.
async fn run_listener(
    routing_url: &str,
    reader: &dyn SourceMembershipReader,
    store: &dyn ProfileStore,
) -> Result<(), BoxError> {
    let mut listener = PgListener::connect(routing_url).await?;
    listener.listen(MEMBERSHIP_CHANNEL).await?;
    info!(channel = MEMBERSHIP_CHANNEL, "listening for membership changes");
    listen_once(&mut listener, reader, store).await
}

async fn shutdown_signal() {
    use tokio::signal;
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = signal::unix::signal(signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
}
