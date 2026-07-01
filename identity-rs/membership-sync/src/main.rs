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

use std::collections::HashSet;
use std::env::var;
use std::error::Error;
#[cfg(not(unix))]
use std::future::pending;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::postgres::PgListener;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, warn};

use identity_core::store::{BoxError, ProfileStore};
use identity_core::{Profile, SourceMembershipReader};
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

/// Re-derive one subject's projected memberships from the source of record and
/// read-merge-write them into its Profile. Preserves every other Profile field
/// (identity attributes, roles). Skips creating an empty profile for a subject that
/// has neither a profile nor any memberships (nothing to project).
async fn sync_subject(
    reader: &dyn SourceMembershipReader,
    store: &dyn ProfileStore,
    sub: &str,
) -> Result<(), BoxError> {
    let memberships = reader.memberships_for(sub).await?;
    let existing = store.get(sub).await?;
    if existing.is_none() && memberships.is_empty() {
        return Ok(()); // no profile, no memberships → nothing to write.
    }
    let profile = existing
        .unwrap_or_else(|| Profile { sub: sub.to_owned(), ..Default::default() })
        .with_memberships(memberships);
    store.put(&profile).await?;
    counter!("membership_sync_subject_syncs_total").increment(1);
    Ok(())
}

/// Backstop: converge EVERY subject that either holds a source-of-record membership
/// (backfill / missed-grant) or still carries a projected membership (heal a missed
/// revoke, including revoke-to-zero where the subject left the source set).
async fn backstop_pass(
    reader: &dyn SourceMembershipReader,
    store: &dyn ProfileStore,
) -> Result<(), BoxError> {
    let mut subjects: HashSet<String> =
        reader.all_member_subjects().await?.into_iter().collect();
    for p in store.scan_all().await? {
        if !p.memberships.is_empty() {
            subjects.insert(p.sub);
        }
    }
    let total = subjects.len();
    let mut synced = 0_u64;
    for sub in subjects {
        if let Err(e) = sync_subject(reader, store, &sub).await {
            counter!("membership_sync_errors_total").increment(1);
            warn!(error = %e, %sub, "backstop subject sync failed");
        } else {
            synced += 1;
        }
    }
    counter!("membership_sync_backstop_passes_total").increment(1);
    gauge!("membership_sync_last_backstop_subjects").set(total as f64);
    info!(subjects = total, synced, "backstop pass");
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
        counter!("membership_sync_signals_total").increment(1);
        if let Err(e) = sync_subject(reader, store, &sub).await {
            counter!("membership_sync_errors_total").increment(1);
            warn!(error = %e, %sub, "signal subject sync failed; backstop will heal");
        }
    }
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    init_tracing();
    let metrics_port: u16 = env_num("METRICS_PORT", 9000_u16);
    PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], metrics_port))
        .install()?;
    info!(port = metrics_port, "metrics listener up");

    let profile_url = env("PROFILE_PG_URL", "postgres://postgres:postgres@postgres:5432/zitadel");
    // Read-only routing connection (least privilege: SELECT on routing.memberships +
    // LISTEN). A SEPARATE database from the identity store in production.
    let routing_url = env("ROUTING_PG_RO_URL", "postgres://postgres:postgres@postgres:5432/zitadel");
    let backstop_interval = Duration::from_secs(env_num("MEMBERSHIP_BACKSTOP_INTERVAL", 600_u64));

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

    // Backfill/heal immediately on startup, before we depend on live signals.
    if let Err(e) = backstop_pass(reader.as_ref(), store.as_ref()).await {
        counter!("membership_sync_errors_total").increment(1);
        error!(error = %e, "initial backstop pass failed");
    }

    let (tx, mut rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = tx.send(true);
    });

    // Periodic backstop.
    let backstop = {
        let reader = Arc::clone(&reader);
        let store = Arc::clone(&store);
        let mut rx = rx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = sleep(backstop_interval) => {
                        if let Err(e) = backstop_pass(reader.as_ref(), store.as_ref()).await {
                            counter!("membership_sync_errors_total").increment(1);
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
                    counter!("membership_sync_errors_total").increment(1);
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
