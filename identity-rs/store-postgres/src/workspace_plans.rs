//! Read-only adapter over the ROUTING plane's `routing.workspaces.plan` column — the
//! source of record for a workspace's plan tier (written by the control plane, `DEFAULT
//! 'free'`). The identity plane PROJECTS this into the enriched request; it never writes
//! it, so this adapter is `SELECT`-only and holds its own least-privilege routing pool
//! (mirroring [`crate::PgSourceMembershipReader`] and [`crate::PgPlatformServiceReader`]).
//!
//! `plan` is read back as an OPAQUE string (design R2): the canonical vocabulary is
//! nexus-owned via the control-plane `PlanLimits` and validated at the WRITE boundary, so
//! the read path here trusts the stored value and never re-validates it (the same posture
//! as [`crate::PgSourceMembershipReader`] persisting the wire `membership kind`).

use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{unfold, BoxStream, StreamExt};
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use sqlx::{PgPool, Row};
use tokio::time::timeout;

use identity_core::store::BoxError;
use identity_core::workspace_plan::{WorkspacePlan, WorkspacePlanReader};

/// A live feed of the provisioned workspace→plan set. Each item is the WHOLE set,
/// yielded once at open and again on every change signal — so the sidecar always holds
/// the current snapshot and a plan upgrade/downgrade lands within seconds. Mirrors
/// [`crate::PlatformFeed`].
pub type WorkspacePlanFeed = BoxStream<'static, Result<Vec<WorkspacePlan>, BoxError>>;

/// The NOTIFY channel the routing control plane publishes on after a workspace mutation
/// (a plan change is a workspace-row change that already fires it). Kept in lockstep with
/// the routing store's `INVALIDATION_CHANNEL` (`routing-rs/store-postgres`). We LISTEN on
/// it and reload the whole set on any signal; the payload (a domain key) is ignored — the
/// signal is a pure "something changed, reload" wakeup, and a missed one self-heals on the
/// poll fallback. (Design 1.3 sub-decision: reuse the shared channel; only add a dedicated
/// plan channel if this one proves too chatty.)
pub const WORKSPACE_INVALIDATION_CHANNEL: &str = "routing_invalidations";

/// Reads the provisioned workspace→plan set out of `routing.workspaces`.
pub struct PgWorkspacePlanReader {
    pool: PgPool,
}

impl PgWorkspacePlanReader {
    /// Open a read-only pool to the routing database. Mirrors the identity store's
    /// pooler-safe settings (no statement cache, server-side statement timeout).
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        let opts = url
            .parse::<PgConnectOptions>()?
            .statement_cache_capacity(0)
            .options([("statement_timeout", "5000")]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }
}

impl PgWorkspacePlanReader {
    /// Open a **live feed** of the workspace→plan set: LISTEN on
    /// [`WORKSPACE_INVALIDATION_CHANNEL`], emit the current set immediately, then re-emit
    /// it on every change signal and on a periodic `poll` fallback (so a lost NOTIFY
    /// self-heals within `poll`). `url` MUST reach the primary on a session connection — a
    /// transaction-mode pooler silently swallows `LISTEN`.
    ///
    /// # Errors
    /// Returns an error if the LISTEN connection cannot be opened; per-reload query
    /// failures surface as `Err` items on the stream (the caller keeps its last known
    /// snapshot and reconnects).
    pub async fn watch_active(&self, url: &str, poll: Duration) -> Result<WorkspacePlanFeed, BoxError> {
        let mut listener = PgListener::connect(url).await?;
        listener.listen(WORKSPACE_INVALIDATION_CHANNEL).await?;
        let init = PlanFeedState {
            listener,
            pool: self.pool.clone(),
            poll,
            primed: false,
        };
        let stream = unfold(init, |mut st| async move {
            if !st.primed {
                // Prime the snapshot at open so the sidecar starts from the current set,
                // not an empty one.
                st.primed = true;
                return Some((load_plans(&st.pool).await, st));
            }
            // Block for a change signal, with a poll fallback, then re-emit the set.
            match timeout(st.poll, st.listener.recv()).await {
                Ok(Ok(_notif)) => Some((load_plans(&st.pool).await, st)),
                Ok(Err(e)) => Some((Err(Box::new(e) as BoxError), st)),
                Err(_elapsed) => Some((load_plans(&st.pool).await, st)),
            }
        });
        Ok(stream.boxed())
    }
}

/// Mutable state threaded through the plan change-feed `unfold`.
struct PlanFeedState {
    listener: PgListener,
    pool: PgPool,
    poll: Duration,
    primed: bool,
}

/// Read the current provisioned workspace→plan set. A provisioned workspace always has a
/// plan (`NOT NULL DEFAULT 'free'`); `plan` is trusted as-is (opaque wire string, design
/// R2 — no re-validation). Shared by the point read
/// ([`WorkspacePlanReader::all_plans`]) and the live feed.
async fn load_plans(pool: &PgPool) -> Result<Vec<WorkspacePlan>, BoxError> {
    let rows = sqlx::query("SELECT workspace_id, plan FROM routing.workspaces")
        .fetch_all(pool)
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let workspace_id: String = r.try_get("workspace_id")?;
        let plan: String = r.try_get("plan")?;
        out.push(WorkspacePlan { workspace_id, plan });
    }
    Ok(out)
}

#[async_trait]
impl WorkspacePlanReader for PgWorkspacePlanReader {
    async fn all_plans(&self) -> Result<Vec<WorkspacePlan>, BoxError> {
        load_plans(&self.pool).await
    }
}
