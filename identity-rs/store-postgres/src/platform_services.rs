//! Read-only adapter over the `platform.services` registry — the source of record for
//! a core service's platform-level permission set (capability: platform-service-authz).
//!
//! The identity sidecar RESOLVES a service's authority from this table; it never writes
//! it, so this adapter is `SELECT`-only and holds its own least-privilege pool
//! (mirroring [`crate::PgSourceMembershipReader`]). Only ACTIVE rows are surfaced — a
//! revoked/inactive service is excluded, which is the fail-closed enforcement point
//! (`PlatformServiceReader` contract).

use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{unfold, BoxStream, StreamExt};
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use sqlx::{PgPool, Row};
use tokio::time::timeout;

use identity_core::platform::{PlatformService, PlatformServiceReader};
use identity_core::principal::PlatformScope;
use identity_core::store::BoxError;

/// A live feed of the ACTIVE platform-service set. Each item is the WHOLE active set
/// (the registry is small), yielded once at open and again on every change signal — so
/// the sidecar always holds the current snapshot and a revoke/permission change lands
/// within seconds. Mirrors the `ProfileStore::watch` contract minus the seq cursor
/// (there is no per-key history to replay — each signal reloads the whole set).
pub type PlatformFeed = BoxStream<'static, Result<Vec<PlatformService>, BoxError>>;

/// The NOTIFY channel every `platform.services` mutation publishes a wakeup on (kept
/// in lockstep with the trigger in `migrations/0001_platform_services.sql`). The
/// sidecar LISTENs on it to reload the resident active set within sub-second.
pub const PLATFORM_CHANGE_CHANNEL: &str = "platform_service_changes";

/// Reads the active platform-service registry out of `platform.services`.
pub struct PgPlatformServiceReader {
    pool: PgPool,
}

impl PgPlatformServiceReader {
    /// Open a read-only pool to the platform registry database. Mirrors the identity
    /// store's pooler-safe settings (no statement cache, server-side statement
    /// timeout).
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

impl PgPlatformServiceReader {
    /// Open a **live feed** of the active registry (ADR-7): LISTEN on
    /// [`PLATFORM_CHANGE_CHANNEL`], emit the current active set immediately, then
    /// re-emit it on every change signal and on a periodic `poll` fallback (so a lost
    /// NOTIFY self-heals within `poll`). `url` MUST reach the primary on a session
    /// connection — a transaction-mode pooler silently swallows `LISTEN`.
    ///
    /// # Errors
    /// Returns an error if the LISTEN connection cannot be opened; per-reload query
    /// failures surface as `Err` items on the stream (the caller keeps its last known
    /// snapshot and reconnects).
    pub async fn watch_active(&self, url: &str, poll: Duration) -> Result<PlatformFeed, BoxError> {
        let mut listener = PgListener::connect(url).await?;
        listener.listen(PLATFORM_CHANGE_CHANNEL).await?;
        let init = PlatformFeedState {
            listener,
            pool: self.pool.clone(),
            poll,
            primed: false,
        };
        let stream = unfold(init, |mut st| async move {
            if !st.primed {
                // Prime the snapshot at open so the sidecar starts from the current
                // active set, not an empty one.
                st.primed = true;
                return Some((load_active(&st.pool).await, st));
            }
            // Block for a change signal, with a poll fallback, then re-emit the set.
            match timeout(st.poll, st.listener.recv()).await {
                Ok(Ok(_notif)) => Some((load_active(&st.pool).await, st)),
                Ok(Err(e)) => Some((Err(Box::new(e) as BoxError), st)),
                Err(_elapsed) => Some((load_active(&st.pool).await, st)),
            }
        });
        Ok(stream.boxed())
    }
}

/// Mutable state threaded through the platform change-feed `unfold`.
struct PlatformFeedState {
    listener: PgListener,
    pool: PgPool,
    poll: Duration,
    primed: bool,
}

/// Read the current ACTIVE platform-service set. Only `status = 'active'` rows confer
/// authority — a revoked/inactive service must not resolve to any platform scope (the
/// exclusion here is the fail-closed enforcement point). Shared by the point read
/// ([`PlatformServiceReader::active_services`]) and the live feed.
async fn load_active(pool: &PgPool) -> Result<Vec<PlatformService>, BoxError> {
    let rows = sqlx::query(
        "SELECT service_id, permissions::text AS permissions \
         FROM platform.services WHERE status = 'active'",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let service_id: String = r.try_get("service_id")?;
        let permissions: String = r.try_get("permissions")?;
        out.push(PlatformService {
            service_id,
            scope: PlatformScope::new(parse_permissions(&permissions)),
        });
    }
    Ok(out)
}

/// Parse the stored `permissions` jsonb (a JSON array of strings) into the named
/// permission set. A malformed/absent value yields an EMPTY set (fail-closed:
/// least-privilege — a service we can't read permissions for admits nothing), never an
/// error that would drop the whole active-set read.
fn parse_permissions(json: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(json).unwrap_or_default()
}

#[async_trait]
impl PlatformServiceReader for PgPlatformServiceReader {
    async fn active_services(&self) -> Result<Vec<PlatformService>, BoxError> {
        load_active(&self.pool).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_permission_array() {
        assert_eq!(
            parse_permissions(r#"["events:write","events:read"]"#),
            vec!["events:write".to_owned(), "events:read".to_owned()],
        );
    }

    #[test]
    fn empty_or_malformed_permissions_are_least_privilege() {
        // An empty array is an empty set; a malformed value fails CLOSED to an empty
        // set (admits nothing), never propagates an error that would drop the read.
        assert!(parse_permissions("[]").is_empty());
        assert!(parse_permissions("not json").is_empty());
        assert!(parse_permissions("{}").is_empty());
        assert!(parse_permissions("null").is_empty());
    }
}
