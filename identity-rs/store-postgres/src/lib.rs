//! `PostgreSQL` adapter for the `ProfileStore` port (RFC §3.5 + C4).
//!
//! This is the identity-plane twin of `routing-rs/store-postgres`: it reuses the
//! Postgres that ZITADEL already runs, under a dedicated `identity` schema (the
//! same pattern decision 14 applies to `routing`), so the identity plane needs no
//! second database technology. One server, one freshness primitive
//! (`LISTEN/NOTIFY`), one backup/HA story across both planes.
//!
//! Layout — one row per subject, the whole Profile stored as a document:
//!   - `identity.profiles(sub PK, doc jsonb, deleted bool, seq bigint)`.
//!   - `doc` is `serde_json(Profile)`, so the Profile shape evolves with no schema
//!     migration. Bound as text with a `::jsonb` cast and read back via `doc::text`
//!     so we need no extra sqlx feature.
//!   - `delete` is a TOMBSTONE (`deleted=true`, bump `seq`), never a row removal,
//!     so a delete is replayable by the `seq`-cursor feed below. `get`/`scan_all`
//!     filter `deleted=false`.
//!
//! The change feed (`watch`, RFC C4) is the one non-trivial piece: it must be a
//! resumable, ordered feed, which `LISTEN/NOTIFY` alone is not (best-effort, no
//! replay). We get that guarantee from a monotonic `seq` cursor: NOTIFY is a pure
//! "something changed, wake up" signal, and correctness comes from draining
//! `WHERE seq > last ORDER BY seq`. A dropped NOTIFY self-heals on the next signal
//! or the periodic poll tick — the same best-effort-feed philosophy the routing
//! plane already documents. `WatchToken` is the 8-byte `seq`.
//!
//! The feed is COMPACTED per key: there is one row per subject, so the catch-up
//! drain replays each key's CURRENT state, not its history (e.g. put-then-delete
//! of one subject surfaces once, as the delete). That is exactly what the cache
//! consumer needs — the latest state per key — and means a key changed N times
//! during a disconnect costs one event, not N.

use std::collections::VecDeque;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{unfold, StreamExt};
use sqlx::postgres::{PgConnectOptions, PgListener, PgPoolOptions};
use sqlx::{PgPool, Row};
use tokio::time::timeout;
use tracing::warn;

use identity_core::store::{
    BoxError, Change, ChangeEvent, ChangeFeed, ProfileStore, WatchToken,
};
use identity_core::Profile;

mod source_memberships;
pub use source_memberships::PgSourceMembershipReader;

/// The NOTIFY channel every profile mutation publishes a wakeup on.
pub const CHANGE_CHANNEL: &str = "identity_changes";

/// How long to wait for a NOTIFY before re-draining anyway. A total loss of
/// notifications (e.g. a pooler that swallows `LISTEN`) degrades to "changes land
/// within one poll interval" instead of never — never wrong, just slower.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Max rows pulled per catch-up drain. The feed loop re-drains until empty, so a
/// larger backlog is still delivered in full — this only bounds a single round.
const DRAIN_BATCH: i64 = 1000;

#[derive(Clone)]
pub struct PgProfileStore {
    pool: PgPool,
    /// The direct/session URL, used to open the dedicated `LISTEN` connection in
    /// `watch`. MUST reach the primary on a session connection — a transaction-mode
    /// pooler silently swallows `LISTEN` (see deploy/README.md).
    url: String,
    poll_interval: Duration,
}

impl PgProfileStore {
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        // Disable sqlx's prepared-statement cache so the pool is safe through a
        // transaction-mode pooler; every query here is a trivial point read/write,
        // so the cache buys nothing (same rationale as the routing store).
        let opts = url
            .parse::<PgConnectOptions>()?
            .statement_cache_capacity(0)
            // Cap any single statement server-side so a slow/stuck query can't
            // pin a pooled connection (and stall coalesced waiters) forever.
            .options([("statement_timeout", "5000")]);
        let pool = PgPoolOptions::new()
            .max_connections(8)
            // Bound the wait for a free connection so pool exhaustion surfaces as
            // a fast error instead of an unbounded hang on the request path.
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;
        Ok(Self {
            pool,
            url: url.to_owned(),
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
    }

    /// Override the change-feed poll fallback (default 30s).
    #[must_use] 
    pub const fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Idempotent schema bootstrap. Writers (sync-worker, reconciler) own this on
    /// startup; the sidecar only reads + listens, so it never creates schema.
    pub async fn init_schema(&self) -> Result<(), BoxError> {
        sqlx::query("CREATE SCHEMA IF NOT EXISTS identity")
            .execute(&self.pool)
            .await?;
        sqlx::query("CREATE SEQUENCE IF NOT EXISTS identity.profile_seq")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS identity.profiles (\
                 sub     text    PRIMARY KEY, \
                 doc     jsonb   NOT NULL, \
                 deleted boolean NOT NULL DEFAULT false, \
                 seq     bigint  NOT NULL DEFAULT nextval('identity.profile_seq'))",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS profiles_seq_idx ON identity.profiles (seq)")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[async_trait]
impl ProfileStore for PgProfileStore {
    async fn get(&self, sub: &str) -> Result<Option<Profile>, BoxError> {
        let row = sqlx::query(
            "SELECT doc::text AS doc FROM identity.profiles WHERE sub = $1 AND deleted = false",
        )
        .bind(sub)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(r) => Ok(Some(serde_json::from_str(&r.get::<String, _>("doc"))?)),
            None => Ok(None),
        }
    }

    async fn put(&self, profile: &Profile) -> Result<(), BoxError> {
        let json = serde_json::to_string(profile)?;
        // Upsert + NOTIFY in one transaction so the wakeup is emitted exactly when
        // the new `seq` becomes visible (NOTIFY is delivered on commit). `seq` is
        // taken once from the VALUES nextval and reused on the conflict path via
        // EXCLUDED.seq, so each write consumes a single sequence value.
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO identity.profiles (sub, doc, deleted, seq) \
             VALUES ($1, $2::jsonb, false, nextval('identity.profile_seq')) \
             ON CONFLICT (sub) DO UPDATE SET \
                 doc = EXCLUDED.doc, deleted = false, seq = EXCLUDED.seq",
        )
        .bind(&profile.sub)
        .bind(&json)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CHANGE_CHANNEL)
            .bind(&profile.sub)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn delete(&self, sub: &str) -> Result<(), BoxError> {
        // Tombstone, not a row removal, so the deletion is replayable by the
        // seq-cursor feed. Only notify when a live row was actually tombstoned —
        // deleting a missing/already-deleted subject is a no-op that emits no
        // change event.
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "UPDATE identity.profiles SET deleted = true, seq = nextval('identity.profile_seq') \
             WHERE sub = $1 AND deleted = false",
        )
        .bind(sub)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() > 0 {
            sqlx::query("SELECT pg_notify($1, $2)")
                .bind(CHANGE_CHANNEL)
                .bind(sub)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn scan_all(&self) -> Result<Vec<Profile>, BoxError> {
        let rows = sqlx::query("SELECT doc::text AS doc FROM identity.profiles WHERE deleted = false")
            .fetch_all(&self.pool)
            .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            match serde_json::from_str::<Profile>(&r.get::<String, _>("doc")) {
                Ok(p) => out.push(p),
                Err(e) => warn!(error = %e, "skipping undecodable profile doc"),
            }
        }
        Ok(out)
    }

    async fn watch(&self, after: Option<WatchToken>) -> Result<ChangeFeed, BoxError> {
        // Resume strictly after the caller's last token; `None` means "from now",
        // i.e. start at the current high-water mark and stream only newer changes.
        let last: i64 = if let Some(tok) = after { decode_token(&tok)? } else {
            let row = sqlx::query("SELECT coalesce(max(seq), 0) AS hw FROM identity.profiles")
                .fetch_one(&self.pool)
                .await?;
            row.get::<i64, _>("hw")
        };

        let mut listener = PgListener::connect(&self.url).await?;
        listener.listen(CHANGE_CHANNEL).await?;

        let init = FeedState {
            listener,
            pool: self.pool.clone(),
            last,
            buf: VecDeque::new(),
            poll: self.poll_interval,
        };

        let stream = unfold(init, |mut st| async move {
            loop {
                // Drain buffered catch-up events first.
                if let Some(ev) = st.buf.pop_front() {
                    return Some((Ok(ev), st));
                }
                match drain(&st.pool, st.last).await {
                    Ok(rows) if rows.is_empty() => {
                        // Nothing new — block on a NOTIFY, with a poll fallback so a
                        // missed signal still heals within `poll`.
                        match timeout(st.poll, st.listener.recv()).await {
                            Ok(Ok(_notif)) => continue, // re-drain
                            Ok(Err(e)) => {
                                return Some((Err(Box::new(e) as BoxError), st));
                            }
                            Err(_elapsed) => continue, // poll tick → re-drain
                        }
                    }
                    Ok(rows) => {
                        for (sub, doc, deleted, seq) in rows {
                            st.last = seq;
                            let change = if deleted {
                                Change::Delete(sub)
                            } else {
                                match serde_json::from_str::<Profile>(&doc) {
                                    Ok(p) => Change::Upsert(Box::new(p)),
                                    Err(e) => {
                                        warn!(error = %e, "skipping undecodable change doc");
                                        continue;
                                    }
                                }
                            };
                            st.buf.push_back(ChangeEvent {
                                change,
                                token: encode_token(seq),
                            });
                        }
                        // Loop back to drain the buffer we just filled.
                    }
                    Err(e) => return Some((Err(e), st)),
                }
            }
        });

        Ok(stream.boxed())
    }
}

/// Mutable state threaded through the change-feed `unfold`.
struct FeedState {
    listener: PgListener,
    pool: PgPool,
    last: i64,
    buf: VecDeque<ChangeEvent>,
    poll: Duration,
}

/// Pull the next batch of changes strictly after `after`, ordered by `seq`.
async fn drain(pool: &PgPool, after: i64) -> Result<Vec<(String, String, bool, i64)>, BoxError> {
    let rows = sqlx::query(
        "SELECT sub, doc::text AS doc, deleted, seq FROM identity.profiles \
         WHERE seq > $1 ORDER BY seq LIMIT $2",
    )
    .bind(after)
    .bind(DRAIN_BATCH)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.get::<String, _>("sub"),
                r.get::<String, _>("doc"),
                r.get::<bool, _>("deleted"),
                r.get::<i64, _>("seq"),
            )
        })
        .collect())
}

/// `WatchToken` is the little-endian `seq`. In-memory only (the sidecar restarts
/// with an empty cache), so the encoding is private to this adapter.
fn encode_token(seq: i64) -> WatchToken {
    seq.to_le_bytes().to_vec()
}

fn decode_token(tok: &[u8]) -> Result<i64, BoxError> {
    let bytes: [u8; 8] = tok
        .try_into()
        .map_err(|_| "watch token must be 8 bytes (seq)")?;
    Ok(i64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trips() {
        for seq in [0_i64, 1, 42, i64::MAX, 9_876_543_210] {
            assert_eq!(decode_token(&encode_token(seq)).unwrap(), seq);
        }
    }

    #[test]
    fn token_rejects_wrong_length() {
        assert!(decode_token(&[1, 2, 3]).is_err());
        assert!(decode_token(&[]).is_err());
        assert!(decode_token(&[0_u8; 9]).is_err());
    }
}
