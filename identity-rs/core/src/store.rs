//! The Durable State Store port (RFC §3.5) — the abstract capability core needs,
//! with NO vendor concretion (rules §2). An adapter crate implements this against
//! a concrete database; core and the services depend only on this trait.

use std::error::Error;

use async_trait::async_trait;
use futures::stream::BoxStream;

use crate::profile::Profile;

pub type BoxError = Box<dyn Error + Send + Sync>;

/// A live change observed from the store (RFC C4). The watch feed delivers these
/// so caches stay fresh and revocations take effect within seconds.
#[derive(Debug, Clone)]
pub enum Change {
    /// A profile was created or updated.
    Upsert(Box<Profile>),
    /// The profile for this subject was removed.
    Delete(String),
}

/// Opaque resume cursor for the change feed — encoding is the adapter's business.
///
/// The caller persists the most recent token and passes it back on reconnect so a
/// watch disconnect misses NOTHING (a resumable feed; RFC C4 / §3.5).
pub type WatchToken = Vec<u8>;

/// A change plus the resume position immediately AFTER it.
#[derive(Debug, Clone)]
pub struct ChangeEvent {
    pub change: Change,
    pub token: WatchToken,
}

/// A live, resumable change feed.
pub type ChangeFeed = BoxStream<'static, Result<ChangeEvent, BoxError>>;

/// Abstract profile store: point reads/writes by subject key, a shard-scoped
/// scan for reconciliation, and a live change feed for cache freshness.
///
/// The hot path uses only `get` (on a cache miss). `watch` backs the push-update
/// path (C4). `scan_all` is the membership backstop's convergence input — at 1B
/// scale an adapter MUST partition it; the small-scale reference scans all.
#[async_trait]
pub trait ProfileStore: Send + Sync {
    /// Point read by subject. `None` if absent.
    async fn get(&self, sub: &str) -> Result<Option<Profile>, BoxError>;

    /// Create or update the profile keyed by its `sub`.
    async fn put(&self, profile: &Profile) -> Result<(), BoxError>;

    /// Remove the profile for a subject (idempotent — missing is not an error).
    async fn delete(&self, sub: &str) -> Result<(), BoxError>;

    /// All stored profiles (membership backstop input). The backstop derives the set
    /// of subjects still carrying a stale projection from this, to heal missed
    /// revokes (paired with the source-of-record member set).
    async fn scan_all(&self) -> Result<Vec<Profile>, BoxError>;

    /// Open a live, **resumable** change feed (C4). `after = Some(token)` resumes
    /// strictly after a previously-yielded event so a reconnect misses nothing;
    /// `None` starts from now. Each yielded `ChangeEvent` carries the resume token
    /// to use on the next reopen. Callers reopen on error from the last token seen.
    async fn watch(&self, after: Option<WatchToken>) -> Result<ChangeFeed, BoxError>;
}
