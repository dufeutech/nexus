use async_trait::async_trait;
use futures::stream::{unfold, StreamExt};
use sqlx::postgres::PgListener;

use router_core::store::{BoxError, InvalidationFeed, InvalidationPublisher, Invalidations};

use crate::{PgRoutingStore, INVALIDATION_CHANNEL};

/// `LISTEN/NOTIFY`-backed invalidation feed. A dedicated listener connection is
/// opened per subscription (reopened by the caller on error).
pub struct PgInvalidations {
    url: String,
}

impl PgInvalidations {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// The pg_notify publish path behind the `InvalidationPublisher` port — the
/// symmetric counterpart of `PgInvalidations` (subscribe). Delegates to the
/// store's existing `notify_invalidation` so the SQL lives in one place.
#[async_trait]
impl InvalidationPublisher for PgRoutingStore {
    async fn publish(&self, domain: &str) -> Result<(), BoxError> {
        self.notify_invalidation(domain).await
    }
}

#[async_trait]
impl Invalidations for PgInvalidations {
    async fn subscribe(&self) -> Result<InvalidationFeed, BoxError> {
        let mut listener = PgListener::connect(&self.url).await?;
        listener.listen(INVALIDATION_CHANNEL).await?;
        // Built over `recv()` so each yielded item is the notification payload
        // (the normalized domain key) or a recoverable error the caller reopens on.
        let stream = unfold(listener, |mut l| async move {
            let item = match l.recv().await {
                Ok(n) => Ok(n.payload().to_owned()),
                Err(e) => Err(Box::new(e) as BoxError),
            };
            Some((item, l))
        });
        Ok(stream.boxed())
    }
}
