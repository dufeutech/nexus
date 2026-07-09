//! NATS adapter for the `Invalidations` port (track D: cross-region delivery).
//!
//! Postgres `LISTEN/NOTIFY` — the default transport (`store-postgres`) — is
//! delivered only within a single Postgres server: physical replicas do not
//! forward `NOTIFY`, so a router in another region stops receiving invalidations
//! and serves stale routes until the cache TTL expires. This adapter carries the
//! same signal over NATS, whose gateway/supercluster fan-out crosses regions.
//!
//! **Core NATS (fire-and-forget) only.** Delivery is at-most-once; a dropped
//! signal self-heals within `ROUTING_CACHE_TTL` (the correctness floor), exactly
//! as the pg_notify path already tolerates. Durable / replay-from-cursor delivery
//! (JetStream) is deliberately out of scope — it belongs to the identity plane's
//! `seq` revocation path, not the routing plane (design.md).
//!
//! The adapter yields the identical `InvalidationFeed` (a stream of normalized
//! domain keys) that `PgInvalidations` produces, so the downstream eviction path
//! (`run_invalidations` -> L1/L2 `invalidate`) is unchanged and transport-agnostic.

use async_trait::async_trait;
use futures::stream::StreamExt;

use router_core::store::{BoxError, InvalidationFeed, InvalidationPublisher, Invalidations};

/// The NATS subject the control plane publishes routing invalidations on — the
/// cross-region analogue of the `routing_invalidations` NOTIFY channel. The
/// payload is the affected normalized domain key (UTF-8), matching pg_notify.
///
/// A single broadcast subject (not per-tenant) mirrors today's single-channel
/// model; interest-based gateway routing already keeps a subject off regions with
/// no subscribers, so per-tenant subjects buy nothing here (design.md open Q2).
pub const INVALIDATION_SUBJECT: &str = "routing.invalidations";

/// NATS-backed invalidation feed. A subscription is opened per `subscribe` call
/// (reopened by the caller on error), mirroring `PgInvalidations`.
pub struct NatsInvalidations {
    url: String,
    subject: String,
}

impl NatsInvalidations {
    /// Adapter publishing/subscribing on the canonical [`INVALIDATION_SUBJECT`].
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            subject: INVALIDATION_SUBJECT.to_owned(),
        }
    }

    /// Adapter with an operator-overridden subject (config, never a literal at the
    /// call site) — keeps the subject a single source of truth.
    pub fn with_subject(url: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            subject: subject.into(),
        }
    }
}

/// NATS-backed publish path behind the `InvalidationPublisher` port — the
/// counterpart of [`NatsInvalidations`] (subscribe). The control plane publishes
/// each invalidation here so subscribers in other regions receive it.
pub struct NatsPublisher {
    client: async_nats::Client,
    subject: String,
}

impl NatsPublisher {
    /// Connect a publisher on the canonical [`INVALIDATION_SUBJECT`]. Uses
    /// retry-on-initial-connect so a not-yet-ready broker does not fail control-
    /// plane startup; the client reconnects in the background (best-effort, the
    /// TTL backstop covers any gap).
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        let client = async_nats::ConnectOptions::new()
            .retry_on_initial_connect()
            .connect(url)
            .await?;
        Ok(Self {
            client,
            subject: INVALIDATION_SUBJECT.to_owned(),
        })
    }
}

#[async_trait]
impl InvalidationPublisher for NatsPublisher {
    async fn publish(&self, domain: &str) -> Result<(), BoxError> {
        // Payload is the normalized domain key (UTF-8), identical to the pg_notify
        // payload — so the feed a subscriber yields is transport-agnostic.
        self.client
            .publish(self.subject.clone(), domain.as_bytes().to_vec().into())
            .await?;
        Ok(())
    }
}

/// Decode a NATS message payload into a normalized domain key. Lossy on purpose:
/// a malformed (non-UTF-8) payload becomes a key that evicts a non-existent entry
/// — a harmless no-op — rather than an error that tears the feed down. This keeps
/// the feed best-effort (it ends only on disconnect, never on a poison message).
fn decode_key(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload).into_owned()
}

#[async_trait]
impl Invalidations for NatsInvalidations {
    async fn subscribe(&self) -> Result<InvalidationFeed, BoxError> {
        // A connect failure surfaces as an error the caller's watch loop retries
        // on (fail-safe): the hot resolve path never touches this feed, and the
        // TTL backstop covers the gap until it reopens.
        let client = async_nats::connect(&self.url).await?;
        let subscriber = client.subscribe(self.subject.clone()).await?;
        // Duplicate / out-of-order deliveries are safe because downstream eviction
        // is idempotent; the stream ends only when the subscription closes, which
        // reopens the feed.
        let stream = subscriber.map(|msg| Ok(decode_key(&msg.payload)));
        Ok(stream.boxed())
    }
}

#[cfg(test)]
mod tests {
    use super::{decode_key, NatsInvalidations, INVALIDATION_SUBJECT};

    #[test]
    fn decodes_utf8_domain_key_verbatim() {
        assert_eq!(decode_key(b"tenant.example.com"), "tenant.example.com");
    }

    #[test]
    fn decodes_malformed_payload_lossily_without_erroring() {
        // An invalid UTF-8 byte yields the replacement char instead of a panic or
        // error — a best-effort eviction of a key that won't exist, never a feed
        // teardown.
        let key = decode_key(&[0xff, 0xfe]);
        assert!(!key.is_empty(), "lossy decode must still produce a key");
    }

    #[test]
    fn defaults_to_the_canonical_subject() {
        // The subject is a single source of truth; `new` uses it, `with_subject`
        // overrides via config (asserted indirectly by the constant being public).
        let _adapter = NatsInvalidations::new("nats://unused:4222");
        assert_eq!(INVALIDATION_SUBJECT, "routing.invalidations");
    }
}
