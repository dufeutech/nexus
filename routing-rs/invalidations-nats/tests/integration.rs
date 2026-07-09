//! Live-NATS integration tests for the `Invalidations` NATS adapter.
//!
//! Gated on `NATS_TEST_URL` so `cargo test` stays green on a machine with no
//! broker (mirrors `store-postgres`'s `STORE_PG_TEST_URL` convention). To run:
//!
//!   docker run -p 4222:4222 nats:latest
//!   NATS_TEST_URL=nats://localhost:4222 cargo test -p invalidations-nats
//!
//! These pin the routing-invalidation-propagation contract at the transport
//! boundary: the feed yields exactly the published normalized domain key
//! (transport-agnostic parity with the pg_notify payload), duplicates deliver
//! independently (idempotent downstream), and a malformed payload never tears the
//! feed down (best-effort).

use std::env;
use std::time::Duration;

use futures::StreamExt;
use invalidations_nats::{NatsInvalidations, INVALIDATION_SUBJECT};
use router_core::store::{InvalidationFeed, Invalidations};
use tokio::time::timeout;

/// Open the adapter feed, or `None` if the test broker isn't configured. Returns
/// a publisher client too, so the test can drive the subject.
async fn setup() -> Option<(async_nats::Client, InvalidationFeed)> {
    let url = env::var("NATS_TEST_URL").ok()?;
    let adapter = NatsInvalidations::new(url.clone());
    let feed = adapter.subscribe().await.expect("subscribe to NATS_TEST_URL");
    let publisher = async_nats::connect(&url).await.expect("publisher connect");
    Some((publisher, feed))
}

macro_rules! skip_if_no_nats {
    () => {
        match setup().await {
            Some(pair) => pair,
            None => {
                eprintln!("SKIP: set NATS_TEST_URL to run this integration test");
                return;
            }
        }
    };
}

/// Publish `key` on the subject and return the next feed item within a bound, or
/// `None` on timeout. Publishes in a short retry loop so the test does not race
/// the subscription's server-side registration (core NATS drops with no interest).
async fn publish_and_recv(
    publisher: &async_nats::Client,
    feed: &mut InvalidationFeed,
    key: &str,
) -> Option<String> {
    for _ in 0..20 {
        publisher
            .publish(INVALIDATION_SUBJECT, key.as_bytes().to_vec().into())
            .await
            .expect("publish");
        publisher.flush().await.expect("flush");
        if let Ok(Some(item)) = timeout(Duration::from_millis(100), feed.next()).await {
            return Some(item.expect("feed item is Ok"));
        }
    }
    None
}

/// 4.2 / 4.3 — a published invalidation surfaces on the feed as exactly the domain
/// key (the same string a pg_notify payload carries → transport-agnostic parity).
#[tokio::test]
async fn feed_yields_the_published_domain_key() {
    let (publisher, mut feed) = skip_if_no_nats!();
    let got = publish_and_recv(&publisher, &mut feed, "tenant.example.com").await;
    assert_eq!(
        got.as_deref(),
        Some("tenant.example.com"),
        "the NATS feed must yield the published normalized domain key verbatim"
    );
}

/// 4.4 — a duplicate signal delivers independently on the feed; downstream eviction
/// is idempotent, so re-delivery is harmless (no additional observable effect).
#[tokio::test]
async fn duplicate_signal_delivers_again_harmlessly() {
    let (publisher, mut feed) = skip_if_no_nats!();
    let first = publish_and_recv(&publisher, &mut feed, "dup.example.com").await;
    assert_eq!(first.as_deref(), Some("dup.example.com"));
    // A second publish of the same key is delivered again (idempotent to evict).
    publisher
        .publish(INVALIDATION_SUBJECT, b"dup.example.com".to_vec().into())
        .await
        .expect("publish dup");
    publisher.flush().await.expect("flush");
    let second = timeout(Duration::from_millis(500), feed.next())
        .await
        .expect("second delivery within bound")
        .expect("feed still open")
        .expect("feed item is Ok");
    assert_eq!(second, "dup.example.com");
}

/// 4.4 — a malformed (non-UTF-8) payload is decoded lossily and still yields a feed
/// item; the feed is never torn down by a poison message (best-effort).
#[tokio::test]
async fn malformed_payload_does_not_tear_down_the_feed() {
    let (publisher, mut feed) = skip_if_no_nats!();
    let mut delivered = None;
    for _ in 0..20 {
        publisher
            .publish(INVALIDATION_SUBJECT, vec![0xff, 0xfe, 0xfd].into())
            .await
            .expect("publish malformed");
        publisher.flush().await.expect("flush");
        if let Ok(Some(item)) = timeout(Duration::from_millis(100), feed.next()).await {
            delivered = Some(item);
            break;
        }
    }
    let item = delivered.expect("expected a lossy-decoded feed item for the malformed payload");
    // Yielded an Ok item (lossy), not an error — the feed stays alive.
    assert!(item.is_ok(), "malformed payload must not error the feed");
}
