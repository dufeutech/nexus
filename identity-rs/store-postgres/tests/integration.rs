//! Integration tests for `PgProfileStore` against a real Postgres.
//!
//! These exercise the SQL paths the unit tests can't: point read/write/delete,
//! the tombstone-delete semantics, `scan_all`, and — most importantly — the
//! resumable `seq`-cursor `watch` feed (catch-up replay + live NOTIFY + delete
//! events).
//!
//! They are gated on `STORE_PG_TEST_URL` so `cargo test` stays green on a machine
//! with no database: unset → each test prints a skip line and returns. Point it at
//! a THROWAWAY Postgres (the tests create the `identity` schema and TRUNCATE the
//! table), e.g.:
//!
//!   docker run --rm -d -p 5433:5432 -e `POSTGRES_PASSWORD=postgres` --name pgtest postgres:16-alpine
//!   `STORE_PG_TEST_URL=postgres://postgres:postgres@localhost:5433/postgres` \
//!     cargo test -p store-postgres --test integration -- --test-threads=1
//!
//! Run single-threaded (`--test-threads=1`): all tests share the one `identity`
//! schema and each begins by truncating it, so they must not interleave.

use std::env;
use std::time::Duration;

use futures::StreamExt;
use identity_core::membership::{MemberType, SourceMembershipReader};
use identity_core::store::{Change, ProfileStore};
use identity_core::Profile;
use sqlx::postgres::PgPoolOptions;
use store_postgres::{PgProfileStore, PgSourceMembershipReader};
use tokio::time::{sleep, timeout};

/// Connect + clean the shared table, or `None` if the test DB isn't configured.
async fn setup() -> Option<PgProfileStore> {
    let url = env::var("STORE_PG_TEST_URL").ok()?;
    let store = PgProfileStore::connect(&url)
        .await
        .expect("connect to STORE_PG_TEST_URL");
    store.init_schema().await.expect("init_schema");
    // Start every test from a clean slate (and reset the sequence so token math
    // is predictable across runs).
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("aux pool");
    sqlx::query("TRUNCATE identity.profiles")
        .execute(&pool)
        .await
        .expect("truncate");
    sqlx::query("ALTER SEQUENCE identity.profile_seq RESTART WITH 1")
        .execute(&pool)
        .await
        .expect("reset seq");
    Some(store)
}

fn profile(sub: &str, suspended: bool) -> Profile {
    Profile {
        sub: sub.to_owned(),
        is_suspended: suspended,
        roles: vec!["viewer".into()],
        ..Default::default()
    }
}

macro_rules! skip_if_no_db {
    ($store:ident) => {
        match setup().await {
            Some(s) => s,
            None => {
                eprintln!("SKIP: set STORE_PG_TEST_URL to run this integration test");
                return;
            }
        }
    };
}

macro_rules! skip_if_no_routing_db {
    ($reader:ident) => {
        match setup_routing_memberships().await {
            Some(r) => r,
            None => {
                eprintln!("SKIP: set STORE_PG_TEST_URL to run this integration test");
                return;
            }
        }
    };
}

#[tokio::test]
async fn put_get_roundtrip() {
    let store = skip_if_no_db!(store);
    assert!(store.get("u1").await.unwrap().is_none(), "absent before put");

    let p = profile("u1", false);
    store.put(&p).await.unwrap();
    let got = store.get("u1").await.unwrap().expect("present after put");
    assert_eq!(got.sub, "u1");
    assert_eq!(got.roles, vec!["viewer".to_owned()]);
    assert!(!got.is_suspended);
}

#[tokio::test]
async fn put_is_an_upsert() {
    let store = skip_if_no_db!(store);
    store.put(&profile("u1", false)).await.unwrap();
    store.put(&profile("u1", true)).await.unwrap();
    let got = store.get("u1").await.unwrap().unwrap();
    assert!(got.is_suspended, "second put overwrote the first");
}

#[tokio::test]
async fn delete_tombstones_and_hides_from_reads() {
    let store = skip_if_no_db!(store);
    store.put(&profile("u1", false)).await.unwrap();
    store.delete("u1").await.unwrap();
    assert!(store.get("u1").await.unwrap().is_none(), "get hides tombstone");
    assert!(
        store.scan_all().await.unwrap().iter().all(|p| p.sub != "u1"),
        "scan_all hides tombstone"
    );
    // Delete of an already-deleted / missing subject is a no-op (must not error).
    store.delete("u1").await.unwrap();
    store.delete("never-existed").await.unwrap();
}

#[tokio::test]
async fn scan_all_returns_live_only() {
    let store = skip_if_no_db!(store);
    store.put(&profile("a", false)).await.unwrap();
    store.put(&profile("b", false)).await.unwrap();
    store.put(&profile("c", false)).await.unwrap();
    store.delete("b").await.unwrap();
    let mut subs: Vec<String> = store.scan_all().await.unwrap().into_iter().map(|p| p.sub).collect();
    subs.sort();
    assert_eq!(subs, vec!["a".to_owned(), "c".to_owned()]);
}

#[tokio::test]
async fn watch_catches_up_on_existing_changes() {
    let store = skip_if_no_db!(store);
    // Two distinct keys written BEFORE the watch opens. `None` would start at the
    // high-water mark and skip them; resuming from token 0 replays from the start.
    store.put(&profile("u1", false)).await.unwrap();
    store.put(&profile("u2", false)).await.unwrap();

    let zero = 0_i64.to_le_bytes().to_vec();
    let mut feed = store.watch(Some(zero)).await.unwrap();

    let mut seen = Vec::new();
    for _ in 0..2 {
        let ev = timeout(Duration::from_secs(5), feed.next())
            .await
            .expect("feed yields within 5s")
            .expect("stream not ended")
            .expect("change event ok");
        seen.push(ev.change);
    }
    // Ordered by seq: upsert u1 (seq 1), upsert u2 (seq 2).
    assert!(matches!(&seen[0], Change::Upsert(p) if p.sub == "u1"));
    assert!(matches!(&seen[1], Change::Upsert(p) if p.sub == "u2"));
}

#[tokio::test]
async fn watch_catchup_is_compacted_per_key() {
    let store = skip_if_no_db!(store);
    // The feed is COMPACTED per key: there is one row per subject, so a catch-up
    // drain (`WHERE seq > last`) replays each key's CURRENT state, not its history.
    // put-then-delete of the same subject therefore surfaces ONCE, as the delete —
    // which is exactly what the cache consumer needs (final state per key).
    store.put(&profile("u1", false)).await.unwrap(); // seq 1
    store.delete("u1").await.unwrap(); // seq 2 — same row, now a tombstone

    let zero = 0_i64.to_le_bytes().to_vec();
    let mut feed = store.watch(Some(zero)).await.unwrap();

    let ev = timeout(Duration::from_secs(5), feed.next())
        .await
        .expect("feed yields within 5s")
        .expect("stream not ended")
        .expect("change event ok");
    assert!(matches!(&ev.change, Change::Delete(sub) if sub == "u1"));

    // No second event for u1 — the seq-1 upsert was compacted away by the tombstone.
    let second = timeout(Duration::from_millis(800), feed.next()).await;
    assert!(second.is_err(), "only one (compacted) event for the key");
}

#[tokio::test]
async fn watch_delivers_live_changes_after_open() {
    let store = skip_if_no_db!(store);
    // `None` = from now: the feed should pick up only writes made AFTER it opens.
    let mut feed = store.watch(None).await.unwrap();

    // Give the listener a moment to be established, then write.
    sleep(Duration::from_millis(200)).await;
    let writer = store.clone();
    tokio::spawn(async move {
        writer.put(&profile("live1", false)).await.unwrap();
        writer.put(&profile("live1", true)).await.unwrap(); // suspension upsert
        writer.delete("live1").await.unwrap();
    });

    let mut kinds = Vec::new();
    for _ in 0..3 {
        let ev = timeout(Duration::from_secs(5), feed.next())
            .await
            .expect("live feed yields within 5s")
            .expect("stream not ended")
            .expect("change event ok");
        kinds.push(ev.change);
    }
    assert!(matches!(&kinds[0], Change::Upsert(p) if !p.is_suspended));
    assert!(matches!(&kinds[1], Change::Upsert(p) if p.is_suspended), "suspension lands as an upsert");
    assert!(matches!(&kinds[2], Change::Delete(sub) if sub == "live1"));
}

/// Create a minimal `routing.memberships` table (subset of the routing store's
/// DDL — the columns the reader selects) and seed it, or `None` if no test DB.
/// Returns a read-only reader over the same URL.
async fn setup_routing_memberships() -> Option<PgSourceMembershipReader> {
    let url = env::var("STORE_PG_TEST_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("aux pool");
    sqlx::query("CREATE SCHEMA IF NOT EXISTS routing")
        .execute(&pool)
        .await
        .expect("routing schema");
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS routing.memberships (\
             user_sub text, workspace_id text, member_type text, role text, \
             status text, PRIMARY KEY (user_sub, workspace_id))",
    )
    .execute(&pool)
    .await
    .expect("memberships table");
    sqlx::query("TRUNCATE routing.memberships")
        .execute(&pool)
        .await
        .expect("truncate memberships");
    // u1: an active staff + active customer membership, plus one INACTIVE row that
    // must be excluded from the projection. u2: one active membership.
    for (sub, ws, mt, role, status) in [
        ("u1", "ws-a", "staff", "admin", "active"),
        ("u1", "ws-b", "customer", "pro", "active"),
        ("u1", "ws-x", "staff", "owner", "suspended"),
        ("u2", "ws-c", "customer", "free", "active"),
    ] {
        sqlx::query(
            "INSERT INTO routing.memberships \
                 (user_sub, workspace_id, member_type, role, status) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(sub)
        .bind(ws)
        .bind(mt)
        .bind(role)
        .bind(status)
        .execute(&pool)
        .await
        .expect("seed membership");
    }
    Some(
        PgSourceMembershipReader::connect(&url)
            .await
            .expect("connect reader"),
    )
}

#[tokio::test]
async fn reader_projects_active_memberships_only() {
    let reader = skip_if_no_routing_db!(reader);
    let mut m = reader.memberships_for("u1").await.unwrap();
    m.sort_by(|a, b| a.workspace_id.cmp(&b.workspace_id));
    // Only the two ACTIVE rows project; the suspended ws-x is excluded (fail-closed).
    assert_eq!(m.len(), 2, "inactive membership must be excluded");
    assert_eq!(m[0].workspace_id, "ws-a");
    assert_eq!(m[0].member_type, MemberType::Staff);
    assert_eq!(m[1].workspace_id, "ws-b");
    assert_eq!(m[1].member_type, MemberType::Customer);

    // all_member_subjects returns the distinct ACTIVE subjects.
    let mut subs = reader.all_member_subjects().await.unwrap();
    subs.sort();
    assert_eq!(subs, vec!["u1".to_owned(), "u2".to_owned()]);

    // A subject with no rows is a member of nothing.
    assert!(reader.memberships_for("ghost").await.unwrap().is_empty());
}

#[tokio::test]
async fn watch_token_resumes_without_duplicates() {
    let store = skip_if_no_db!(store);
    store.put(&profile("u1", false)).await.unwrap();
    store.put(&profile("u2", false)).await.unwrap();

    // First pass from the beginning: read exactly one event, remember its token.
    let zero = 0_i64.to_le_bytes().to_vec();
    let mut feed = store.watch(Some(zero)).await.unwrap();
    let first = timeout(Duration::from_secs(5), feed.next())
        .await
        .expect("yields")
        .unwrap()
        .unwrap();
    let resume_token = first.token.clone();
    assert!(matches!(&first.change, Change::Upsert(p) if p.sub == "u1"));
    drop(feed); // simulate a reconnect

    // Resume strictly AFTER the first event: must see u2 next, never u1 again.
    let mut feed2 = store.watch(Some(resume_token)).await.unwrap();
    let next = timeout(Duration::from_secs(5), feed2.next())
        .await
        .expect("yields")
        .unwrap()
        .unwrap();
    assert!(
        matches!(&next.change, Change::Upsert(p) if p.sub == "u2"),
        "resume skips the already-seen u1 and continues at u2"
    );
}
