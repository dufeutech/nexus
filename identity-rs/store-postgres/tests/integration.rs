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
//! All tests share the one `identity` schema and each begins by truncating it, so
//! they must not interleave: `setup()` serializes them behind a process-wide lock
//! (held via the returned guard), so a plain `cargo test` — CI included — is safe
//! without `--test-threads=1`.

use std::env;
use std::time::Duration;

use futures::StreamExt;
use identity_core::authz::{AuthzAuthoring, AuthzResolver};
use identity_core::membership::{MemberType, Membership, SourceMembershipReader};
use identity_core::store::{Change, ProfileStore};
use identity_core::Profile;
use sqlx::postgres::PgPoolOptions;
use store_postgres::{PgProfileStore, PgSourceMembershipReader};
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::{sleep, timeout};

/// Serializes the tests: they share one database and truncate shared tables in
/// their setup, so two running at once would eat each other's rows. tokio's
/// Mutex works across the per-test runtimes (`#[tokio::test]` builds one each).
static DB_LOCK: Mutex<()> = Mutex::const_new(());

/// Connect + clean the shared table, or `None` if the test DB isn't configured.
/// The returned guard holds the database for the duration of the test.
async fn setup() -> Option<(PgProfileStore, MutexGuard<'static, ()>)> {
    let url = env::var("STORE_PG_TEST_URL").ok()?;
    let guard = DB_LOCK.lock().await;
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
    Some((store, guard))
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
    let (store, _guard) = skip_if_no_db!(store);
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
    let (store, _guard) = skip_if_no_db!(store);
    store.put(&profile("u1", false)).await.unwrap();
    store.put(&profile("u1", true)).await.unwrap();
    let got = store.get("u1").await.unwrap().unwrap();
    assert!(got.is_suspended, "second put overwrote the first");
}

#[tokio::test]
async fn delete_tombstones_and_hides_from_reads() {
    let (store, _guard) = skip_if_no_db!(store);
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
    let (store, _guard) = skip_if_no_db!(store);
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
    let (store, _guard) = skip_if_no_db!(store);
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
    let (store, _guard) = skip_if_no_db!(store);
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
    let (store, _guard) = skip_if_no_db!(store);
    // `None` = from now: the feed should pick up only writes made AFTER it opens.
    let mut feed = store.watch(None).await.unwrap();

    // Give the listener a moment to be established.
    sleep(Duration::from_millis(200)).await;

    // Write → observe, one state at a time. The feed is COMPACTED per key (one
    // row per subject; a drain replays the row's CURRENT state), so firing all
    // three writes first would legitimately collapse them into fewer events —
    // sequencing each write behind the previous event keeps every intermediate
    // state observable while still exercising live NOTIFY delivery.
    macro_rules! next_change {
        () => {
            timeout(Duration::from_secs(5), feed.next())
                .await
                .expect("live feed yields within 5s")
                .expect("stream not ended")
                .expect("change event ok")
                .change
        };
    }

    store.put(&profile("live1", false)).await.unwrap();
    let created = next_change!();
    assert!(matches!(&created, Change::Upsert(p) if p.sub == "live1" && !p.is_suspended));

    store.put(&profile("live1", true)).await.unwrap(); // suspension upsert
    let suspended = next_change!();
    assert!(matches!(&suspended, Change::Upsert(p) if p.is_suspended), "suspension lands as an upsert");

    store.delete("live1").await.unwrap();
    let deleted = next_change!();
    assert!(matches!(&deleted, Change::Delete(sub) if sub == "live1"));
}

/// Create a minimal `routing.memberships` table (subset of the routing store's
/// DDL — the columns the reader selects) and seed it, or `None` if no test DB.
/// Returns a read-only reader over the same URL.
async fn setup_routing_memberships() -> Option<(PgSourceMembershipReader, MutexGuard<'static, ()>)> {
    let url = env::var("STORE_PG_TEST_URL").ok()?;
    let guard = DB_LOCK.lock().await;
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
    Some((
        PgSourceMembershipReader::connect(&url)
            .await
            .expect("connect reader"),
        guard,
    ))
}

#[tokio::test]
async fn reader_projects_active_memberships_only() {
    let (reader, _guard) = skip_if_no_routing_db!(reader);
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

// --------------------------------------------------------------------------- //
// Nexus-native authorization adapter (nexus-native-authorization).
// --------------------------------------------------------------------------- //

/// spec R2 + R3/R4 mechanism: an absent subject resolves to deny-by-default facts;
/// authoring assigns/revokes and the resolver reflects it (read-merge-write).
/// Idempotent assign; suspend/reactivate flip the live flag.
#[tokio::test]
async fn authz_authoring_roundtrip_and_facts() {
    let (store, _guard) = skip_if_no_db!(store);

    // Absent subject → deny-by-default zero value (spec R2), never an error.
    let absent = store.facts("u1").await.unwrap();
    assert!(absent.roles.is_empty() && absent.entitlements.is_empty() && !absent.is_suspended);

    // Authoring creates the row and reflects each fact (spec R4).
    store.assign_role("u1", "admin").await.unwrap();
    store.assign_role("u1", "admin").await.unwrap(); // idempotent — no duplicate
    store.grant_entitlement("u1", "pro").await.unwrap();
    store.suspend("u1").await.unwrap();
    let authored = store.facts("u1").await.unwrap();
    assert_eq!(authored.roles, vec!["admin".to_owned()], "role assigned once");
    assert_eq!(authored.entitlements, vec!["pro".to_owned()]);
    assert!(authored.is_suspended);
    assert!(store.has_role("u1", "admin").await.unwrap());
    assert!(!store.has_role("u1", "viewer").await.unwrap());

    // Revocation clears each fact (spec R3: a revoked grant stops being effective).
    store.revoke_role("u1", "admin").await.unwrap();
    store.revoke_entitlement("u1", "pro").await.unwrap();
    store.reactivate("u1").await.unwrap();
    let cleared = store.facts("u1").await.unwrap();
    assert!(cleared.roles.is_empty() && cleared.entitlements.is_empty() && !cleared.is_suspended);
    // Revoking an unheld role is a no-op (idempotent), not an error.
    store.revoke_role("u1", "never-held").await.unwrap();
}

/// spec R3 mechanism (revocation within seconds) + task 2.3 no-clobber: an authz
/// write preserves memberships/identity AND emits the change-feed signal the sidecar
/// consumes, so a grant/suspend propagates over the SAME feed within seconds.
#[tokio::test]
async fn authz_authoring_preserves_memberships_and_emits_feed() {
    let (store, _guard) = skip_if_no_db!(store);
    // A profile already carries a membership projection + display identity.
    let base = Profile {
        sub: "u1".into(),
        username: Some("alice".into()),
        memberships: vec![Membership {
            workspace_id: "ws-a".into(),
            member_type: MemberType::Staff,
            role: "admin".into(),
            entitlements: vec![],
        }],
        ..Default::default()
    };
    store.put(&base).await.unwrap();

    // Open the feed from now, then author a role — the sidecar's live-update path.
    let mut feed = store.watch(None).await.unwrap();
    sleep(Duration::from_millis(200)).await;
    store.suspend("u1").await.unwrap();

    let ev = timeout(Duration::from_secs(5), feed.next())
        .await
        .expect("feed yields within 5s")
        .expect("stream not ended")
        .expect("change event ok");
    // The feed emits the FULL updated profile: suspension applied, but the membership
    // projection + display identity preserved (no clobber — task 2.3).
    assert!(
        matches!(&ev.change, Change::Upsert(p)
            if p.is_suspended
            && p.username.as_deref() == Some("alice")
            && p.memberships.len() == 1
            && p.memberships.first().map(|m| m.workspace_id.as_str()) == Some("ws-a")),
        "authored suspension reached the feed with membership + display preserved (no clobber)"
    );
}

/// spec R4 bootstrap gate: `any_subject_has_role` is false on an empty store and
/// true once an admin is authored — the exact query the authz-admin bootstrap uses
/// to seed the first administrator iff none exists.
#[tokio::test]
async fn any_subject_has_role_backs_the_bootstrap_gate() {
    let (store, _guard) = skip_if_no_db!(store);
    assert!(!store.any_subject_has_role("admin").await.unwrap(), "no admin on an empty store");
    store.assign_role("boot", "admin").await.unwrap();
    assert!(store.any_subject_has_role("admin").await.unwrap(), "admin now exists");
    assert!(!store.any_subject_has_role("superuser").await.unwrap(), "only the authored role matches");
    // A suspended admin still counts (present, not deleted); a fully revoked one does not.
    store.suspend("boot").await.unwrap();
    assert!(store.any_subject_has_role("admin").await.unwrap(), "suspended admin still holds the role");
    store.revoke_role("boot", "admin").await.unwrap();
    assert!(!store.any_subject_has_role("admin").await.unwrap(), "revoked → no admin remains");
}

#[tokio::test]
async fn watch_token_resumes_without_duplicates() {
    let (store, _guard) = skip_if_no_db!(store);
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

/// Pull the next real change signal (a `key_id`) off the api-key eviction feed, skipping
/// the periodic `Ok(None)` poll heartbeats.
async fn next_key_id(feed: &mut store_postgres::ApiKeyChangeFeed) -> String {
    loop {
        let item = timeout(Duration::from_secs(5), feed.next())
            .await
            .expect("api-key feed yields within 5s")
            .expect("stream not ended")
            .expect("feed item ok");
        if let Some(id) = item {
            return id;
        }
        // Ok(None) = poll heartbeat; keep waiting for the real signal.
    }
}

#[tokio::test]
async fn api_key_change_feed_delivers_affected_key_id_on_mutation() {
    // apikey-resolve-cache tasks 6.3/6.4/6.6 (mechanism): the `api_key_changes` feed the
    // resolve-cache evicts on MUST deliver the affected key_id for a live mutation, so a
    // revoke/rotate drives targeted single-entry eviction within seconds (a dropped signal
    // otherwise self-heals via the cache TTL, exercised in the sidecar unit tests).
    use std::sync::Arc;
    // Share the process-wide DB lock + identity-schema bootstrap; the api-key table is set
    // up below on the same URL.
    let (_store, _guard) = skip_if_no_db!(store);
    let url = env::var("STORE_PG_TEST_URL").expect("checked by skip_if_no_db");

    // The api-key WRITER owns the api_keys table + its change-notify trigger.
    let hasher: Arc<dyn identity_core::SecretHasher> =
        Arc::new(store_postgres::HmacSecretHasher::new(b"test-pepper".to_vec()));
    let keys = store_postgres::PgApiKeyStore::connect(&url, hasher)
        .await
        .expect("connect api-key store");
    keys.init_schema().await.expect("init api_keys schema");
    // Clean slate so the first post-open signal is deterministic.
    let pool = PgPoolOptions::new().max_connections(1).connect(&url).await.expect("aux pool");
    sqlx::query("TRUNCATE identity.api_keys").execute(&pool).await.expect("truncate api_keys");

    // Open the eviction feed FROM NOW, then let the LISTEN establish.
    let mut feed = store_postgres::PgApiKeyReader::watch_changes(&url, Duration::from_secs(5))
        .await
        .expect("open api-key change feed");
    sleep(Duration::from_millis(200)).await;

    // Issue → the INSERT fires a NOTIFY carrying the new key_id.
    let issued = keys
        .issue("u-creator", &["ws-1".to_owned()], None, 0)
        .await
        .expect("issue key");
    assert_eq!(next_key_id(&mut feed).await, issued.key_id, "the INSERT signal carries the new key_id");

    // Revoke → the UPDATE fires a NOTIFY carrying the SAME key_id (targeted eviction).
    assert!(keys.revoke(&issued.key_id).await.expect("revoke"));
    assert_eq!(next_key_id(&mut feed).await, issued.key_id, "the revoke signal carries the affected key_id");
}
