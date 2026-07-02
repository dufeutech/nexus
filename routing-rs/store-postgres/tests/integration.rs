//! Integration tests for `PgRoutingStore` against a real Postgres.
//!
//! These exercise the SQL paths the unit tests can't — most importantly the
//! nexus-owned-workspace-tenancy §6.3 **transfer** contract (repoint ownership +
//! reset staff atomically, customer memberships and routing/data ride through) and
//! the §5.1 **account backfill** (a legacy ownerless workspace is auto-owned by a
//! solo account on `init_schema`).
//!
//! Gated on `STORE_PG_TEST_URL` so `cargo test` stays green on a machine with no
//! database: unset → each test prints a skip line and returns. Point it at a
//! THROWAWAY Postgres (the tests create the `routing` schema and TRUNCATE its
//! tables), e.g.:
//!
//!   docker run --rm -d -p 5433:5432 -e POSTGRES_PASSWORD=postgres --name pgtest postgres:16-alpine
//!   STORE_PG_TEST_URL=postgres://postgres:postgres@localhost:5433/postgres \
//!     cargo test -p store-postgres --test integration -- --test-threads=1
//!
//! All tests share the one `routing` schema and each begins by truncating it, so
//! they must not interleave: `setup()` serializes them behind a process-wide lock
//! (held via the returned guard), so a plain `cargo test` — CI included — is safe
//! without `--test-threads=1`.

use std::env;

use router_core::domain::{Pool, WorkspaceConfig};
use router_core::store::{
    Membership, MembershipStore, OwnershipStore, RoutingStore,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use store_postgres::PgRoutingStore;
use tokio::sync::{Mutex, MutexGuard};

/// Serializes the tests: they share one schema and truncate it in `setup()`, so
/// two running at once would eat each other's rows. tokio's Mutex works across
/// the per-test runtimes (`#[tokio::test]` builds one per test).
static DB_LOCK: Mutex<()> = Mutex::const_new(());

/// Connect + clean every `routing` table, or `None` if the test DB isn't set.
/// The returned guard holds the schema for the duration of the test.
async fn setup() -> Option<(PgRoutingStore, sqlx::PgPool, MutexGuard<'static, ()>)> {
    let url = env::var("STORE_PG_TEST_URL").ok()?;
    let guard = DB_LOCK.lock().await;
    let store = PgRoutingStore::connect(&url)
        .await
        .expect("connect to STORE_PG_TEST_URL");
    store.init_schema().await.expect("init_schema");
    // Aux pool for direct assertions/seed the port doesn't expose (e.g. reading a
    // workspace's account_id, seeding an ownerless legacy row).
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("aux pool");
    // Start every test from a clean slate. CASCADE + naming every table clears the
    // FK-linked graph regardless of order.
    sqlx::query(
        "TRUNCATE routing.accounts, routing.account_members, routing.workspaces, \
         routing.domains, routing.domain_challenges, routing.auth_routes, \
         routing.memberships RESTART IDENTITY CASCADE",
    )
    .execute(&pool)
    .await
    .expect("truncate");
    Some((store, pool, guard))
}

macro_rules! skip_if_no_db {
    () => {
        match setup().await {
            Some(pair) => pair,
            None => {
                eprintln!("SKIP: set STORE_PG_TEST_URL to run this integration test");
                return;
            }
        }
    };
}

fn workspace(id: &str) -> WorkspaceConfig {
    WorkspaceConfig {
        workspace_id: id.to_owned(),
        plan: "free".to_owned(),
        target_pool: Pool::new("application"),
        features: vec![],
        updated_at: None,
    }
}

fn membership(sub: &str, ws: &str, member_type: &str, role: &str) -> Membership {
    Membership {
        user_sub: sub.to_owned(),
        workspace_id: ws.to_owned(),
        member_type: member_type.to_owned(),
        role: role.to_owned(),
        status: "active".to_owned(),
    }
}

/// Read a workspace's owning account directly (the `RoutingStore` port intentionally
/// keeps `account_id` off the hot-path `WorkspaceConfig`, so the test reads the row).
async fn workspace_account(pool: &sqlx::PgPool, ws: &str) -> Option<String> {
    sqlx::query("SELECT account_id FROM routing.workspaces WHERE workspace_id = $1")
        .bind(ws)
        .fetch_one(pool)
        .await
        .expect("workspace row")
        .get::<Option<String>, _>("account_id")
}

#[tokio::test]
async fn transfer_repoints_ownership_and_resets_staff_only() {
    let (store, pool, _guard) = skip_if_no_db!();

    // Two owning accounts; ws_1 starts owned by the old account.
    assert!(store.create_account("acct_old", "Old", None).await.unwrap());
    assert!(store.create_account("acct_new", "New", None).await.unwrap());
    store.upsert_workspace(&workspace("ws_1")).await.unwrap();
    assert!(store.set_workspace_account("ws_1", "acct_old").await.unwrap());

    // A verified domain (routing state) + a staff and a customer membership.
    store.upsert_domain("app.example.com", "ws_1", false, true).await.unwrap();
    store.upsert_membership(&membership("staff_a", "ws_1", "staff", "admin")).await.unwrap();
    store.upsert_membership(&membership("cust_b", "ws_1", "customer", "buyer")).await.unwrap();

    // Transfer to the new account: one staff membership removed.
    let removed = store.transfer_workspace("ws_1", "acct_new").await.unwrap();
    assert_eq!(removed, Some(1), "exactly the one staff membership is reset");

    // Ownership repointed...
    assert_eq!(workspace_account(&pool, "ws_1").await.as_deref(), Some("acct_new"));
    // ...routing rides through untouched (domain still resolves ws_1)...
    assert_eq!(
        store.lookup_domain("app.example.com", false).await.unwrap().as_deref(),
        Some("ws_1"),
    );
    // ...customer membership survives, staff is gone.
    let mut left: Vec<(String, String)> = store
        .memberships_for_workspace("ws_1")
        .await
        .unwrap()
        .into_iter()
        .map(|m| (m.user_sub, m.member_type))
        .collect();
    left.sort();
    assert_eq!(left, vec![("cust_b".to_owned(), "customer".to_owned())]);
}

#[tokio::test]
async fn transfer_preserves_plan_and_switches_payer_to_the_new_account() {
    let (store, pool, _guard) = skip_if_no_db!();

    // workspace-tenancy R4: plan lives on the WORKSPACE (it travels with a
    // transfer); payer lives on the ACCOUNT (it switches with a transfer). Two
    // accounts with distinct payers of record; ws_pro starts on the old one.
    assert!(store.create_account("acct_old", "Old", Some("payer_old")).await.unwrap());
    assert!(store.create_account("acct_new", "New", Some("payer_new")).await.unwrap());
    let mut ws = workspace("ws_pro");
    ws.plan = "pro".to_owned();
    store.upsert_workspace(&ws).await.unwrap();
    assert!(store.set_workspace_account("ws_pro", "acct_old").await.unwrap());

    store.transfer_workspace("ws_pro", "acct_new").await.unwrap();

    // Plan travels: the workspace still carries `pro` — a transfer must never
    // reset or re-derive it from the receiving account.
    let after = store.get_workspace("ws_pro").await.unwrap().expect("workspace survives");
    assert_eq!(after.plan, "pro", "plan travels with the workspace");

    // Payer switches: the workspace is now owned by the account whose payer of
    // record is `payer_new`; the old payer is no longer on the hook.
    assert_eq!(workspace_account(&pool, "ws_pro").await.as_deref(), Some("acct_new"));
    let payer = store
        .get_account("acct_new")
        .await
        .unwrap()
        .expect("new owning account")
        .payer_ref;
    assert_eq!(payer.as_deref(), Some("payer_new"), "payer switches to the new account's");
    // The transfer mutates ownership only — it must not clobber either
    // account's payer of record.
    let old_payer = store.get_account("acct_old").await.unwrap().expect("old account").payer_ref;
    assert_eq!(old_payer.as_deref(), Some("payer_old"));
}

#[tokio::test]
async fn domains_are_aliases_and_removal_leaves_the_workspace_intact() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // workspace-tenancy R1: the workspace_id is the stable identity; domains are
    // detachable aliases. Several domains resolve to ONE workspace…
    let mut ws = workspace("ws_alias");
    ws.plan = "pro".to_owned();
    store.upsert_workspace(&ws).await.unwrap();
    store.upsert_domain("a.example.com", "ws_alias", false, true).await.unwrap();
    store.upsert_domain("b.example.com", "ws_alias", false, true).await.unwrap();
    assert_eq!(store.lookup_domain("a.example.com", false).await.unwrap().as_deref(), Some("ws_alias"));
    assert_eq!(store.lookup_domain("b.example.com", false).await.unwrap().as_deref(), Some("ws_alias"));

    // …and removing one alias leaves the workspace (and its config) untouched
    // while the other alias keeps resolving.
    store.delete_domain("a.example.com", false).await.unwrap();
    assert_eq!(store.lookup_domain("a.example.com", false).await.unwrap(), None, "removed alias stops resolving");
    assert_eq!(store.lookup_domain("b.example.com", false).await.unwrap().as_deref(), Some("ws_alias"));
    let survivor = store.get_workspace("ws_alias").await.unwrap().expect("workspace survives alias removal");
    assert_eq!(survivor.plan, "pro", "workspace config rides through the alias change");
}

#[tokio::test]
async fn create_account_is_idempotent_and_never_clobbers() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // workspace-tenancy R2: a repeat provision for an existing account is a
    // no-op — it must never overwrite the account's name or payer of record.
    assert!(store.create_account("acct_1", "First", Some("payer_1")).await.unwrap());
    assert!(
        !store.create_account("acct_1", "Imposter", Some("payer_2")).await.unwrap(),
        "second provision reports no-op"
    );
    let acct = store.get_account("acct_1").await.unwrap().expect("account exists");
    assert_eq!(acct.name, "First", "name not clobbered by a repeat provision");
    assert_eq!(acct.payer_ref.as_deref(), Some("payer_1"), "payer not clobbered");
}

#[tokio::test]
async fn transfer_of_unknown_workspace_is_none() {
    let (store, _pool, _guard) = skip_if_no_db!();
    store.create_account("acct_new", "New", None).await.unwrap();
    assert_eq!(store.transfer_workspace("ghost", "acct_new").await.unwrap(), None);
}

#[tokio::test]
async fn init_schema_backfills_a_solo_account_for_an_ownerless_workspace() {
    let (store, pool, _guard) = skip_if_no_db!();

    // A legacy row: a workspace with no owning account (upsert_workspace does not
    // set account_id — create-time ownership is a separate call, and a migrated
    // `tenants` row had none).
    store.upsert_workspace(&workspace("legacy_ws")).await.unwrap();
    assert_eq!(workspace_account(&pool, "legacy_ws").await, None, "ownerless before backfill");

    // Re-running the idempotent bootstrap runs the backfill.
    store.init_schema().await.unwrap();

    // A solo account keyed by the workspace_id now owns it...
    assert_eq!(workspace_account(&pool, "legacy_ws").await.as_deref(), Some("legacy_ws"));
    assert!(store.get_account("legacy_ws").await.unwrap().is_some(), "solo account provisioned");

    // ...and it is idempotent: a second pass neither errors nor re-owns it.
    store.init_schema().await.unwrap();
    assert_eq!(workspace_account(&pool, "legacy_ws").await.as_deref(), Some("legacy_ws"));
}
