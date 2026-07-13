//! Integration tests for `PgRoutingStore` against a real Postgres.
//!
//! These exercise the SQL paths the unit tests can't — most importantly the
//! nexus-owned-workspace-tenancy §6.3 **transfer** contract (repoint ownership +
//! reset staff atomically, customer memberships and routing/data ride through) and
//! the provisioning-idempotency create contract (keyed replay returns the ORIGINAL
//! row, same-key racers resolve to one row, keyless creates never conflict,
//! reconfigure never creates).
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

use router_core::auth::RouteAuth;
use router_core::domain::{Pool, WorkspaceConfig};
use router_core::normalize::{normalize_host, parent_domain};
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
        name: format!("{id} display name"),
        plan: "free".to_owned(),
        target_pool: Pool::new("application"),
        features: vec![],
        updated_at: None,
    }
}

/// Keyless create (the common seed path in these tests): every call inserts.
async fn seed_workspace(store: &PgRoutingStore, id: &str) {
    let outcome = store.create_workspace(&workspace(id), None).await.unwrap();
    assert!(outcome.created, "keyless seed create must insert");
    assert_eq!(outcome.id, id, "seed create returns the supplied id");
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

/// Resolve a host through the store exactly as `AppState::resolve` does
/// (tenant-router `main.rs`): normalize, one EXACT point read, then — only on a
/// miss — one SINGLE-LABEL WILDCARD-parent point read; a non-conforming host is
/// no-match before any read. This mirrors the hot path so the store-layer guard
/// tests pin the same exact→wildcard→fail-closed ordering the router enforces
/// (domain-host-resolution). It is the store contract under test, not a second
/// matcher.
async fn resolve_via_store(store: &PgRoutingStore, host: &str) -> Option<String> {
    let key = normalize_host(host);
    if key.is_empty() {
        return None;
    }
    match store.lookup_domain(&key, false).await.unwrap() {
        Some(ws) => Some(ws),
        None => match parent_domain(&key) {
            Some(parent) => store.lookup_domain(&parent, true).await.unwrap(),
            None => None,
        },
    }
}

#[tokio::test]
async fn apex_and_wildcard_coexist_and_route_to_their_own_workspaces() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // domain-host-resolution: the apex (exact row) and its wildcard (wildcard row)
    // are INDEPENDENT entries for the same domain string — the composite
    // (domain, is_wildcard) key lets both exist at once. Seed apex→A, wildcard→B.
    seed_workspace(&store, "ws_apex").await;
    seed_workspace(&store, "ws_wild").await;
    store.upsert_domain("example.com", "ws_apex", false, true).await.unwrap();
    store.upsert_domain("example.com", "ws_wild", true, true).await.unwrap();

    // The apex resolves to its exact workspace (A), NOT via the wildcard...
    assert_eq!(
        resolve_via_store(&store, "example.com").await.as_deref(),
        Some("ws_apex"),
        "apex resolves to its own exact row, not the wildcard",
    );
    // ...and a subdomain with no exact row resolves via the parent wildcard (B).
    assert_eq!(
        resolve_via_store(&store, "shop.example.com").await.as_deref(),
        Some("ws_wild"),
        "a subdomain resolves via the parent's wildcard row",
    );

    // A wildcard alone must never answer the apex: drop the exact row and the
    // apex now fails closed even though the wildcard still covers subdomains.
    store.delete_domain("example.com", false).await.unwrap();
    assert_eq!(
        resolve_via_store(&store, "example.com").await,
        None,
        "a wildcard does not cover the apex itself (TLS-wildcard semantics)",
    );
    assert_eq!(
        resolve_via_store(&store, "shop.example.com").await.as_deref(),
        Some("ws_wild"),
        "the wildcard still answers its subdomains after the apex row is gone",
    );
}

#[tokio::test]
async fn an_exact_row_beats_a_covering_wildcard() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // domain-host-resolution (most-specific-wins): an exact row for the subdomain
    // must take precedence over a wildcard that would otherwise cover it.
    seed_workspace(&store, "ws_exact").await;
    seed_workspace(&store, "ws_wild").await;
    store.upsert_domain("example.com", "ws_wild", true, true).await.unwrap();
    store.upsert_domain("shop.example.com", "ws_exact", false, true).await.unwrap();

    // shop.example.com has both an exact row (A) and a covering wildcard (B) —
    // the exact-first read wins and the wildcard hop never runs.
    assert_eq!(
        resolve_via_store(&store, "shop.example.com").await.as_deref(),
        Some("ws_exact"),
        "the exact row wins over the covering wildcard",
    );
    // A sibling with no exact row still falls through to the wildcard.
    assert_eq!(
        resolve_via_store(&store, "blog.example.com").await.as_deref(),
        Some("ws_wild"),
        "a sibling without an exact row still resolves via the wildcard",
    );
}

#[tokio::test]
async fn wildcard_matching_is_single_label_only() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // domain-host-resolution (single-label depth): a wildcard matches ONLY hosts
    // exactly one label below it. `a.b.example.com` is two labels below
    // `example.com`, so the `example.com` wildcard must NOT answer it.
    seed_workspace(&store, "ws_top").await;
    store.upsert_domain("example.com", "ws_top", true, true).await.unwrap();
    assert_eq!(
        resolve_via_store(&store, "a.b.example.com").await,
        None,
        "a two-label-deep host is not covered by the top wildcard",
    );

    // Coverage of the deeper host requires a wildcard at ITS OWN parent
    // (`b.example.com`); then the single-label hop resolves it.
    seed_workspace(&store, "ws_deep").await;
    store.upsert_domain("b.example.com", "ws_deep", true, true).await.unwrap();
    assert_eq!(
        resolve_via_store(&store, "a.b.example.com").await.as_deref(),
        Some("ws_deep"),
        "a wildcard at the host's own parent covers its single-label children",
    );
}

#[tokio::test]
async fn an_unknown_host_fails_closed_to_no_tenant() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // domain-host-resolution (fail-closed): a host with neither an exact row nor a
    // matching parent wildcard resolves to NO tenant — never a default/catch-all.
    // Seed an unrelated domain so the store is non-empty (a populated store must
    // still refuse an unknown host).
    seed_workspace(&store, "ws_known").await;
    store.upsert_domain("known.example.com", "ws_known", false, true).await.unwrap();

    assert_eq!(
        resolve_via_store(&store, "unknown.other.com").await,
        None,
        "an unknown host resolves to no tenant, not a default",
    );
    // A non-conforming host is refused before any lookup — same no-tenant result.
    assert_eq!(
        resolve_via_store(&store, "ex ample.com").await,
        None,
        "a non-conforming host fails closed without a lookup",
    );
}

#[tokio::test]
async fn transfer_repoints_ownership_and_resets_staff_only() {
    let (store, pool, _guard) = skip_if_no_db!();

    // Two owning accounts; ws_1 starts owned by the old account.
    assert!(store.create_account("acct_old", "Old", None, None).await.unwrap().created);
    assert!(store.create_account("acct_new", "New", None, None).await.unwrap().created);
    seed_workspace(&store, "ws_1").await;
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
    assert!(store.create_account("acct_old", "Old", Some("payer_old"), None).await.unwrap().created);
    assert!(store.create_account("acct_new", "New", Some("payer_new"), None).await.unwrap().created);
    let mut ws = workspace("ws_pro");
    ws.plan = "pro".to_owned();
    assert!(store.create_workspace(&ws, None).await.unwrap().created);
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
    assert!(store.create_workspace(&ws, None).await.unwrap().created);
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
async fn keyed_account_replay_returns_the_original_and_never_clobbers() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // provisioning-idempotency: replaying an idempotency key returns the ORIGINAL
    // account (its id, `created: false`) and never overwrites its name/payer —
    // this is what keeps signup provisioning safe to call unconditionally.
    let first = store
        .create_account("acct_1", "First", Some("payer_1"), Some("signup:sub-a"))
        .await
        .unwrap();
    assert!(first.created, "first keyed create inserts");
    assert_eq!(first.id, "acct_1");

    // The replay arrives with a FRESH minted id (the handler mints per request) —
    // the key, not the id, is what replays.
    let replay = store
        .create_account("acct_2", "Imposter", Some("payer_2"), Some("signup:sub-a"))
        .await
        .unwrap();
    assert!(!replay.created, "replay reports no insert");
    assert_eq!(replay.id, "acct_1", "replay returns the ORIGINAL id");
    assert!(store.get_account("acct_2").await.unwrap().is_none(), "no second account minted");

    let acct = store.get_account("acct_1").await.unwrap().expect("account exists");
    assert_eq!(acct.name, "First", "name not clobbered by a replay");
    assert_eq!(acct.payer_ref.as_deref(), Some("payer_1"), "payer not clobbered");
}

#[tokio::test]
async fn concurrent_same_key_creates_resolve_to_one_account() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // provisioning-idempotency (race scenario): two same-key creates racing on
    // separate connections yield exactly one row, and BOTH callers receive its id.
    let (left, right) = tokio::join!(
        store.create_account("acct_l", "Left", None, Some("signup:racer")),
        store.create_account("acct_r", "Right", None, Some("signup:racer")),
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(
        [left.created, right.created].iter().filter(|c| **c).count(),
        1,
        "exactly one racer inserts"
    );
    assert_eq!(left.id, right.id, "both racers receive the same id");
}

#[tokio::test]
async fn keyless_creates_never_conflict() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // A NULL idempotency key opts out of replay protection: every keyless create
    // inserts (UNIQUE treats NULLs as distinct)...
    assert!(store.create_account("acct_a", "Same Name", None, None).await.unwrap().created);
    assert!(store.create_account("acct_b", "Same Name", None, None).await.unwrap().created);
    // ...and creation never overwrites: same display name, two distinct resources
    // (workspace-tenancy: display names carry no identity semantics).
    assert!(store.get_account("acct_a").await.unwrap().is_some());
    assert!(store.get_account("acct_b").await.unwrap().is_some());

    let mut ws_first = workspace("ws_a");
    let mut ws_second = workspace("ws_b");
    ws_first.name = "Same Name".to_owned();
    ws_second.name = "Same Name".to_owned();
    assert!(store.create_workspace(&ws_first, None).await.unwrap().created);
    assert!(store.create_workspace(&ws_second, None).await.unwrap().created);
}

#[tokio::test]
async fn keyed_workspace_replay_returns_the_original_untouched() {
    let (store, _pool, _guard) = skip_if_no_db!();

    let created = store.create_workspace(&workspace("ws_orig"), Some("flow:one")).await.unwrap();
    assert!(created.created);

    // Replay with a fresh minted id AND different config: the original row rides
    // through untouched (create never overwrites).
    let mut differing = workspace("ws_other");
    differing.plan = "pro".to_owned();
    let replay = store.create_workspace(&differing, Some("flow:one")).await.unwrap();
    assert!(!replay.created, "replay reports no insert");
    assert_eq!(replay.id, "ws_orig", "replay returns the ORIGINAL id");
    let row = store.get_workspace("ws_orig").await.unwrap().expect("original survives");
    assert_eq!(row.plan, "free", "replay must not reconfigure the original");
    assert!(store.get_workspace("ws_other").await.unwrap().is_none(), "no ghost row");
}

#[tokio::test]
async fn update_workspace_reconfigures_but_never_creates() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // provisioning-idempotency: reconfiguring an unknown id matches nothing —
    // it must NOT create (the caller 404s instead of minting a ghost).
    assert!(
        !store.update_workspace(&workspace("ws_ghost")).await.unwrap(),
        "unknown id matches zero rows"
    );
    assert!(store.get_workspace("ws_ghost").await.unwrap().is_none(), "nothing created");

    // The happy path updates config but leaves the display name alone (name is
    // create-time data; PUT carries no name).
    seed_workspace(&store, "ws_cfg").await;
    let mut next = workspace("ws_cfg");
    next.plan = "pro".to_owned();
    next.name = "ignored by update".to_owned();
    assert!(store.update_workspace(&next).await.unwrap(), "existing row matched");
    let after = store.get_workspace("ws_cfg").await.unwrap().expect("row survives");
    assert_eq!(after.plan, "pro", "plan reconfigured");
    assert_eq!(after.name, "ws_cfg display name", "display name untouched by update");
}

#[tokio::test]
async fn transfer_of_unknown_workspace_is_none() {
    let (store, _pool, _guard) = skip_if_no_db!();
    let _ = store.create_account("acct_new", "New", None, None).await.unwrap();
    assert_eq!(store.transfer_workspace("ghost", "acct_new").await.unwrap(), None);
}

#[tokio::test]
async fn auth_route_requirement_fields_round_trip() {
    let (store, _pool, _guard) = skip_if_no_db!();
    seed_workspace(&store, "ws_auth").await;

    // A phase-1 rule (no requirements) and a phase-2 gated rule.
    let plain = RouteAuth { required: true, ..RouteAuth::PASS_THROUGH };
    let gated = RouteAuth {
        required: true,
        requires_role: Some("admin".to_owned()),
        requires_entitlement: Some("pro".to_owned()),
        min_aal: Some(2),
        ..RouteAuth::PASS_THROUGH
    };
    // identity-existence-hiding: an account-scoped protected rule (e.g. /me).
    let account = RouteAuth { required: true, account_scoped: true, ..RouteAuth::PASS_THROUGH };
    store.upsert_auth_route("ws_auth", "/", &plain).await.unwrap();
    store.upsert_auth_route("ws_auth", "/admin", &gated).await.unwrap();
    store.upsert_auth_route("ws_auth", "/me", &account).await.unwrap();

    let policy = store.get_auth_policy("ws_auth").await.unwrap();
    let hit = policy.resolve("/admin/users");
    assert_eq!(hit.requires_role.as_deref(), Some("admin"));
    assert_eq!(hit.requires_entitlement.as_deref(), Some("pro"));
    assert_eq!(hit.min_aal, Some(2));
    assert!(!hit.account_scoped, "a gated workspace rule is not account-scoped");
    let miss = policy.resolve("/pricing");
    assert!(miss.required && !miss.has_requirements(), "phase-1 rule carries no requirements");
    // account_scoped survives the round-trip through the store.
    assert!(policy.resolve("/me").account_scoped, "account-scoped rule persisted");
    assert!(!policy.resolve("/pricing").account_scoped, "default is workspace-scoped");

    // Upserting the gated rule back to plain clears the requirement columns.
    store.upsert_auth_route("ws_auth", "/admin", &plain).await.unwrap();
    let cleared = store.get_auth_policy("ws_auth").await.unwrap();
    assert!(!cleared.resolve("/admin").has_requirements());
}
