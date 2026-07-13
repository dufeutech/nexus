//! Integration tests for `PgRoutingStore` against a real Postgres.
//!
//! These exercise the SQL paths the unit tests can't — most importantly the
//! nexus-owned-workspace-tenancy §6.3 **transfer** contract (repoint ownership +
//! reset staff atomically, customer memberships and routing/data ride through),
//! the provisioning-idempotency create contract (keyed replay returns the
//! ORIGINAL row, same-key racers resolve to one row, keyless creates never
//! conflict, reconfigure never creates), and the admin-action-audit ledger
//! (every mutation records an event in the SAME transaction — an unrecordable
//! mutation rolls back — plus named-token issue/rotate/revoke and denials).
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

use router_core::audit::{
    AuditCtx, AuditEventRecord, AuditQuery, DenialEvent, DenialKind, InvalidQueryBound,
    OUTCOME_OK, OUTCOME_REPLAY,
};
use router_core::auth::RouteAuth;
use router_core::domain::{Pool, WorkspaceConfig};
use router_core::normalize::{normalize_host, parent_domain};
use router_core::store::{
    DomainUpsert, Membership, MembershipStore, NewAccount, OwnershipStore, RoutingStore,
};
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use store_postgres::{AdminTokenHasher, PgAdminTokenStore, PgRoutingStore};
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
         routing.memberships, routing.admin_audit_events, routing.admin_tokens \
         RESTART IDENTITY CASCADE",
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

/// The audit context every test mutation carries (admin-action-audit): a named
/// token id plus an asserted operator, so the recorded events can be asserted.
fn actx() -> AuditCtx {
    AuditCtx {
        actor: "atk_test".to_owned(),
        asserted_operator: Some("tester@example.com".to_owned()),
        trace_id: None,
        source_ip: Some("127.0.0.1".to_owned()),
    }
}

/// Query the ledger for one action's events (time-ordered).
async fn events_for_action(store: &PgRoutingStore, action: &str) -> Vec<AuditEventRecord> {
    store
        .query_audit_events(&AuditQuery::default())
        .await
        .expect("query audit events")
        .into_iter()
        .filter(|event| event.action == action)
        .collect()
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
    let outcome = store.create_workspace(&workspace(id), None, None, &actx()).await.unwrap();
    assert!(outcome.created, "keyless seed create must insert");
    assert_eq!(outcome.id, id, "seed create returns the supplied id");
}

/// Provision an account owned by `owner` (keyless).
async fn seed_account(store: &PgRoutingStore, id: &str, name: &str, payer: Option<&str>) {
    let outcome = store
        .provision_account(
            &NewAccount {
                account_id: id,
                name,
                payer_ref: payer,
                owner_sub: "owner_seed",
                idempotency_key: None,
            },
            &actx(),
        )
        .await
        .unwrap();
    assert!(outcome.created, "keyless seed provision must insert");
}

/// Admin domain write shorthand for the resolution tests.
async fn put_domain(store: &PgRoutingStore, domain: &str, ws: &str, wildcard: bool) {
    store
        .upsert_domain(
            &DomainUpsert { domain, workspace_id: ws, wildcard, verified: true },
            &actx(),
        )
        .await
        .unwrap();
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
    put_domain(&store, "example.com", "ws_apex", false).await;
    put_domain(&store, "example.com", "ws_wild", true).await;

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
    store.delete_domain("example.com", false, &actx()).await.unwrap();
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
    put_domain(&store, "example.com", "ws_wild", true).await;
    put_domain(&store, "shop.example.com", "ws_exact", false).await;

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
    put_domain(&store, "example.com", "ws_top", true).await;
    assert_eq!(
        resolve_via_store(&store, "a.b.example.com").await,
        None,
        "a two-label-deep host is not covered by the top wildcard",
    );

    // Coverage of the deeper host requires a wildcard at ITS OWN parent
    // (`b.example.com`); then the single-label hop resolves it.
    seed_workspace(&store, "ws_deep").await;
    put_domain(&store, "b.example.com", "ws_deep", true).await;
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
    put_domain(&store, "known.example.com", "ws_known", false).await;

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
    seed_account(&store, "acct_old", "Old", None).await;
    seed_account(&store, "acct_new", "New", None).await;
    let outcome = store
        .create_workspace(&workspace("ws_1"), Some("acct_old"), None, &actx())
        .await
        .unwrap();
    assert!(outcome.created);
    assert_eq!(workspace_account(&pool, "ws_1").await.as_deref(), Some("acct_old"));

    // A verified domain (routing state) + a staff and a customer membership.
    put_domain(&store, "app.example.com", "ws_1", false).await;
    store.upsert_membership(&membership("staff_a", "ws_1", "staff", "admin"), &actx()).await.unwrap();
    store.upsert_membership(&membership("cust_b", "ws_1", "customer", "buyer"), &actx()).await.unwrap();

    // Transfer to the new account: one staff membership removed.
    let removed = store.transfer_workspace("ws_1", "acct_new", &actx()).await.unwrap();
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

    // admin-action-audit: the transfer left exactly one ledger event, attributed
    // to the acting token, carrying the target and the staff-reset fact.
    let events = events_for_action(&store, "workspace.transfer").await;
    assert_eq!(events.len(), 1, "one transfer, one event");
    let event = &events[0];
    assert!(event.event_id.starts_with("aev_"), "typed event id: {}", event.event_id);
    assert_eq!(event.actor_token_id, "atk_test");
    assert_eq!(event.asserted_operator.as_deref(), Some("tester@example.com"));
    assert_eq!(event.target_id.as_deref(), Some("ws_1"));
    assert_eq!(event.outcome, OUTCOME_OK);
    assert_eq!(event.detail["staff_removed"], 1, "detail carries the reset count");
}

#[tokio::test]
async fn transfer_preserves_plan_and_switches_payer_to_the_new_account() {
    let (store, pool, _guard) = skip_if_no_db!();

    // workspace-tenancy R4: plan lives on the WORKSPACE (it travels with a
    // transfer); payer lives on the ACCOUNT (it switches with a transfer). Two
    // accounts with distinct payers of record; ws_pro starts on the old one.
    seed_account(&store, "acct_old", "Old", Some("payer_old")).await;
    seed_account(&store, "acct_new", "New", Some("payer_new")).await;
    let mut ws = workspace("ws_pro");
    ws.plan = "pro".to_owned();
    assert!(store.create_workspace(&ws, Some("acct_old"), None, &actx()).await.unwrap().created);

    store.transfer_workspace("ws_pro", "acct_new", &actx()).await.unwrap();

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
    assert!(store.create_workspace(&ws, None, None, &actx()).await.unwrap().created);
    put_domain(&store, "a.example.com", "ws_alias", false).await;
    put_domain(&store, "b.example.com", "ws_alias", false).await;
    assert_eq!(store.lookup_domain("a.example.com", false).await.unwrap().as_deref(), Some("ws_alias"));
    assert_eq!(store.lookup_domain("b.example.com", false).await.unwrap().as_deref(), Some("ws_alias"));

    // …and removing one alias leaves the workspace (and its config) untouched
    // while the other alias keeps resolving.
    store.delete_domain("a.example.com", false, &actx()).await.unwrap();
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
        .provision_account(
            &NewAccount {
                account_id: "acct_1",
                name: "First",
                payer_ref: Some("payer_1"),
                owner_sub: "sub-a",
                idempotency_key: Some("signup:sub-a"),
            },
            &actx(),
        )
        .await
        .unwrap();
    assert!(first.created, "first keyed create inserts");
    assert_eq!(first.id, "acct_1");

    // The replay arrives with a FRESH minted id (the handler mints per request) —
    // the key, not the id, is what replays.
    let replay = store
        .provision_account(
            &NewAccount {
                account_id: "acct_2",
                name: "Imposter",
                payer_ref: Some("payer_2"),
                owner_sub: "sub-a",
                idempotency_key: Some("signup:sub-a"),
            },
            &actx(),
        )
        .await
        .unwrap();
    assert!(!replay.created, "replay reports no insert");
    assert_eq!(replay.id, "acct_1", "replay returns the ORIGINAL id");
    assert!(store.get_account("acct_2").await.unwrap().is_none(), "no second account minted");

    let acct = store.get_account("acct_1").await.unwrap().expect("account exists");
    assert_eq!(acct.name, "First", "name not clobbered by a replay");
    assert_eq!(acct.payer_ref.as_deref(), Some("payer_1"), "payer not clobbered");

    // admin-action-audit spec "Idempotent replays are audited as replays": two
    // events for the two calls — the original `ok`, the replay `replay`, both
    // carrying the idempotency key, distinguishable and time-ordered.
    let events = events_for_action(&store, "account.provision").await;
    assert_eq!(events.len(), 2, "original AND replay each leave an event");
    assert_eq!(events[0].outcome, OUTCOME_OK);
    assert_eq!(events[1].outcome, OUTCOME_REPLAY, "the replay is marked as a replay");
    assert_eq!(events[1].target_id.as_deref(), Some("acct_1"), "replay targets the ORIGINAL");
    assert_eq!(events[0].idempotency_key.as_deref(), Some("signup:sub-a"));
    assert!(events[0].event_id < events[1].event_id, "aev_ ids sort by event time");
}

#[tokio::test]
async fn concurrent_same_key_creates_resolve_to_one_account() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // provisioning-idempotency (race scenario): two same-key creates racing on
    // separate connections yield exactly one row, and BOTH callers receive its id.
    let left_acct = NewAccount {
        account_id: "acct_l",
        name: "Left",
        payer_ref: None,
        owner_sub: "racer",
        idempotency_key: Some("signup:racer"),
    };
    let right_acct = NewAccount {
        account_id: "acct_r",
        name: "Right",
        payer_ref: None,
        owner_sub: "racer",
        idempotency_key: Some("signup:racer"),
    };
    let ctx = actx();
    let (left, right) = tokio::join!(
        store.provision_account(&left_acct, &ctx),
        store.provision_account(&right_acct, &ctx),
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
    seed_account(&store, "acct_a", "Same Name", None).await;
    seed_account(&store, "acct_b", "Same Name", None).await;
    // ...and creation never overwrites: same display name, two distinct resources
    // (workspace-tenancy: display names carry no identity semantics).
    assert!(store.get_account("acct_a").await.unwrap().is_some());
    assert!(store.get_account("acct_b").await.unwrap().is_some());

    let mut ws_first = workspace("ws_a");
    let mut ws_second = workspace("ws_b");
    ws_first.name = "Same Name".to_owned();
    ws_second.name = "Same Name".to_owned();
    assert!(store.create_workspace(&ws_first, None, None, &actx()).await.unwrap().created);
    assert!(store.create_workspace(&ws_second, None, None, &actx()).await.unwrap().created);
}

#[tokio::test]
async fn keyed_workspace_replay_returns_the_original_untouched() {
    let (store, _pool, _guard) = skip_if_no_db!();

    let created = store
        .create_workspace(&workspace("ws_orig"), None, Some("flow:one"), &actx())
        .await
        .unwrap();
    assert!(created.created);

    // Replay with a fresh minted id AND different config: the original row rides
    // through untouched (create never overwrites).
    let mut differing = workspace("ws_other");
    differing.plan = "pro".to_owned();
    let replay = store
        .create_workspace(&differing, None, Some("flow:one"), &actx())
        .await
        .unwrap();
    assert!(!replay.created, "replay reports no insert");
    assert_eq!(replay.id, "ws_orig", "replay returns the ORIGINAL id");
    let row = store.get_workspace("ws_orig").await.unwrap().expect("original survives");
    assert_eq!(row.plan, "free", "replay must not reconfigure the original");
    assert!(store.get_workspace("ws_other").await.unwrap().is_none(), "no ghost row");

    // The replay is visible in the ledger, distinguishable from the creation.
    let events = events_for_action(&store, "workspace.create").await;
    assert_eq!(events.len(), 2, "creation + replay each leave an event");
    assert_eq!(events[0].outcome, OUTCOME_OK);
    assert_eq!(events[1].outcome, OUTCOME_REPLAY);
}

#[tokio::test]
async fn update_workspace_reconfigures_but_never_creates() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // provisioning-idempotency: reconfiguring an unknown id matches nothing —
    // it must NOT create (the caller 404s instead of minting a ghost).
    assert!(
        !store.update_workspace(&workspace("ws_ghost"), &actx()).await.unwrap(),
        "unknown id matches zero rows"
    );
    assert!(store.get_workspace("ws_ghost").await.unwrap().is_none(), "nothing created");
    assert!(
        events_for_action(&store, "workspace.reconfigure").await.is_empty(),
        "a no-op reconfigure mutates nothing and records nothing"
    );

    // The happy path updates config but leaves the display name alone (name is
    // create-time data; PUT carries no name).
    seed_workspace(&store, "ws_cfg").await;
    let mut next = workspace("ws_cfg");
    next.plan = "pro".to_owned();
    next.name = "ignored by update".to_owned();
    assert!(store.update_workspace(&next, &actx()).await.unwrap(), "existing row matched");
    let after = store.get_workspace("ws_cfg").await.unwrap().expect("row survives");
    assert_eq!(after.plan, "pro", "plan reconfigured");
    assert_eq!(after.name, "ws_cfg display name", "display name untouched by update");
    assert_eq!(
        events_for_action(&store, "workspace.reconfigure").await.len(),
        1,
        "the real reconfigure left its event"
    );
}

#[tokio::test]
async fn transfer_of_unknown_workspace_is_none() {
    let (store, _pool, _guard) = skip_if_no_db!();
    seed_account(&store, "acct_new", "New", None).await;
    assert_eq!(store.transfer_workspace("ghost", "acct_new", &actx()).await.unwrap(), None);
    assert!(
        events_for_action(&store, "workspace.transfer").await.is_empty(),
        "a failed transfer mutates nothing and records nothing"
    );
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
    store.upsert_auth_route("ws_auth", "/", &plain, &actx()).await.unwrap();
    store.upsert_auth_route("ws_auth", "/admin", &gated, &actx()).await.unwrap();
    store.upsert_auth_route("ws_auth", "/me", &account, &actx()).await.unwrap();

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
    store.upsert_auth_route("ws_auth", "/admin", &plain, &actx()).await.unwrap();
    let cleared = store.get_auth_policy("ws_auth").await.unwrap();
    assert!(!cleared.resolve("/admin").has_requirements());
}

// --------------------------------------------------------------------------- //
// admin-action-audit: the fail-closed ledger contract.
// --------------------------------------------------------------------------- //

#[tokio::test]
async fn a_mutation_that_cannot_be_audited_does_not_commit() {
    let (store, pool, _guard) = skip_if_no_db!();

    // Spec scenario "A mutation that cannot be audited does not commit": force
    // the audit insert to fail by hiding the ledger table, then attempt a
    // mutation. The workspace insert runs FIRST in the same transaction — if
    // recording were best-effort, the row would survive.
    sqlx::query("ALTER TABLE routing.admin_audit_events RENAME TO admin_audit_events_hidden")
        .execute(&pool)
        .await
        .expect("hide ledger");
    let result = store.create_workspace(&workspace("ws_unaudited"), None, None, &actx()).await;
    // Restore the ledger BEFORE asserting so a failure can't poison later tests.
    sqlx::query("ALTER TABLE routing.admin_audit_events_hidden RENAME TO admin_audit_events")
        .execute(&pool)
        .await
        .expect("restore ledger");

    assert!(result.is_err(), "the caller gets an error, never a success with a missing event");
    assert!(
        store.get_workspace("ws_unaudited").await.unwrap().is_none(),
        "the mutation rolled back with the failed audit insert (fail-closed)"
    );
}

#[tokio::test]
async fn events_are_complete_secret_free_and_queryable_by_filter() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // Two actors mutate; the ledger must reconstruct who did what and be
    // filterable by actor and target (design D6).
    seed_workspace(&store, "ws_q").await; // actor atk_test
    let other = AuditCtx {
        actor: "atk_other".to_owned(),
        asserted_operator: None,
        trace_id: Some("00-trace-span-01".to_owned()),
        source_ip: Some("10.1.1.1".to_owned()),
    };
    store
        .upsert_membership(&membership("user_x", "ws_q", "staff", "admin"), &other)
        .await
        .unwrap();

    // Filter by actor: each actor sees exactly their own action.
    let by_actor = store
        .query_audit_events(&AuditQuery { actor: Some("atk_other".to_owned()), ..AuditQuery::default() })
        .await
        .unwrap();
    assert_eq!(by_actor.len(), 1, "actor filter scopes the review");
    let event = &by_actor[0];
    assert_eq!(event.action, "membership.upsert");
    assert_eq!(event.surface, "control-plane");
    assert_eq!(event.target_id.as_deref(), Some("ws_q"));
    assert_eq!(event.trace_id.as_deref(), Some("00-trace-span-01"));
    assert_eq!(event.source_ip.as_deref(), Some("10.1.1.1"));
    assert!(!event.occurred_at.is_empty(), "the event carries its time");

    // Filter by target: both actors' events on ws_q, in time (= id) order.
    let by_target = store
        .query_audit_events(&AuditQuery { target: Some("ws_q".to_owned()), ..AuditQuery::default() })
        .await
        .unwrap();
    assert_eq!(by_target.len(), 2, "target filter returns exactly the matching events");
    assert!(by_target[0].event_id < by_target[1].event_id, "time order");

    // Cursor pagination: resuming after page 1's last id yields page 2 only.
    let page_one = store
        .query_audit_events(&AuditQuery {
            target: Some("ws_q".to_owned()),
            limit: Some(1),
            ..AuditQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(page_one.len(), 1);
    let page_two = store
        .query_audit_events(&AuditQuery {
            target: Some("ws_q".to_owned()),
            cursor: Some(page_one[0].event_id.clone()),
            ..AuditQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(page_two.len(), 1, "cursor resumes strictly after the previous page");
    assert_ne!(page_two[0].event_id, page_one[0].event_id);

    // Malformed time bound → the typed error (the HTTP layer's 400).
    let bad = store
        .query_audit_events(&AuditQuery { from: Some("not-a-time".to_owned()), ..AuditQuery::default() })
        .await;
    assert!(
        bad.is_err_and(|e| e.downcast_ref::<InvalidQueryBound>().is_some()),
        "a malformed bound surfaces as InvalidQueryBound, not an opaque 500"
    );
}

#[tokio::test]
async fn named_tokens_issue_rotate_revoke_with_lineage_and_audit() {
    let (store, _pool, _guard) = skip_if_no_db!();
    let tokens = PgAdminTokenStore::new(&store, AdminTokenHasher::new(b"test-pepper"));

    // Two named callers, individually identifiable (spec: two callers are
    // distinguishable in the ledger — their token ids differ).
    let broker = tokens.issue("signup-broker", &actx()).await.unwrap();
    let ci = tokens.issue("ci", &actx()).await.unwrap();
    assert_ne!(broker.token_id, ci.token_id, "each caller gets its own credential id");
    assert_ne!(broker.secret, ci.secret);

    // Both secrets resolve to their own ids.
    assert_eq!(tokens.lookup(&broker.secret).await.unwrap().as_deref(), Some(broker.token_id.as_str()));
    assert_eq!(tokens.lookup(&ci.secret).await.unwrap().as_deref(), Some(ci.token_id.as_str()));
    assert_eq!(tokens.lookup("nexus_admin_wrong").await.unwrap(), None, "unknown secret fails closed");

    // Revoking one caller leaves the other working (spec scenario).
    assert!(tokens.revoke(&ci.token_id, &actx()).await.unwrap());
    assert_eq!(tokens.lookup(&ci.secret).await.unwrap(), None, "revoked secret is rejected");
    assert_eq!(
        tokens.lookup(&broker.secret).await.unwrap().as_deref(),
        Some(broker.token_id.as_str()),
        "the other caller's credential keeps working"
    );
    assert!(!tokens.revoke(&ci.token_id, &actx()).await.unwrap(), "second revoke is a no-op");

    // Rotation: new secret under the same name, lineage recorded, old one dead.
    let rotated = tokens.rotate(&broker.token_id, &actx()).await.unwrap().expect("active token rotates");
    assert_ne!(rotated.token_id, broker.token_id);
    assert_eq!(tokens.lookup(&broker.secret).await.unwrap(), None, "pre-rotation secret is dead");
    assert_eq!(
        tokens.lookup(&rotated.secret).await.unwrap().as_deref(),
        Some(rotated.token_id.as_str())
    );
    assert!(tokens.rotate(&broker.token_id, &actx()).await.unwrap().is_none(), "revoked id can't rotate");

    // The provisioning actions are themselves in the ledger — and no event
    // anywhere carries a secret (spec: events never leak secrets).
    assert_eq!(events_for_action(&store, "admin_token.issue").await.len(), 2);
    assert_eq!(events_for_action(&store, "admin_token.rotate").await.len(), 1);
    assert_eq!(events_for_action(&store, "admin_token.revoke").await.len(), 1);
    let all = store.query_audit_events(&AuditQuery::default()).await.unwrap();
    for event in &all {
        let serialized = serde_json::to_string(event).unwrap();
        assert!(
            !serialized.contains("nexus_admin_"),
            "no event may carry credential material: {serialized}"
        );
    }
}

#[tokio::test]
async fn denials_are_recorded_without_credential_material() {
    let (store, _pool, _guard) = skip_if_no_db!();

    // Spec "A failed authentication leaves a trace": time, surface, source, and
    // the absent-vs-invalid fact — nothing else.
    store
        .record_auth_denial(&DenialEvent {
            kind: DenialKind::Invalid,
            source_ip: Some("203.0.113.9".to_owned()),
            trace_id: None,
        })
        .await
        .unwrap();
    store
        .record_auth_denial(&DenialEvent {
            kind: DenialKind::Absent,
            source_ip: None,
            trace_id: None,
        })
        .await
        .unwrap();

    let denials = events_for_action(&store, "auth.denied").await;
    assert_eq!(denials.len(), 2);
    assert_eq!(denials[0].actor_token_id, "unauthenticated");
    assert_eq!(denials[0].outcome, "denied");
    assert_eq!(denials[0].detail["credential"], "invalid");
    assert_eq!(denials[0].source_ip.as_deref(), Some("203.0.113.9"));
    assert_eq!(denials[1].detail["credential"], "absent");
}
