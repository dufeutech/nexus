//! Shared test scaffolding for the tenant-router: one in-memory `RoutingStore`
//! fake and an `AppState` builder over it, used by the resolve keep-warm tests
//! and the `/authorize`-vs-router parity tests. Kept in a single place so the
//! fake cannot drift between test modules (single source of truth).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use moka::future::Cache;

use router_core::audit::AuditCtx;
use router_core::auth::{AuthPolicy, RouteAuth};
use router_core::domain::{Pool, WorkspaceConfig};
use router_core::store::{
    BoxError, CreateOutcome, DomainRecord, DomainUpsert, RoutingStore,
};

use crate::state::{refresh_point, AppState};

/// An in-memory `RoutingStore` answering only the three reads `resolve` makes —
/// the exact/wildcard domain lookup, the workspace config, and the (pass-through)
/// auth policy — and counting every `lookup_domain`. The domain map is held
/// behind a lock so a later refresh test can change what a re-fetch returns.
/// Every control-plane method returns a loud `Err`: no resolve test drives them,
/// and a stray call should fail rather than lie.
pub(crate) struct FakeStore {
    domains: Mutex<HashMap<(String, bool), String>>,
    lookups: AtomicUsize,
    fail: AtomicBool,
}

impl FakeStore {
    /// Build over an initial set of verified `((domain, is_wildcard), workspace_id)`
    /// rows.
    pub(crate) fn new<I>(pairs: I) -> Self
    where
        I: IntoIterator<Item = ((String, bool), String)>,
    {
        Self {
            domains: Mutex::new(pairs.into_iter().collect()),
            lookups: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
        }
    }

    /// An empty store — every host is unknown and fails closed.
    pub(crate) fn empty() -> Self {
        Self::new([])
    }

    /// Total `lookup_domain` calls seen so far.
    pub(crate) fn lookups(&self) -> usize {
        self.lookups.load(Ordering::Relaxed)
    }

    /// Flip whether `lookup_domain` fails — models a store/refresh outage so a
    /// keep-warm test can drive the failure-handling and bounded-staleness paths.
    pub(crate) fn set_fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::Relaxed);
    }

    /// Point a `(domain, exact)` row at a workspace (or change it), so a refresh
    /// test can verify a background re-fetch picks up the new value.
    pub(crate) fn set_domain(&self, domain: &str, workspace_id: &str) {
        self.domains
            .lock()
            .unwrap()
            .insert((domain.to_owned(), false), workspace_id.to_owned());
    }
}

#[async_trait]
impl RoutingStore for FakeStore {
    async fn lookup_domain(&self, domain: &str, wildcard: bool) -> Result<Option<String>, BoxError> {
        let _ = self.lookups.fetch_add(1, Ordering::Relaxed);
        if self.fail.load(Ordering::Relaxed) {
            return Err("FakeStore: lookup_domain failing (injected outage)".into());
        }
        Ok(self
            .domains
            .lock()
            .unwrap()
            .get(&(domain.to_owned(), wildcard))
            .cloned())
    }

    async fn get_workspace(&self, workspace_id: &str) -> Result<Option<WorkspaceConfig>, BoxError> {
        // Any workspace a domain row points at has a trivial config — the resolve
        // tests care whether resolution succeeds and which workspace, not the
        // config's other contents.
        Ok(Some(WorkspaceConfig {
            workspace_id: workspace_id.to_owned(),
            name: String::new(),
            plan: "free".to_owned(),
            target_pool: Pool::new("application"),
            features: vec![],
            updated_at: None,
        }))
    }

    async fn get_auth_policy(&self, _workspace_id: &str) -> Result<AuthPolicy, BoxError> {
        Ok(AuthPolicy::default())
    }

    // --- control-plane surface: never exercised by the resolve tests ---------- //
    async fn create_workspace(
        &self,
        _cfg: &WorkspaceConfig,
        _owner_account: Option<&str>,
        _idempotency_key: Option<&str>,
        _actx: &AuditCtx,
    ) -> Result<CreateOutcome, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn update_workspace(&self, _cfg: &WorkspaceConfig, _actx: &AuditCtx) -> Result<bool, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn upsert_domain(&self, _up: &DomainUpsert<'_>, _actx: &AuditCtx) -> Result<(), BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn create_pending_domain(
        &self,
        _domain: &str,
        _workspace_id: &str,
        _actx: &AuditCtx,
    ) -> Result<bool, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn set_domain_verified(
        &self,
        _domain: &str,
        _verified: bool,
        _actx: &AuditCtx,
    ) -> Result<(), BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn delete_domain(&self, _domain: &str, _wildcard: bool, _actx: &AuditCtx) -> Result<(), BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn domains_for_workspace(&self, _workspace_id: &str) -> Result<Vec<String>, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn get_domain(&self, _domain: &str, _wildcard: bool) -> Result<Option<DomainRecord>, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn count_domains_for_workspace(&self, _workspace_id: &str) -> Result<u32, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn pending_domains(&self) -> Result<Vec<String>, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn expire_pending_domains(&self, _ttl_secs: i64) -> Result<Vec<String>, BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn upsert_auth_route(
        &self,
        _workspace_id: &str,
        _prefix: &str,
        _auth: &RouteAuth,
        _actx: &AuditCtx,
    ) -> Result<(), BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
    async fn delete_auth_route(
        &self,
        _workspace_id: &str,
        _prefix: &str,
        _actx: &AuditCtx,
    ) -> Result<(), BoxError> {
        Err("FakeStore: control-plane surface is not exercised by resolve tests".into())
    }
}

/// Build a ready, L1-only `AppState` over `store` with the given L1 lifetime, so
/// the real `resolve`/`api::router` paths run against the fake. `ttl` is the L1
/// `time_to_live`; the keep-warm refresh point derives from it.
pub(crate) fn build_state(store: Arc<dyn RoutingStore>, ttl: Duration) -> AppState {
    AppState {
        l1: Cache::builder().max_capacity(1024).time_to_live(ttl).build(),
        l2: None,
        neg: Cache::builder().max_capacity(1024).build(),
        store,
        l2_ttl: 60,
        // Keep-warm refresh point derived from the L1 lifetime, exactly as `main`
        // wires it (D2) — tests inherit the production derivation, not a knob.
        refresh_after: refresh_point(ttl),
        refreshing: Arc::new(Mutex::new(HashSet::new())),
        ready: Arc::new(AtomicBool::new(true)),
        last_apply_ms: Arc::new(AtomicU64::new(0)),
        warm_ms: Arc::new(AtomicU64::new(0)),
        start: Instant::now(),
    }
}
