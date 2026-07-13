//! The Routing Store port (RFC §3.10/§3.11) and the cache-invalidation feed port
//! (RFC C16) — the abstract capabilities core needs, with NO vendor concretion
//! (rules §2). An adapter crate implements these against a concrete database;
//! core and the services depend only on the traits.

use std::error::Error;
use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::BoxStream;
use serde::Serialize;

use crate::audit::AuditCtx;
use crate::auth::{AuthPolicy, RouteAuth};
use crate::domain::WorkspaceConfig;

pub type BoxError = Box<dyn Error + Send + Sync>;

/// The admin domain-mapping write, bundled (RFC §3.13): which workspace the
/// domain maps to, whether it is a wildcard row, and the verification flag.
#[derive(Debug, Clone, Copy)]
pub struct DomainUpsert<'a> {
    pub domain: &'a str,
    pub workspace_id: &'a str,
    pub wildcard: bool,
    pub verified: bool,
}

/// A stored domain mapping as the control plane sees it (RFC §3.13): which
/// workspace owns it, whether it is a wildcard, and whether it is verified. Unlike
/// the hot-path `lookup_domain`, this reads a row regardless of verification state
/// — the lifecycle (declare/verify) needs to see pending rows too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRecord {
    pub workspace_id: String,
    pub wildcard: bool,
    pub verified: bool,
}

/// A live ownership-proof challenge (RFC C4): the minted token and whether it has
/// passed its time-to-live. The challenge name is derived (see
/// `crate::verify::challenge_name`), not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub domain: String,
    pub token: String,
    pub expired: bool,
}

/// Abstract routing store: point lookups by domain and workspace on the request
/// path (no scans, RFC §3.10), plus the control-plane write surface (RFC §3.13).
///
/// `lookup_domain` is the hot-path read (on a cache miss): a point read by the
/// **normalized** domain key. The router does at most two — one exact, then one
/// wildcard-parent (RFC C14). Only **verified** mappings resolve (RFC C16):
/// an unverified domain MUST NOT resolve to a workspace on protected routes.
#[async_trait]
pub trait RoutingStore: Send + Sync {
    /// Resolve a normalized domain to its owning `workspace_id`, if a *verified*
    /// mapping exists. `wildcard = false` matches an exact custom domain/subdomain;
    /// `wildcard = true` matches a wildcard registered against the parent domain.
    async fn lookup_domain(&self, domain: &str, wildcard: bool)
        -> Result<Option<String>, BoxError>;

    /// Load a workspace's config (the routing value). `None` if absent.
    async fn get_workspace(&self, workspace_id: &str) -> Result<Option<WorkspaceConfig>, BoxError>;

    // --- control-plane write surface (RFC §3.13) ---------------------------- //

    /// Create a workspace — insert-only, NEVER touches an existing row
    /// (provisioning-idempotency: create and reconfigure are disjoint). The id in
    /// `cfg` is server-minted ([`crate::ids`]). With an idempotency key, a replay
    /// returns the ORIGINAL row's id with `created = false` instead of inserting;
    /// two same-key racers resolve to one row, both receiving its id. A `None`
    /// key opts out of replay protection (every call inserts). When
    /// `owner_account` is set and THIS call inserted, ownership is assigned in
    /// the same transaction (a replay never re-owns). Records one
    /// `workspace.create` audit event atomically with the write
    /// (admin-action-audit): an unrecorded create does not commit.
    async fn create_workspace(
        &self,
        cfg: &WorkspaceConfig,
        owner_account: Option<&str>,
        idempotency_key: Option<&str>,
        actx: &AuditCtx,
    ) -> Result<CreateOutcome, BoxError>;

    /// Reconfigure an existing workspace's plan/pool/features — update-only,
    /// NEVER creates (an unknown id is `false`, not a new row). The display name
    /// and ownership are deliberately untouched: name is create-time data,
    /// ownership changes ride [`OwnershipStore::transfer_workspace`]. Audited
    /// atomically (`workspace.reconfigure`) when a row matched.
    async fn update_workspace(&self, cfg: &WorkspaceConfig, actx: &AuditCtx)
        -> Result<bool, BoxError>;

    /// Create or update a domain → workspace mapping. This is the **admin** write
    /// (it may reassign ownership); the self-service declare path uses
    /// [`RoutingStore::create_pending_domain`], which never reassigns. Audited
    /// atomically (`domain.upsert`).
    async fn upsert_domain(&self, up: &DomainUpsert<'_>, actx: &AuditCtx)
        -> Result<(), BoxError>;

    /// Atomically claim a NEW exact (non-wildcard), unverified domain for a
    /// workspace (RFC C3 self-service declare). Returns `true` iff this call
    /// inserted the row; `false` if a row for the domain already existed (insert
    /// was a no-op). Crucially it MUST NOT overwrite an existing row's
    /// `workspace_id` — that closes the declare race where two workspaces claim the
    /// same domain concurrently (the loser gets `false` and is then told
    /// `domain_taken`).
    /// Audited atomically (`domain.declare`) when THIS call inserted the row; a
    /// lost race / existing row records nothing (no state changed).
    async fn create_pending_domain(
        &self,
        domain: &str,
        workspace_id: &str,
        actx: &AuditCtx,
    ) -> Result<bool, BoxError>;

    /// Set an exact (non-wildcard) domain's ownership-verification flag (RFC C16:
    /// verify ownership). Keyed on `(domain, is_wildcard=false)` — the lifecycle
    /// only ever verifies exact self-service domains, never a wildcard row.
    /// Audited atomically (`domain.verify`) when a row changed.
    async fn set_domain_verified(
        &self,
        domain: &str,
        verified: bool,
        actx: &AuditCtx,
    ) -> Result<(), BoxError>;

    /// Remove a domain mapping (idempotent — missing is not an error). `wildcard`
    /// selects which row of the `(domain, is_wildcard)` pair to drop. Audited
    /// atomically (`domain.delete`) when a row was actually removed (a no-op
    /// delete mutates nothing and records nothing).
    async fn delete_domain(&self, domain: &str, wildcard: bool, actx: &AuditCtx)
        -> Result<(), BoxError>;

    /// The domains owned by a workspace — used by the control plane to publish the
    /// precise invalidations for a workspace-config change.
    async fn domains_for_workspace(&self, workspace_id: &str) -> Result<Vec<String>, BoxError>;

    /// Read one domain row regardless of verification state (RFC C3): lets the
    /// lifecycle detect a cross-workspace claim and an idempotent re-declare. Keyed
    /// on `(domain, is_wildcard)` so a same-name wildcard row can never be read in
    /// place of the exact self-service row. `None` if that row is unknown.
    async fn get_domain(
        &self,
        domain: &str,
        wildcard: bool,
    ) -> Result<Option<DomainRecord>, BoxError>;

    /// Count the domains a workspace holds — **verified plus pending** (RFC C3/I6),
    /// the figure the quota gate compares against the plan limit.
    async fn count_domains_for_workspace(&self, workspace_id: &str) -> Result<u32, BoxError>;

    /// The pending (unverified) domains, for the periodic verification poll
    /// (RFC C4). Order is unspecified.
    async fn pending_domains(&self) -> Result<Vec<String>, BoxError>;

    /// Expire pending (unverified) domains older than `ttl_secs` (RFC C3): an
    /// abandoned declare is removed, freeing its quota slot and dropping out of
    /// the verification poll. Returns the removed domain keys. A pending domain
    /// never routed, so its removal changes no resolution/authorization outcome
    /// and MUST NOT trigger an invalidation.
    async fn expire_pending_domains(&self, ttl_secs: i64) -> Result<Vec<String>, BoxError>;

    // --- per-route auth policy (RFC N4) ------------------------------------- //

    /// Load a workspace's route-protection policy (RFC N4). A hot-path read folded
    /// into the router's decision miss-load. Returns the pass-through default
    /// ([`AuthPolicy::default`]) when the workspace has no rules — absence of a
    /// policy is "public", never an error, so no row needs to exist for a site to
    /// work.
    async fn get_auth_policy(&self, workspace_id: &str) -> Result<AuthPolicy, BoxError>;

    /// Create or update one path-prefix rule for a workspace (control-plane write).
    /// The per-workspace default is the rule with `prefix = "/"`. The rule carries
    /// the full protection decision, including the optional phase-2 requirement
    /// fields (`None` = no requirement). Audited atomically (`auth_route.upsert`).
    async fn upsert_auth_route(
        &self,
        workspace_id: &str,
        prefix: &str,
        auth: &RouteAuth,
        actx: &AuditCtx,
    ) -> Result<(), BoxError>;

    /// Remove one path-prefix rule (idempotent — missing is not an error).
    /// Audited atomically (`auth_route.delete`).
    async fn delete_auth_route(
        &self,
        workspace_id: &str,
        prefix: &str,
        actx: &AuditCtx,
    ) -> Result<(), BoxError>;
}

/// The ownership-proof challenge store (RFC C4). Kept distinct from the routing
/// store so the challenge lifecycle (a control-plane concern) never touches the
/// hot read path; an adapter MAY back both with one technology (rules §2).
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Idempotently obtain the challenge for a domain (RFC C3 idempotence): if a
    /// live (unexpired) challenge exists, return it unchanged; if none exists, or
    /// the existing one has expired, mint a fresh token with the given TTL and
    /// return that. Re-declaring a pending domain therefore yields the SAME
    /// challenge until it expires, then a re-issued one (RFC C4: re-issuable).
    async fn mint_or_get_challenge(
        &self,
        domain: &str,
        workspace_id: &str,
        ttl_secs: i64,
    ) -> Result<Challenge, BoxError>;

    /// Read the current challenge with its expiry computed, if any.
    async fn get_challenge(&self, domain: &str) -> Result<Option<Challenge>, BoxError>;

    /// Retire a challenge on successful verification (idempotent — missing is not
    /// an error).
    async fn delete_challenge(&self, domain: &str) -> Result<(), BoxError>;
}

/// A live invalidation feed (RFC C16): the control plane publishes the affected
/// **normalized domain key** on every mutation; resolvers evict that key from
/// every cache tier so they converge promptly. The payload is the domain string.
pub type InvalidationFeed = BoxStream<'static, Result<String, BoxError>>;

/// The capability of subscribing to control-plane invalidations. Kept distinct
/// from the store so a different transport (a message bus, a poll) is an adapter
/// swap, never a core change.
#[async_trait]
pub trait Invalidations: Send + Sync {
    /// Open a live invalidation feed. Callers reopen on error.
    async fn subscribe(&self) -> Result<InvalidationFeed, BoxError>;
}

/// The publish counterpart of [`Invalidations`]: the control plane emits the
/// affected **normalized domain key** here after every mutation, and every
/// subscriber (across regions) evicts it. Kept distinct from the store — and
/// symmetric with the subscribe port — so the transport (pg_notify, a message
/// bus) is an adapter swap, never a control-plane change.
#[async_trait]
pub trait InvalidationPublisher: Send + Sync {
    /// Publish the invalidation for `domain`. Best-effort: a failure MUST NOT fail
    /// the committed write — the cache TTL backstop heals a lost signal.
    async fn publish(&self, domain: &str) -> Result<(), BoxError>;
}

/// Fan an invalidation out to several transports at once (e.g. pg_notify AND a
/// message bus during a cross-region rollout). Publishing to every sink keeps
/// enabling a new transport purely **additive** — subscribers still on the old
/// one never lose the signal. Best-effort: every sink is attempted even if an
/// earlier one fails; the last error (if any) is returned for the caller to log.
pub struct FanoutPublisher {
    sinks: Vec<Arc<dyn InvalidationPublisher>>,
}

impl FanoutPublisher {
    /// Build a fan-out over `sinks`. One sink degenerates to a direct publish.
    #[must_use]
    pub fn new(sinks: Vec<Arc<dyn InvalidationPublisher>>) -> Self {
        Self { sinks }
    }
}

#[async_trait]
impl InvalidationPublisher for FanoutPublisher {
    async fn publish(&self, domain: &str) -> Result<(), BoxError> {
        let mut last_err = None;
        for sink in &self.sinks {
            if let Err(e) = sink.publish(domain).await {
                last_err = Some(e);
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

// --- ownership + membership (nexus-owned-workspace-tenancy) ------------------ //
//
// The management-plane write surface for the tenancy model: Accounts own
// Workspaces (transferable by repointing `account_id`), and typed staff|customer
// Memberships are the live authz source of record. These are control-plane
// concerns only — deliberately split OUT of the hot-path `RoutingStore` so the
// resolver's port stays a lean point-lookup surface (rules §2). One adapter MAY
// back all of them with one technology.

/// An owning Account (the member container; a solo user is a one-member account).
/// `payer_ref` is the billing/payer of record, which switches on a transfer.
#[expect(
    clippy::struct_field_names,
    reason = "account_id keeps the uniform <entity>_id wire name shared with the \
              store column and every other id field, not a bare `id`"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Account {
    pub account_id: String,
    pub name: String,
    pub payer_ref: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// One membership of a user in an account (owner-only in v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountMember {
    pub account_id: String,
    pub user_sub: String,
    pub role: String,
}

/// A workspace-scoped membership — the live authz record the identity plane
/// projects and resolves fail-closed. `member_type` is `"staff"` or `"customer"`
/// (validated at the write boundary and CHECK-constrained in the store).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Membership {
    pub user_sub: String,
    pub workspace_id: String,
    pub member_type: String,
    pub role: String,
    pub status: String,
}

/// The two membership kinds. Kept as bare `&str` constants (not an enum) because
/// the store persists the wire string and the DB CHECK is the backstop — the
/// control plane only needs to validate admin input against this closed set.
pub const MEMBER_TYPES: [&str; 2] = ["staff", "customer"];

/// Outcome of an idempotent create (provisioning-idempotency): the canonical id —
/// the freshly minted one, or the ORIGINAL resource's when the idempotency key
/// replayed — and whether THIS call inserted the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOutcome {
    /// The id the caller must use from here on.
    pub id: String,
    /// `true` iff this call inserted the row (`false` = replay of an earlier one).
    pub created: bool,
}

/// The account-provisioning write, bundled: create-time account data plus the
/// owner membership asserted with it. The `account_id` is server-minted
/// ([`crate::ids`]); `idempotency_key` is the caller's replay guard.
#[derive(Debug, Clone, Copy)]
pub struct NewAccount<'a> {
    pub account_id: &'a str,
    pub name: &'a str,
    pub payer_ref: Option<&'a str>,
    pub owner_sub: &'a str,
    pub idempotency_key: Option<&'a str>,
}

/// Account ownership + workspace-transfer surface (control plane, RFC §3.13).
#[async_trait]
pub trait OwnershipStore: Send + Sync {
    /// Provision an account with a server-minted id ([`crate::ids`]) — insert-only
    /// — and assert its `owner` membership, in ONE transaction. With an
    /// idempotency key, a replay returns the ORIGINAL account's id with
    /// `created = false`, never clobbers its name/payer, and only re-asserts the
    /// owner membership — this is what keeps signup provisioning safe to call
    /// unconditionally (provisioning-idempotency). Two same-key racers resolve to
    /// one row. Records one `account.provision` audit event atomically with the
    /// write (admin-action-audit): an unrecorded provision does not commit.
    async fn provision_account(
        &self,
        account: &NewAccount<'_>,
        actx: &AuditCtx,
    ) -> Result<CreateOutcome, BoxError>;

    /// Load an account, `None` if absent.
    async fn get_account(&self, account_id: &str) -> Result<Option<Account>, BoxError>;

    /// The members of an account.
    async fn account_members(&self, account_id: &str) -> Result<Vec<AccountMember>, BoxError>;

    /// Transfer a workspace to a different owning account (RFC workspace-tenancy):
    /// repoint `account_id` AND reset staff memberships in ONE transaction, so a
    /// half-applied transfer can never leave the previous owner's staff with access
    /// (the security contract of a sale/transfer). The `workspace_id`, its domains,
    /// its data, and its **customer** memberships are untouched. Returns
    /// `Some(staff_removed)` on success, or `None` if the workspace is unknown.
    /// Audited atomically (`workspace.transfer`).
    async fn transfer_workspace(
        &self,
        workspace_id: &str,
        account_id: &str,
        actx: &AuditCtx,
    ) -> Result<Option<u64>, BoxError>;
}

/// Workspace membership CRUD (control plane): the write surface the identity plane
/// consumes via the change feed to resolve `(sub, workspace) -> {type, role}`.
#[async_trait]
pub trait MembershipStore: Send + Sync {
    /// Grant or update a membership. Idempotent upsert keyed `(user_sub,
    /// workspace_id)` — a user holds at most one membership per workspace.
    /// Audited atomically (`membership.upsert`).
    async fn upsert_membership(&self, m: &Membership, actx: &AuditCtx) -> Result<(), BoxError>;

    /// Revoke a membership (idempotent — missing is not an error). Audited
    /// atomically (`membership.revoke`).
    async fn delete_membership(
        &self,
        user_sub: &str,
        workspace_id: &str,
        actx: &AuditCtx,
    ) -> Result<(), BoxError>;

    /// The memberships of a workspace (staff and customer).
    async fn memberships_for_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<Membership>, BoxError>;
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use futures::executor::block_on;

    use super::{Arc, BoxError, FanoutPublisher, InvalidationPublisher};

    /// Records the domains it was asked to publish; optionally fails to exercise
    /// the best-effort fan-out semantics.
    struct Recorder {
        seen: Mutex<Vec<String>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl InvalidationPublisher for Recorder {
        async fn publish(&self, domain: &str) -> Result<(), BoxError> {
            self.seen.lock().unwrap().push(domain.to_owned());
            if self.fail {
                Err("sink failed".into())
            } else {
                Ok(())
            }
        }
    }

    fn recorder(fail: bool) -> Arc<Recorder> {
        Arc::new(Recorder {
            seen: Mutex::new(vec![]),
            fail,
        })
    }

    #[test]
    fn fanout_publishes_to_every_sink() {
        let first = recorder(false);
        let second = recorder(false);
        let fan = FanoutPublisher::new(vec![
            Arc::clone(&first) as Arc<dyn InvalidationPublisher>,
            Arc::clone(&second) as Arc<dyn InvalidationPublisher>,
        ]);
        block_on(fan.publish("x.example.com")).unwrap();
        assert_eq!(first.seen.lock().unwrap().as_slice(), ["x.example.com"]);
        assert_eq!(second.seen.lock().unwrap().as_slice(), ["x.example.com"]);
    }

    #[test]
    fn fanout_attempts_all_sinks_even_when_one_fails() {
        let failing = recorder(true);
        let healthy = recorder(false);
        let fan = FanoutPublisher::new(vec![
            Arc::clone(&failing) as Arc<dyn InvalidationPublisher>,
            Arc::clone(&healthy) as Arc<dyn InvalidationPublisher>,
        ]);
        // A sink failure surfaces as Err (so the operator sees it), but the later
        // sink still received the signal — enabling one transport never starves
        // another.
        assert!(block_on(fan.publish("y.example.com")).is_err());
        assert_eq!(healthy.seen.lock().unwrap().as_slice(), ["y.example.com"]);
    }
}
