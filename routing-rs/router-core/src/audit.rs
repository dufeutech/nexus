//! Administrative audit ledger — core types (admin-action-audit).
//!
//! Every mutating admin action on the control plane records a durable audit
//! event **in the same transaction as the mutation** (fail-closed: an
//! unrecorded admin mutation does not commit — design D1/D2). This module holds
//! the abstract WHAT: the closed action vocabulary, the transport-facts context
//! the HTTP adapter contributes, the reserved actor ids, and the query/export
//! shapes. The recording itself is a store-adapter concern (the transaction
//! lives there); no vendor concretion appears here (rules §2).
//!
//! This ledger is NOT telemetry: it never rides the fail-open collection layer,
//! and telemetry unavailability never affects it.

use std::error::Error;
use std::fmt;

use serde::Serialize;
use serde_json::Value;

/// The surface name this plane's events carry (`surface` column).
pub const SURFACE_CONTROL_PLANE: &str = "control-plane";

// --------------------------------------------------------------------------- //
// Closed action vocabulary (design D3). Adding an action is a deliberate,
// reviewed change to this list — the store rejects anything outside it, so a
// typo'd or ad-hoc action name can never enter the ledger.
// --------------------------------------------------------------------------- //

/// `POST /accounts` — account provisioned (owner membership asserted with it).
pub const ACTION_ACCOUNT_PROVISION: &str = "account.provision";
/// `POST /workspaces` — workspace created (ownership assigned with it).
pub const ACTION_WORKSPACE_CREATE: &str = "workspace.create";
/// `PUT /workspaces/{id}` — plan/pool/features reconfigured.
pub const ACTION_WORKSPACE_RECONFIGURE: &str = "workspace.reconfigure";
/// `POST /workspaces/{id}/transfer` — ownership repointed, staff reset.
pub const ACTION_WORKSPACE_TRANSFER: &str = "workspace.transfer";
/// `PUT /workspaces/{id}/members` — membership granted or updated.
pub const ACTION_MEMBERSHIP_UPSERT: &str = "membership.upsert";
/// `DELETE /workspaces/{id}/members/{sub}` — membership revoked.
pub const ACTION_MEMBERSHIP_REVOKE: &str = "membership.revoke";
/// `POST /domains` — admin domain mapping created/updated.
pub const ACTION_DOMAIN_UPSERT: &str = "domain.upsert";
/// `POST /domains/declare` — self-service pending domain claimed.
pub const ACTION_DOMAIN_DECLARE: &str = "domain.declare";
/// Ownership proof accepted — domain flipped to verified (endpoint or poll).
pub const ACTION_DOMAIN_VERIFY: &str = "domain.verify";
/// `DELETE /domains/{domain}` — domain mapping removed.
pub const ACTION_DOMAIN_DELETE: &str = "domain.delete";
/// `PUT /workspaces/{id}/auth-routes` — route-protection rule written.
pub const ACTION_AUTH_ROUTE_UPSERT: &str = "auth_route.upsert";
/// `DELETE /workspaces/{id}/auth-routes` — route-protection rule removed.
pub const ACTION_AUTH_ROUTE_DELETE: &str = "auth_route.delete";
/// `POST /admin-tokens` — named admin credential issued.
pub const ACTION_ADMIN_TOKEN_ISSUE: &str = "admin_token.issue";
/// `POST /admin-tokens/{id}/rotate` — credential rotated under its lineage.
pub const ACTION_ADMIN_TOKEN_ROTATE: &str = "admin_token.rotate";
/// `POST /admin-tokens/{id}/revoke` — credential revoked.
pub const ACTION_ADMIN_TOKEN_REVOKE: &str = "admin_token.revoke";
/// Rejected admin authentication (401) — recorded best-effort, never in a
/// mutation transaction (no mutation exists).
pub const ACTION_AUTH_DENIED: &str = "auth.denied";

/// The closed vocabulary, in one place, so membership is checkable.
pub const ACTIONS: [&str; 16] = [
    ACTION_ACCOUNT_PROVISION,
    ACTION_WORKSPACE_CREATE,
    ACTION_WORKSPACE_RECONFIGURE,
    ACTION_WORKSPACE_TRANSFER,
    ACTION_MEMBERSHIP_UPSERT,
    ACTION_MEMBERSHIP_REVOKE,
    ACTION_DOMAIN_UPSERT,
    ACTION_DOMAIN_DECLARE,
    ACTION_DOMAIN_VERIFY,
    ACTION_DOMAIN_DELETE,
    ACTION_AUTH_ROUTE_UPSERT,
    ACTION_AUTH_ROUTE_DELETE,
    ACTION_ADMIN_TOKEN_ISSUE,
    ACTION_ADMIN_TOKEN_ROTATE,
    ACTION_ADMIN_TOKEN_REVOKE,
    ACTION_AUTH_DENIED,
];

/// Whether `action` is in the closed vocabulary. The store's `record` refuses
/// anything else, keeping the ledger's action space reviewable.
#[must_use]
pub fn is_known_action(action: &str) -> bool {
    ACTIONS.contains(&action)
}

// --------------------------------------------------------------------------- //
// Reserved actor ids: attributions that are not a named token's id. Reserved
// (not mintable) so they can never collide with a real `admin_tokens.token_id`.
// --------------------------------------------------------------------------- //

/// The legacy shared env token, accepted only while `ADMIN_LEGACY_TOKEN_OK=true`
/// (design D5). Every use logs a deprecation warning.
pub const ACTOR_LEGACY_SHARED: &str = "legacy-shared";
/// Auth explicitly disabled at startup (trusted-network/dev only): callers are
/// anonymous by operator decision, and the ledger says so.
pub const ACTOR_AUTH_DISABLED: &str = "auth-disabled";
/// The background verification poll — a system mutation, not an HTTP caller.
pub const ACTOR_SYSTEM_VERIFY_POLL: &str = "system:verify-poll";
/// The actor recorded on a denial event: nobody authenticated.
pub const ACTOR_UNAUTHENTICATED: &str = "unauthenticated";

/// Outcome value for a successful mutation.
pub const OUTCOME_OK: &str = "ok";
/// Outcome value for an idempotency-key replay (`created: false`): the attempt
/// is audit-relevant and distinguishable from the original creation.
pub const OUTCOME_REPLAY: &str = "replay";

/// Length cap (bytes) for the caller-asserted `x-acting-operator` header. The
/// value is stored VERBATIM (never truncated — truncation isn't verbatim), so an
/// over-long assertion is rejected at the boundary instead.
pub const ASSERTED_OPERATOR_MAX_BYTES: usize = 256;

/// Length cap (bytes) for the captured correlation (`traceparent`) value.
pub const TRACE_ID_MAX_BYTES: usize = 128;

/// The transport facts the HTTP adapter contributes to every audit event
/// (design D2): the authenticated actor plus correlation data. Built once per
/// request by the auth middleware and passed down; the store layer supplies the
/// action/target/outcome semantics where the transaction lives. The asserted
/// operator is recorded verbatim, marked as asserted by its column, and NEVER
/// influences authentication, authorization, or the action's outcome.
#[derive(Debug, Clone)]
pub struct AuditCtx {
    /// The acting credential's identifier (`admin_tokens.token_id`), or a
    /// reserved actor id (`legacy-shared`, `auth-disabled`, `system:*`,
    /// `bootstrap`). Never credential material.
    pub actor: String,
    /// The caller-asserted human operator (`x-acting-operator`), verbatim.
    pub asserted_operator: Option<String>,
    /// Request correlation (W3C `traceparent`) where present.
    pub trace_id: Option<String>,
    /// Caller network source.
    pub source_ip: Option<String>,
}

impl AuditCtx {
    /// A system-actor context for non-HTTP mutations (background jobs): no
    /// transport facts exist, only the reserved actor id.
    #[must_use]
    pub fn system(actor: &str) -> Self {
        Self {
            actor: actor.to_owned(),
            asserted_operator: None,
            trace_id: None,
            source_ip: None,
        }
    }
}

/// Why an admin authentication was rejected. Distinguishes a missing/malformed
/// credential from a presented-but-invalid one — without ever carrying the
/// presented value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialKind {
    /// No credential (or a malformed `Authorization` header) was presented.
    Absent,
    /// A credential was presented and rejected.
    Invalid,
}

impl DenialKind {
    /// The wire/ledger word for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Invalid => "invalid",
        }
    }
}

/// A rejected-authentication event (spec: "Denied admin access is recorded").
/// Carries time (stamped at insert), surface (the store's), source, and the
/// absent-vs-invalid fact — never the presented credential material.
#[derive(Debug, Clone)]
pub struct DenialEvent {
    /// Whether a credential was absent or presented-but-invalid.
    pub kind: DenialKind,
    /// Caller network source.
    pub source_ip: Option<String>,
    /// Request correlation (W3C `traceparent`) where present.
    pub trace_id: Option<String>,
}

/// A malformed query bound (e.g. an unparseable `from`/`to` timestamp) — the
/// typed error the read adapter surfaces so the HTTP layer can answer 400
/// instead of a masked 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidQueryBound;

impl fmt::Display for InvalidQueryBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid audit query bound (use an RFC 3339 timestamp)")
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Error's provided methods (source/description/cause/provide/type_id) are \
              deprecated, unstable, or correct by default for a unit error"
)]
impl Error for InvalidQueryBound {}

/// Filters for the read surface (`GET /audit/events`, design D6). All optional;
/// results are time-ordered (by `event_id` — UUIDv7 order IS time order) and
/// cursor-paginated.
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    /// Inclusive lower bound on `occurred_at` (RFC 3339).
    pub from: Option<String>,
    /// Exclusive upper bound on `occurred_at` (RFC 3339).
    pub to: Option<String>,
    /// Exact match on the acting credential id.
    pub actor: Option<String>,
    /// Exact match on the target id.
    pub target: Option<String>,
    /// Resume strictly after this `event_id` (the previous page's last).
    pub cursor: Option<String>,
    /// Page size; the adapter clamps it to a sane bound.
    pub limit: Option<u32>,
}

/// One ledger row as the read surface returns it: the complete, self-describing
/// record (spec: reconstructs who did what, where, and when, without consulting
/// any other record). `asserted_operator` is caller-asserted by definition —
/// the field name marks it in every export.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEventRecord {
    /// Typed, time-ordered id (`aev_<uuidv7>`), unique across both surfaces.
    pub event_id: String,
    /// When the action occurred (RFC 3339, DB clock).
    pub occurred_at: String,
    /// Which admin surface recorded it.
    pub surface: String,
    /// The action, from the closed vocabulary.
    pub action: String,
    /// The acting credential's identifier (or a reserved actor id).
    pub actor_token_id: String,
    /// Caller-asserted operator, verbatim; confers nothing.
    pub asserted_operator: Option<String>,
    /// What kind of resource the action targeted.
    pub target_kind: Option<String>,
    /// The targeted resource's identifier.
    pub target_id: Option<String>,
    /// `ok`, `replay`, or an error class — never raw error detail.
    pub outcome: String,
    /// Request semantics minus secrets (JSON object).
    pub detail: Value,
    /// Request correlation where present.
    pub trace_id: Option<String>,
    /// Caller network source.
    pub source_ip: Option<String>,
    /// The idempotency key, when one was supplied.
    pub idempotency_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{is_known_action, AuditCtx, DenialKind, ACTIONS, ACTOR_SYSTEM_VERIFY_POLL};

    #[test]
    fn vocabulary_is_closed() {
        assert!(is_known_action("workspace.transfer"), "known actions are members");
        assert!(!is_known_action("workspace.rename"), "unknown actions are rejected");
        assert!(!is_known_action(""), "empty is rejected");
    }

    #[test]
    fn vocabulary_has_no_duplicates() {
        let unique: BTreeSet<&str> = ACTIONS.into_iter().collect();
        assert_eq!(unique.len(), ACTIONS.len(), "each action appears exactly once");
    }

    #[test]
    fn system_ctx_carries_only_the_actor() {
        let ctx = AuditCtx::system(ACTOR_SYSTEM_VERIFY_POLL);
        assert_eq!(ctx.actor, ACTOR_SYSTEM_VERIFY_POLL);
        assert!(ctx.asserted_operator.is_none() && ctx.trace_id.is_none(), "no transport facts");
    }

    #[test]
    fn denial_kinds_have_stable_ledger_words() {
        assert_eq!(DenialKind::Absent.as_str(), "absent");
        assert_eq!(DenialKind::Invalid.as_str(), "invalid");
    }
}
