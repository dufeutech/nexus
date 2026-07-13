//! Administrative audit ledger — core types (admin-action-audit), the identity
//! plane's twin of `router_core::audit`. The two planes share the CONVENTION
//! (record shape, id scheme, closed-vocabulary discipline), not a crate — the
//! workspaces stay uncoupled (design D3).
//!
//! Every mutating authz-admin action records a durable audit event **in the
//! same transaction as the mutation** (fail-closed: an unrecorded admin
//! mutation does not commit — design D1/D2). This module holds the abstract
//! WHAT: the closed action vocabulary, the transport-facts context the HTTP
//! adapter contributes, the reserved actor ids, and the query/export shapes.
//! The recording itself is a store-adapter concern (the transaction lives
//! there). This ledger is NOT telemetry: it never rides the fail-open
//! collection layer, and telemetry unavailability never affects it.

use std::error::Error;
use std::fmt;

use serde::Serialize;
use serde_json::Value;

/// The surface name this plane's events carry (`surface` column).
pub const SURFACE_AUTHZ_ADMIN: &str = "authz-admin";

// --------------------------------------------------------------------------- //
// Closed action vocabulary (design D3). Adding an action is a deliberate,
// reviewed change to this list — the store rejects anything outside it.
// --------------------------------------------------------------------------- //

/// `PUT /authz/{sub}/roles` — global role assigned.
pub const ACTION_ROLE_ASSIGN: &str = "role.assign";
/// `DELETE /authz/{sub}/roles/{role}` — global role revoked.
pub const ACTION_ROLE_REVOKE: &str = "role.revoke";
/// `PUT /authz/{sub}/entitlements` — entitlement granted.
pub const ACTION_ENTITLEMENT_GRANT: &str = "entitlement.grant";
/// `DELETE /authz/{sub}/entitlements/{entitlement}` — entitlement revoked.
pub const ACTION_ENTITLEMENT_REVOKE: &str = "entitlement.revoke";
/// `POST /authz/{sub}/suspend` — subject suspended.
pub const ACTION_SUBJECT_SUSPEND: &str = "subject.suspend";
/// `POST /authz/{sub}/reactivate` — subject reactivated.
pub const ACTION_SUBJECT_REACTIVATE: &str = "subject.reactivate";
/// `POST /apikeys` — customer PAT issued.
pub const ACTION_APIKEY_ISSUE: &str = "apikey.issue";
/// `POST /apikeys/{key_id}/rotate` — customer PAT rotated.
pub const ACTION_APIKEY_ROTATE: &str = "apikey.rotate";
/// `POST /apikeys/{key_id}/revoke` — customer PAT revoked.
pub const ACTION_APIKEY_REVOKE: &str = "apikey.revoke";
/// `POST /admin-tokens` — named admin credential issued.
pub const ACTION_ADMIN_TOKEN_ISSUE: &str = "admin_token.issue";
/// `POST /admin-tokens/{id}/rotate` — credential rotated under its lineage.
pub const ACTION_ADMIN_TOKEN_ROTATE: &str = "admin_token.rotate";
/// `POST /admin-tokens/{id}/revoke` — credential revoked.
pub const ACTION_ADMIN_TOKEN_REVOKE: &str = "admin_token.revoke";
/// The break-glass startup grant of the initial administrator (design D8).
pub const ACTION_BOOTSTRAP_GRANT: &str = "bootstrap.grant";
/// Rejected admin authentication (401) — recorded best-effort, never in a
/// mutation transaction (no mutation exists).
pub const ACTION_AUTH_DENIED: &str = "auth.denied";

/// The closed vocabulary, in one place, so membership is checkable.
pub const ACTIONS: [&str; 14] = [
    ACTION_ROLE_ASSIGN,
    ACTION_ROLE_REVOKE,
    ACTION_ENTITLEMENT_GRANT,
    ACTION_ENTITLEMENT_REVOKE,
    ACTION_SUBJECT_SUSPEND,
    ACTION_SUBJECT_REACTIVATE,
    ACTION_APIKEY_ISSUE,
    ACTION_APIKEY_ROTATE,
    ACTION_APIKEY_REVOKE,
    ACTION_ADMIN_TOKEN_ISSUE,
    ACTION_ADMIN_TOKEN_ROTATE,
    ACTION_ADMIN_TOKEN_REVOKE,
    ACTION_BOOTSTRAP_GRANT,
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
/// Auth explicitly disabled at startup (trusted-network/dev only).
pub const ACTOR_AUTH_DISABLED: &str = "auth-disabled";
/// The break-glass bootstrap mechanism (design D8) — a system actor.
pub const ACTOR_BOOTSTRAP: &str = "bootstrap";
/// The actor recorded on a denial event: nobody authenticated.
pub const ACTOR_UNAUTHENTICATED: &str = "unauthenticated";

/// Outcome value for a successful mutation.
pub const OUTCOME_OK: &str = "ok";
/// Outcome value for an idempotency-key replay (`created: false`).
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
    /// reserved actor id. Never credential material.
    pub actor: String,
    /// The caller-asserted human operator (`x-acting-operator`), verbatim.
    pub asserted_operator: Option<String>,
    /// Request correlation (W3C `traceparent`) where present.
    pub trace_id: Option<String>,
    /// Caller network source.
    pub source_ip: Option<String>,
}

impl AuditCtx {
    /// A system-actor context for non-HTTP mutations (e.g. the bootstrap
    /// grant): no transport facts exist, only the reserved actor id.
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

/// Why an admin authentication was rejected — without ever carrying the
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

    use super::{is_known_action, AuditCtx, DenialKind, ACTIONS, ACTOR_BOOTSTRAP};

    #[test]
    fn vocabulary_is_closed() {
        assert!(is_known_action("role.assign"), "known actions are members");
        assert!(!is_known_action("role.rename"), "unknown actions are rejected");
        assert!(!is_known_action(""), "empty is rejected");
    }

    #[test]
    fn vocabulary_has_no_duplicates() {
        let unique: BTreeSet<&str> = ACTIONS.into_iter().collect();
        assert_eq!(unique.len(), ACTIONS.len(), "each action appears exactly once");
    }

    #[test]
    fn system_ctx_carries_only_the_actor() {
        let ctx = AuditCtx::system(ACTOR_BOOTSTRAP);
        assert_eq!(ctx.actor, ACTOR_BOOTSTRAP);
        assert!(ctx.asserted_operator.is_none() && ctx.trace_id.is_none(), "no transport facts");
    }

    #[test]
    fn denial_kinds_have_stable_ledger_words() {
        assert_eq!(DenialKind::Absent.as_str(), "absent");
        assert_eq!(DenialKind::Invalid.as_str(), "invalid");
    }
}
