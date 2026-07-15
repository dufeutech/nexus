//! Admin-plane authorization — core types and the decision port
//! (admin-plane-authorization).
//!
//! After authentication resolves an admin caller to an identifiable actor
//! (admin-action-audit), every admin action is AUTHORIZED against the actor's
//! granted scopes before it executes: deny-by-default, fail-closed, each
//! outcome carrying an auditable reason (the same contract the platform's
//! `authorization-policy-engine` spec pins for the edge gate — this surface is
//! its second consumer). This module holds the abstract WHAT: the closed scope
//! vocabulary, the action classes the admin surface groups its routes into,
//! the decision request/outcome shapes, and the vendor-agnostic decision port.
//! The concrete engine (design D1: the adopted Cedar crate) is an adapter in a
//! separate crate that implements [`AdminPolicyDecisionPoint`]; no engine type
//! appears here, so the engine stays a reversible swap (rules §2).

use std::error::Error;
use std::fmt;

use serde::Serialize;

// --------------------------------------------------------------------------- //
// Closed scope vocabulary (design D3). Adding a scope is a deliberate,
// reviewed change to this list — the store rejects anything else at write
// time, so a typo'd grant can never enter a credential.
// --------------------------------------------------------------------------- //

/// Read access: tenancy/domain/auth-route GETs and audit query/export.
pub const SCOPE_READ: &str = "read";
/// Mutations of platform data: accounts, workspaces, memberships, domains,
/// auth-route rules.
pub const SCOPE_PROVISION: &str = "provision";
/// Admin-credential administration (mint/rotate/revoke/list). Distinguished:
/// no other scope includes it, so an ordinary credential can never expand its
/// own grant or destroy another caller's (spec "Credential administration is
/// a distinguished privilege").
pub const SCOPE_TOKEN_ADMIN: &str = "token-admin";

/// The closed vocabulary, in one place, so membership is checkable — and the
/// FULL grant the cutover backfill assigns (spec "Cutover preserves existing
/// callers").
pub const SCOPES: [&str; 3] = [SCOPE_READ, SCOPE_PROVISION, SCOPE_TOKEN_ADMIN];

/// Whether `scope` is in the closed vocabulary. Mint refuses anything else.
#[must_use]
pub fn is_known_scope(scope: &str) -> bool {
    SCOPES.contains(&scope)
}

// --------------------------------------------------------------------------- //
// Action classes: every admin route belongs to exactly one, and the class is
// what a request must hold the matching scope for. A route the surface cannot
// classify is DENIED for every actor (fail-closed), never waved through.
// --------------------------------------------------------------------------- //

/// The action class an admin route belongs to — the unit of authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionClass {
    /// Read-only access (GETs, audit query/export). Requires [`SCOPE_READ`].
    Read,
    /// Platform-data mutation. Requires [`SCOPE_PROVISION`].
    Provision,
    /// Admin-credential administration. Requires [`SCOPE_TOKEN_ADMIN`].
    TokenAdmin,
}

impl ActionClass {
    /// The wire/ledger word for this class (also the Cedar action id).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => SCOPE_READ,
            Self::Provision => SCOPE_PROVISION,
            Self::TokenAdmin => SCOPE_TOKEN_ADMIN,
        }
    }
}

impl fmt::Display for ActionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// --------------------------------------------------------------------------- //
// The decision port (design D2, mirroring the identity plane's
// PolicyDecisionPoint): request in → decision out, deny-by-default. Sync —
// evaluation is in-memory over already-resolved facts; no I/O belongs here.
// --------------------------------------------------------------------------- //

/// The effect of an authorization decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The action is allowed.
    Permit,
    /// The action is refused (the deny-by-default outcome).
    Deny,
}

/// A decision plus a machine-readable reason, so an outcome can be audited
/// without re-running the request (spec: refusals carry a reason; recorded
/// actions carry the permitting reason).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Permit or deny.
    pub effect: Effect,
    /// Why: the permitting policy id, or the absence of any permit / the
    /// failing input (fail-closed).
    pub reason: String,
}

impl Decision {
    /// A permit carrying the reason it was allowed (the permitting policy id).
    #[must_use]
    pub fn permit(reason: impl Into<String>) -> Self {
        Self { effect: Effect::Permit, reason: reason.into() }
    }

    /// A deny carrying the reason it was refused.
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self { effect: Effect::Deny, reason: reason.into() }
    }

    /// Whether this decision permits the action.
    #[must_use]
    pub const fn is_permit(&self) -> bool {
        matches!(self.effect, Effect::Permit)
    }
}

/// One admin authorization question: may `actor` (holding `scopes`) perform an
/// action of `class`? `resource` is the forward-compatibility seam for
/// per-tenant grants (design D6): carried so a future policy can scope a grant
/// to a workspace, deliberately unread by the first-slice policy.
#[derive(Clone, Debug)]
pub struct AdminPolicyRequest<'a> {
    /// The authenticated actor's identifier (attribution only — the decision
    /// reads the grant, not the id).
    pub actor: &'a str,
    /// The actor's granted scopes, as resolved WITH the credential lookup.
    pub scopes: &'a [String],
    /// The action class of the route being invoked.
    pub class: ActionClass,
    /// The targeted resource id (e.g. a workspace id), when the route names
    /// one. Unread by the parity policy; the per-tenant seam.
    pub resource: Option<&'a str>,
}

/// The decision port: evaluates one [`AdminPolicyRequest`] against declarative
/// policy. Implementations MUST be deny-by-default and fail-closed — an
/// evaluation that cannot complete is a deny carrying the failure as its
/// reason, never a permit.
pub trait AdminPolicyDecisionPoint: Send + Sync {
    /// Decide one request. Infallible by design: failures map to a deny.
    fn decide(&self, request: &AdminPolicyRequest<'_>) -> Decision;
}

/// One admin credential as the review surface returns it (spec "A credential's
/// grant is reviewable"): identity, grant, and lifecycle facts — NEVER the
/// secret or its hash.
#[derive(Debug, Clone, Serialize)]
pub struct AdminCredentialRecord {
    /// The public token id (`atk_…`).
    pub token_id: String,
    /// The named caller the credential identifies.
    pub name: String,
    /// `active` or `revoked`.
    pub status: String,
    /// The granted scopes the authorization gate evaluates against.
    pub scopes: Vec<String>,
    /// Rotation lineage: the token this one replaced, when rotated.
    pub rotated_from: Option<String>,
    /// When the credential was created (RFC 3339, DB clock).
    pub created_at: String,
}

/// The lockout guard's typed refusal (spec "The last credential administrator
/// cannot be removed"): revoking (or de-scoping) the only active credential
/// holding [`SCOPE_TOKEN_ADMIN`] would lock the admin plane out of credential
/// administration, so the store refuses and surfaces this for the HTTP layer
/// to answer 409 with the hazard named — never a masked 500.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastTokenAdminGuard;

impl fmt::Display for LastTokenAdminGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "refused: would leave zero active credentials holding token-admin (lockout hazard)",
        )
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "Error's provided methods (source/description/cause/provide/type_id) are \
              deprecated, unstable, or correct by default for a unit error"
)]
impl Error for LastTokenAdminGuard {}

/// The fail-closed stand-in installed when no valid policy set could be
/// loaded (spec "A failed policy load denies all gated actions"): every
/// decision is a deny naming the unavailability, so gated routes refuse
/// loudly instead of running open (or crashing the liveness surface).
#[derive(Debug, Clone, Copy, Default)]
pub struct DenyAllAdminPdp;

impl AdminPolicyDecisionPoint for DenyAllAdminPdp {
    fn decide(&self, _request: &AdminPolicyRequest<'_>) -> Decision {
        Decision::deny("deny:policy-unavailable")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_known_scope, ActionClass, AdminPolicyDecisionPoint, AdminPolicyRequest,
        Decision, DenyAllAdminPdp, SCOPES,
    };

    #[test]
    fn scope_vocabulary_is_closed() {
        assert!(is_known_scope("read"));
        assert!(is_known_scope("provision"));
        assert!(is_known_scope("token-admin"));
        assert!(!is_known_scope("admin"), "unknown scopes are rejected");
        assert!(!is_known_scope(""), "empty is rejected");
        assert_eq!(SCOPES.len(), 3, "the closed vocabulary is exactly the documented set");
    }

    #[test]
    fn action_classes_map_to_their_scope_words() {
        assert_eq!(ActionClass::Read.as_str(), "read");
        assert_eq!(ActionClass::Provision.as_str(), "provision");
        assert_eq!(ActionClass::TokenAdmin.as_str(), "token-admin");
    }

    #[test]
    fn deny_all_denies_everything_with_the_unavailability_reason() {
        let pdp = DenyAllAdminPdp;
        let full: Vec<String> = SCOPES.iter().map(|scope| (*scope).to_owned()).collect();
        let request = AdminPolicyRequest {
            actor: "atk_test",
            scopes: &full,
            class: ActionClass::Read,
            resource: None,
        };
        let decision = pdp.decide(&request);
        assert_eq!(decision, Decision::deny("deny:policy-unavailable"));
        assert!(!decision.is_permit(), "a full grant still denies when no policy loaded");
    }
}
