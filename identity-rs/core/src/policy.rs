//! The Policy Decision Point (PDP) — the platform's L2 authorization decision seam.
//!
//! Fact *resolution* ([`AuthzResolver`](crate::authz::AuthzResolver) →
//! [`AuthzFacts`]) and the *decision* are different concerns (design Decision 1), so
//! the decision gets its own vendor-agnostic port here rather than overloading the
//! resolver. A [`PolicyDecisionPoint`] evaluates a request's
//! **(principal, action, resource, context)** against declarative policy and returns a
//! [`Decision`] — **deny-by-default**, **fail-closed**, each outcome carrying an
//! auditable reason (`authorization-policy-engine` spec).
//!
//! No engine type appears in this module: the concrete engine (Cedar) is an adapter in
//! a separate crate that implements [`PolicyDecisionPoint`], so it is a reversible
//! swap and neither `core` nor the sidecar imports the engine crate (CLAUDE.md
//! "an adapter isolates every dependency").

use crate::authz::AuthzFacts;

/// The effect of an authorization decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The request is allowed.
    Permit,
    /// The request is denied (the deny-by-default outcome).
    Deny,
}

/// A decision plus a machine-readable reason, so an outcome can be audited without
/// re-running the request (`authorization-policy-engine` spec: "each decision carries
/// an auditable reason").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// Permit or deny.
    pub effect: Effect,
    /// Why: the permitting policy id, or the absence of any permit / the failing input.
    pub reason: String,
}

impl Decision {
    /// A permit carrying the reason it was allowed (e.g. the permitting policy id).
    #[must_use]
    pub fn permit(reason: impl Into<String>) -> Self {
        Self { effect: Effect::Permit, reason: reason.into() }
    }

    /// A deny carrying the reason it was refused (no permitting policy, or a
    /// missing/unparseable input that failed closed).
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self { effect: Effect::Deny, reason: reason.into() }
    }

    /// True only for [`Effect::Permit`]. Deny-by-default: anything that is not an
    /// explicit permit is a deny.
    #[must_use]
    pub const fn is_permit(&self) -> bool {
        matches!(self.effect, Effect::Permit)
    }
}

/// The action a request seeks. A single `access` verb today — there is no per-HTTP-method
/// authorization dimension (the method only feeds assurance level). Kept as an enum so a
/// later change can add verbs without reshaping the request (design Decision 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Access the resolved route.
    Access,
}

/// A resolved minimum-assurance-level requirement for a route.
///
/// The three states are exactly what parity needs: an **absent** requirement is not
/// checked at all (matching `authorize_route`'s `Option` = `None`); a **present** level
/// (including `0`) requires the principal to carry a mapped assurance level that meets
/// it; a present-but-**unparseable** requirement is one we cannot evaluate and MUST
/// fail closed (deny), never vanish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MinAal {
    /// No AAL requirement on this route — the AAL dimension is skipped.
    None,
    /// The route requires at least this assurance level (a present requirement; `0`
    /// still requires the principal to carry a mapped level).
    Least(i64),
    /// A requirement was present but could not be parsed — fail closed (deny).
    Unparseable,
}

impl MinAal {
    /// Resolve a raw `x-auth-min-aal` signal into a requirement. `None` (header absent)
    /// is no requirement; a parseable integer (including `0`) is a present requirement;
    /// anything else is [`MinAal::Unparseable`] and will deny. This mirrors
    /// `RouteRequirements.min_aal` staying raw so an unparseable value denies rather
    /// than silently disappearing.
    #[must_use]
    pub fn from_raw(raw: Option<&str>) -> Self {
        match raw {
            None => Self::None,
            Some(value) => match value.parse::<i64>() {
                Ok(level) => Self::Least(level),
                Err(_) => Self::Unparseable,
            },
        }
    }
}

/// The subject of a decision: nexus-authored authorization facts plus the request's
/// resolved assurance level and principal kind. Roles/entitlements are always present
/// (possibly empty), so a set requirement against empty enrichment denies; `aal` is
/// `None` when the authentication method did not map to a level (fail-closed on any
/// present AAL requirement).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPrincipal {
    /// The principal kind label (`user`/`service`/`apikey`); carried for forward use.
    pub kind: String,
    /// Coarse global roles nexus authored for the subject (empty = none held).
    pub roles: Vec<String>,
    /// Global entitlements nexus authored for the subject (empty = none held).
    pub entitlements: Vec<String>,
    /// The assurance level of the authentication method, or `None` if the method did
    /// not map to a level (an AAL requirement then cannot be met — fail-closed).
    pub aal: Option<i64>,
    /// Whether nexus has suspended the subject. Carried but inert in the parity policy.
    pub suspended: bool,
}

impl PolicyPrincipal {
    /// Build the principal from nexus-authored [`AuthzFacts`] plus the request's
    /// resolved assurance level and principal kind. The sidecar only supplies these —
    /// it never decides.
    #[must_use]
    pub fn from_facts(facts: &AuthzFacts, aal: Option<i64>, kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            roles: facts.roles.clone(),
            entitlements: facts.entitlements.clone(),
            aal,
            suspended: facts.is_suspended,
        }
    }
}

/// The resource of a decision: the per-route requirements the tenant-router resolved,
/// carried as data. An empty-string role/entitlement requirement is "no requirement"
/// (design Decision 2, `"" = none`); `min_aal` carries the three-state requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyResource {
    /// The required role, or `""` for no role requirement.
    pub requires_role: String,
    /// The required entitlement, or `""` for no entitlement requirement.
    pub requires_entitlement: String,
    /// The minimum assurance level requirement (absent / present-level / unparseable).
    pub min_aal: MinAal,
    /// Whether the route is account-scoped. Carried but inert in the parity policy.
    pub account_scoped: bool,
}

impl PolicyResource {
    /// Build the resource from the resolved per-route requirement signals — the exact
    /// fields the sidecar reads from the trusted `x-auth-*` headers. `None` role /
    /// entitlement map to `""` (no requirement); the raw min-AAL is resolved via
    /// [`MinAal::from_raw`]. Pure translation of resolved data — no decision here.
    #[must_use]
    pub fn from_requirements(
        role: Option<&str>,
        entitlement: Option<&str>,
        min_aal_raw: Option<&str>,
        account_scoped: bool,
    ) -> Self {
        Self {
            requires_role: role.unwrap_or("").to_owned(),
            requires_entitlement: entitlement.unwrap_or("").to_owned(),
            min_aal: MinAal::from_raw(min_aal_raw),
            account_scoped,
        }
    }
}

/// Ambient decision context — carried for forward-compatibility (geo/plan/method are
/// present in the schema but unreferenced by the parity policy, design Decision 2).
/// Empty today.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicyContext {
    /// The caller's resolved geo/residency, if any. Inert in the parity policy.
    pub geo: Option<String>,
    /// The acting workspace's plan tier, if any. Inert in the parity policy.
    pub plan: Option<String>,
}

/// A complete authorization query: who (principal), doing what (action), to what
/// (resource), in what ambient context. The enforcement surface builds this and asks
/// the [`PolicyDecisionPoint`]; the surface never compares attributes itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRequest {
    /// The subject and its nexus-authored facts.
    pub principal: PolicyPrincipal,
    /// The verb (single `access` today).
    pub action: Action,
    /// The route and its resolved requirements.
    pub resource: PolicyResource,
    /// Ambient context (inert today).
    pub context: PolicyContext,
}

/// The vendor-agnostic authorization decision boundary (design Decision 1). An adapter
/// evaluates the request against declarative policy and returns a [`Decision`]:
/// **deny-by-default** (a request no policy permits is denied) and **fail-closed** (a
/// missing or unparseable input denies, never permits).
///
/// Synchronous by design: the decision is in-process, microsecond-scale policy
/// evaluation on the sidecar hot path (no I/O), so it does not need the async ports'
/// shape.
pub trait PolicyDecisionPoint: Send + Sync {
    /// Decide the request. Implementations MUST deny by default and fail closed; the
    /// returned [`Decision`] MUST carry an auditable reason for either outcome.
    fn decide(&self, request: &PolicyRequest) -> Decision;
}

/// A fail-closed PDP that denies every request. Installed by an enforcement surface
/// when the real policy engine cannot load or validate its policy set (design
/// Decision 3, `authorization-policy-engine` spec "a malformed policy set fails closed
/// at load"): the surface refuses to serve gated routes rather than evaluate an
/// empty/partial set. Ungated routes never call the PDP, so they still pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct DenyAllPdp;

impl PolicyDecisionPoint for DenyAllPdp {
    fn decide(&self, _request: &PolicyRequest) -> Decision {
        Decision::deny("policy engine unavailable — failing closed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_is_not_permit() {
        let deny = Decision::deny("no-permit");
        assert!(!deny.is_permit());
        assert_eq!(deny.effect, Effect::Deny);
        assert_eq!(deny.reason, "no-permit");
    }

    #[test]
    fn permit_carries_reason() {
        let permit = Decision::permit("policy0");
        assert!(permit.is_permit());
        assert_eq!(permit.reason, "policy0");
    }

    #[test]
    fn min_aal_from_raw_absent_is_none() {
        assert_eq!(MinAal::from_raw(None), MinAal::None);
    }

    #[test]
    fn min_aal_from_raw_zero_is_a_present_requirement() {
        // Parity: `Some("0")` is a PRESENT requirement — the principal must still carry
        // a mapped level (any level ≥ 0), unlike an absent requirement which is skipped.
        assert_eq!(MinAal::from_raw(Some("0")), MinAal::Least(0));
        assert_eq!(MinAal::from_raw(Some("2")), MinAal::Least(2));
    }

    #[test]
    fn min_aal_from_raw_garbage_is_unparseable() {
        assert_eq!(MinAal::from_raw(Some("high")), MinAal::Unparseable);
        assert_eq!(MinAal::from_raw(Some("")), MinAal::Unparseable);
    }

    #[test]
    fn principal_projects_from_facts() {
        let facts = AuthzFacts {
            roles: vec!["admin".to_owned()],
            entitlements: vec!["pro".to_owned()],
            is_suspended: true,
        };
        let principal = PolicyPrincipal::from_facts(&facts, Some(1), "user");
        assert_eq!(principal.roles, vec!["admin".to_owned()]);
        assert_eq!(principal.entitlements, vec!["pro".to_owned()]);
        assert_eq!(principal.aal, Some(1));
        assert!(principal.suspended);
        assert_eq!(principal.kind, "user");
    }

    #[test]
    fn resource_maps_absent_requirements_to_empty() {
        let resource = PolicyResource::from_requirements(None, None, None, false);
        assert_eq!(resource.requires_role, "");
        assert_eq!(resource.requires_entitlement, "");
        assert_eq!(resource.min_aal, MinAal::None);
        assert!(!resource.account_scoped);
    }

    #[test]
    fn resource_carries_present_requirements() {
        let resource =
            PolicyResource::from_requirements(Some("admin"), Some("pro"), Some("2"), true);
        assert_eq!(resource.requires_role, "admin");
        assert_eq!(resource.requires_entitlement, "pro");
        assert_eq!(resource.min_aal, MinAal::Least(2));
        assert!(resource.account_scoped);
    }
}
