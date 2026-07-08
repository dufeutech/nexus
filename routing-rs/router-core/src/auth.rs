//! Per-route authentication policy (RFC N4, phase 1) — pure domain logic for the
//! edge's anonymous-pass-through-vs-protected decision. The tenant-router resolves
//! a policy per `(domain, path)` and the edge enacts it; this module holds only
//! the value types and the deterministic resolution rule. Vendor-free (rules §2),
//! data-driven (rules §1.3/§5: the rules come from the store, never a constant).
//!
//! Two-knob separation (N4): authentication *method* (password/passkey/MFA/SSO)
//! stays in the `IdP`; this is route *protection* only. Phase 1 is the boolean
//! `required` gate; phase 2 adds the optional per-rule role / entitlement /
//! minimum-AAL requirements, resolved here and enforced at the edge (403).
//!
//! Default is **pass-through** (`required = false`): a tenant with no policy, or a
//! path matching no rule, is public. That makes "any customer site works with zero
//! URL constraints" the zero-config behavior; protection is opt-in (the upsell).

use serde::{Deserialize, Serialize};

/// The protection decision for one route. `required = false` → anonymous
/// pass-through (`jwt_authn` `allow_missing`); `required = true` → a verified
/// credential is demanded (`jwt_authn` `provider`). The phase-2 requirement
/// fields are optional refinements enforced after authentication: `None` means
/// no requirement (the phase-1 behavior, and the wire absence of the signal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAuth {
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_entitlement: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_aal: Option<u8>,
    /// Whether a *protected* route is scoped to the routed workspace and so gated on
    /// the caller's membership of it (identity-existence-hiding). Default `false`
    /// means **workspace-scoped**: a protected route requires membership and a
    /// non-member is hidden behind a 404. Set `true` to mark an **account-scoped**
    /// route — authenticated but not tied to one workspace (e.g. `/me`,
    /// list-my-workspaces) — which is reachable without a workspace membership.
    /// Only meaningful when `required = true`; the wire signal is emitted only when
    /// `true`, so its absence is the fail-closed (workspace-scoped, gated) state.
    #[serde(default, skip_serializing_if = "is_false")]
    pub account_scoped: bool,
}

/// serde `skip_serializing_if` for the account-scoped flag: the default (`false`,
/// workspace-scoped) is the wire-absent state, mirroring the requirement signals.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if requires a fn taking &T, so the &bool \
              signature is mandated by the API, not a missed by-value opportunity"
)]
const fn is_false(b: &bool) -> bool {
    !*b
}

impl RouteAuth {
    /// The zero-config decision: public (anonymous pass-through).
    pub const PASS_THROUGH: Self = Self {
        required: false,
        requires_role: None,
        requires_entitlement: None,
        min_aal: None,
        account_scoped: false,
    };

    /// True when the rule carries any phase-2 requirement.
    #[must_use]
    pub const fn has_requirements(&self) -> bool {
        self.requires_role.is_some()
            || self.requires_entitlement.is_some()
            || self.min_aal.is_some()
    }

    /// Fail-closed interpretation: a rule carrying any requirement demands a
    /// verified credential, even if the stored row says otherwise (the CRUD
    /// surface rejects that combination, but a hand-edited row must not open
    /// an authorization-gated route to anonymous callers).
    #[must_use]
    pub const fn normalized(mut self) -> Self {
        if self.has_requirements() {
            self.required = true;
        }
        self
    }
}

impl Default for RouteAuth {
    fn default() -> Self {
        Self::PASS_THROUGH
    }
}

/// One path override: a request-path **prefix** and the protection it carries.
///
/// The prefix matches at *segment boundaries* (see [`AuthPolicy::resolve`]) so
/// `/app` covers `/app` and `/app/…` but never `/application`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathRule {
    pub prefix: String,
    pub auth: RouteAuth,
}

/// A tenant's route-protection policy: a flat set of path-prefix rules. Resolution
/// is **longest-matching-prefix wins** (so a specific `/app` override beats the
/// tenant-wide `/` default), which is order-free and therefore needs no priority
/// column in the store. A path matching no rule is pass-through.
///
/// The per-tenant *default* is just the rule whose prefix is `/` (it matches every
/// path and is, by construction, the shortest possible prefix — hence the lowest
/// priority). Representing the default as an ordinary `/` rule keeps the store and
/// the CRUD surface uniform: one table, one resolution rule, no special case.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicy {
    #[serde(default)]
    rules: Vec<PathRule>,
}

impl AuthPolicy {
    #[must_use]
    pub const fn new(rules: Vec<PathRule>) -> Self {
        Self { rules }
    }

    /// The configured rules (unordered) — for the control-plane list endpoint and
    /// diagnostics. Resolution does not depend on their order.
    #[must_use]
    pub fn rules(&self) -> &[PathRule] {
        &self.rules
    }

    /// Resolve the protection for a request path: the [`RouteAuth`] of the rule
    /// with the **longest matching prefix**, or pass-through when none matches.
    /// Pure, total, deterministic — the same path always yields the same decision.
    ///
    /// Matching is at segment boundaries: a rule prefix `p` matches path `path`
    /// iff `path == p`, or `path` starts with `p` and the next character is `/`
    /// (or `p` itself ends with `/`). This prevents `/app` from matching
    /// `/application` while still covering `/app/orders`. Paths are case-sensitive
    /// (unlike hosts) and compared verbatim; the caller strips any query string.
    #[must_use]
    pub fn resolve(&self, path: &str) -> RouteAuth {
        self.rules
            .iter()
            .filter(|r| prefix_matches(&r.prefix, path))
            .max_by_key(|r| r.prefix.len())
            .map_or(RouteAuth::PASS_THROUGH, |r| r.auth.clone().normalized())
    }
}

/// Segment-boundary prefix match (see [`AuthPolicy::resolve`]). An empty prefix
/// never matches (a malformed rule must not silently become a catch-all); the
/// catch-all is the explicit `/` prefix.
fn prefix_matches(prefix: &str, path: &str) -> bool {
    if prefix.is_empty() {
        return false;
    }
    if path == prefix {
        return true;
    }
    // Boundary: either the rule prefix already ends at a separator (`/app/`)
    // or the path continues with one (`/app` vs `/app/orders`).
    path.strip_prefix(prefix)
        .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: &str, required: bool) -> PathRule {
        PathRule {
            prefix: prefix.into(),
            auth: RouteAuth { required, ..RouteAuth::PASS_THROUGH },
        }
    }

    #[test]
    fn empty_policy_is_pass_through() {
        let p = AuthPolicy::default();
        assert!(!p.resolve("/").required);
        assert!(!p.resolve("/anything/here").required);
    }

    #[test]
    fn tenant_default_via_root_rule_applies_when_nothing_more_specific() {
        // `/` is the per-tenant default: protect the whole site.
        let p = AuthPolicy::new(vec![rule("/", true)]);
        assert!(p.resolve("/").required);
        assert!(p.resolve("/app/orders").required);
    }

    #[test]
    fn longest_prefix_wins_over_default() {
        // Protect everything by default, but carve out a public marketing path.
        let p = AuthPolicy::new(vec![rule("/", true), rule("/blog", false)]);
        assert!(p.resolve("/app").required); // default
        assert!(!p.resolve("/blog").required); // override
        assert!(!p.resolve("/blog/post-1").required); // override covers subtree
    }

    #[test]
    fn public_default_with_private_carveout() {
        // Public by default, lock down /app — the common SaaS shape.
        let p = AuthPolicy::new(vec![rule("/app", true)]);
        assert!(!p.resolve("/").required); // no `/` rule -> pass-through default
        assert!(!p.resolve("/pricing").required);
        assert!(p.resolve("/app").required);
        assert!(p.resolve("/app/settings").required);
    }

    #[test]
    fn prefix_matches_only_at_segment_boundary() {
        let p = AuthPolicy::new(vec![rule("/app", true)]);
        assert!(p.resolve("/app").required);
        assert!(p.resolve("/app/x").required);
        // /application must NOT inherit the /app rule.
        assert!(!p.resolve("/application").required);
    }

    #[test]
    fn trailing_slash_prefix_is_a_clean_boundary() {
        let p = AuthPolicy::new(vec![rule("/api/", true)]);
        assert!(p.resolve("/api/").required);
        assert!(p.resolve("/api/v1").required);
        assert!(!p.resolve("/api").required); // `/api` is not under `/api/`
    }

    #[test]
    fn empty_prefix_never_catches() {
        // A malformed empty-prefix rule must not become an accidental catch-all.
        let p = AuthPolicy::new(vec![rule("", true)]);
        assert!(!p.resolve("/").required);
        assert!(!p.resolve("/x").required);
    }

    #[test]
    fn most_specific_among_several_wins() {
        let p = AuthPolicy::new(vec![
            rule("/", false),
            rule("/app", true),
            rule("/app/public", false),
        ]);
        assert!(!p.resolve("/").required);
        assert!(p.resolve("/app").required);
        assert!(p.resolve("/app/orders").required);
        assert!(!p.resolve("/app/public").required); // longest prefix wins
        assert!(!p.resolve("/app/public/logo.png").required);
    }

    #[test]
    fn requirements_ride_the_matched_rule() {
        let gated = PathRule {
            prefix: "/admin".into(),
            auth: RouteAuth {
                required: true,
                requires_role: Some("admin".into()),
                requires_entitlement: Some("pro".into()),
                min_aal: Some(2),
                ..RouteAuth::PASS_THROUGH
            },
        };
        let p = AuthPolicy::new(vec![rule("/", true), gated]);
        let hit = p.resolve("/admin/users");
        assert_eq!(hit.requires_role.as_deref(), Some("admin"));
        assert_eq!(hit.requires_entitlement.as_deref(), Some("pro"));
        assert_eq!(hit.min_aal, Some(2));
        // A path matching only the phase-1 rule carries no requirements.
        let miss = p.resolve("/app");
        assert!(miss.required && !miss.has_requirements());
    }

    #[test]
    fn requirement_implies_required_fail_closed() {
        // A hand-edited row combining a requirement with required=false must
        // resolve as protected, never as anonymous pass-through.
        let inconsistent = PathRule {
            prefix: "/members".into(),
            auth: RouteAuth {
                required: false,
                requires_entitlement: Some("member".into()),
                ..RouteAuth::PASS_THROUGH
            },
        };
        let p = AuthPolicy::new(vec![inconsistent]);
        let hit = p.resolve("/members");
        assert!(hit.required);
        assert_eq!(hit.requires_entitlement.as_deref(), Some("member"));
    }

    #[test]
    fn phase1_json_without_requirement_fields_deserializes() -> Result<(), serde_json::Error> {
        // A cached phase-1 RouteAuth (only `required`) must keep deserializing;
        // the new fields default to None (no requirement).
        let auth: RouteAuth = serde_json::from_str(r#"{"required":true}"#)?;
        assert!(auth.required && !auth.has_requirements());
        Ok(())
    }

    #[test]
    fn account_scoped_defaults_to_false_and_rides_the_rule() -> Result<(), serde_json::Error> {
        // A protected rule with no account_scoped field is workspace-scoped
        // (gated) — the fail-closed default for existence-hiding.
        let gated: RouteAuth = serde_json::from_str(r#"{"required":true}"#)?;
        assert!(!gated.account_scoped);
        // An explicit account-scoped rule (e.g. /me) rides the resolved rule.
        let account = PathRule {
            prefix: "/me".into(),
            auth: RouteAuth { required: true, account_scoped: true, ..RouteAuth::PASS_THROUGH },
        };
        let p = AuthPolicy::new(vec![rule("/", true), account]);
        assert!(p.resolve("/me").account_scoped); // account-scoped: not gated
        assert!(!p.resolve("/app").account_scoped); // default: workspace-scoped, gated
        Ok(())
    }

    #[test]
    fn account_scoped_is_wire_absent_when_false() -> Result<(), serde_json::Error> {
        // The default (workspace-scoped) must not appear on the wire, mirroring the
        // requirement signals — absence IS the fail-closed gated state.
        let workspace_scoped = RouteAuth { required: true, ..RouteAuth::PASS_THROUGH };
        let json = serde_json::to_string(&workspace_scoped)?;
        assert!(!json.contains("account_scoped"));
        let account = RouteAuth { required: true, account_scoped: true, ..RouteAuth::PASS_THROUGH };
        assert!(serde_json::to_string(&account)?.contains("account_scoped"));
        Ok(())
    }

    #[test]
    fn serde_round_trips() -> Result<(), serde_json::Error> {
        let p = AuthPolicy::new(vec![rule("/", true), rule("/blog", false)]);
        let json = serde_json::to_string(&p)?;
        let back: AuthPolicy = serde_json::from_str(&json)?;
        assert_eq!(p, back);
        Ok(())
    }

    #[test]
    fn deserializes_from_absent_rules() -> Result<(), serde_json::Error> {
        // #[serde(default)] keeps an old cached RoutingDecision (no `auth` block)
        // deserializable as the pass-through default.
        let p: AuthPolicy = serde_json::from_str("{}")?;
        assert_eq!(p, AuthPolicy::default());
        assert!(!p.resolve("/").required);
        Ok(())
    }
}
