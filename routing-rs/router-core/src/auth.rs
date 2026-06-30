//! Per-route authentication policy (RFC N4, phase 1) — pure domain logic for the
//! edge's anonymous-pass-through-vs-protected decision. The tenant-router resolves
//! a policy per `(domain, path)` and the edge enacts it; this module holds only
//! the value types and the deterministic resolution rule. Vendor-free (rules §2),
//! data-driven (rules §1.3/§5: the rules come from the store, never a constant).
//!
//! Two-knob separation (N4): authentication *method* (password/passkey/MFA/SSO)
//! stays in the IdP; this is route *protection* only — "must this path carry a
//! verified credential, or may it pass through anonymously?". Phase 1 covers the
//! single boolean `required`; role/entitlement/min-AAL gating is a later phase.
//!
//! Default is **pass-through** (`required = false`): a tenant with no policy, or a
//! path matching no rule, is public. That makes "any customer site works with zero
//! URL constraints" the zero-config behavior; protection is opt-in (the upsell).

use serde::{Deserialize, Serialize};

/// The protection decision for one route: phase 1 is the single authentication
/// gate. `required = false` → anonymous pass-through (jwt_authn `allow_missing`);
/// `required = true` → a verified credential is demanded (jwt_authn `provider`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAuth {
    pub required: bool,
}

impl RouteAuth {
    /// The zero-config decision: public (anonymous pass-through).
    pub const PASS_THROUGH: RouteAuth = RouteAuth { required: false };
}

impl Default for RouteAuth {
    fn default() -> Self {
        RouteAuth::PASS_THROUGH
    }
}

/// One path override: a request-path **prefix** and the protection it carries.
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
    pub fn new(rules: Vec<PathRule>) -> Self {
        Self { rules }
    }

    /// The configured rules (unordered) — for the control-plane list endpoint and
    /// diagnostics. Resolution does not depend on their order.
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
    pub fn resolve(&self, path: &str) -> RouteAuth {
        self.rules
            .iter()
            .filter(|r| prefix_matches(&r.prefix, path))
            .max_by_key(|r| r.prefix.len())
            .map(|r| r.auth)
            .unwrap_or(RouteAuth::PASS_THROUGH)
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
    match path.strip_prefix(prefix) {
        // Boundary: either the rule prefix already ends at a separator (`/app/`)
        // or the path continues with one (`/app` vs `/app/orders`).
        Some(rest) => prefix.ends_with('/') || rest.starts_with('/'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(prefix: &str, required: bool) -> PathRule {
        PathRule { prefix: prefix.into(), auth: RouteAuth { required } }
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
    fn serde_round_trips() {
        let p = AuthPolicy::new(vec![rule("/", true), rule("/blog", false)]);
        let json = serde_json::to_string(&p).unwrap();
        let back: AuthPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn deserializes_from_absent_rules() {
        // #[serde(default)] keeps an old cached RoutingDecision (no `auth` block)
        // deserializable as the pass-through default.
        let p: AuthPolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, AuthPolicy::default());
        assert!(!p.resolve("/").required);
    }
}
