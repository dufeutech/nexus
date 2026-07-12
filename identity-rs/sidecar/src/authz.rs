//! The route-requirement authorization concern: the production PDP path
//! ([`decide_route_requirements`]) that gates a route on its resolved requirements,
//! the pure translation into a vendor-agnostic [`PolicyRequest`], and the
//! `#[cfg(test)]` parity oracle the gate tests compare it against.

use std::collections::HashMap;
use std::sync::Arc;

use identity_core::{
    Action, AuthzFacts, PolicyContext, PolicyDecisionPoint, PolicyPrincipal, PolicyRequest,
    PolicyResource, Profile,
};

use crate::extract::RouteRequirements;

/// The N4 phase-2 authorization comparison — the hand-coded requirement check that the
/// PDP (`decide_route_requirements`) now replaces in production (adopt-cedar-policy-gate).
/// Retained ONLY as the `#[cfg(test)]` **parity oracle**: the parity harness runs the
/// full input matrix through both this and the PDP and asserts identical effects, and
/// the existing gate tests still pin its exact behavior. EVERY resolved requirement must
/// be satisfied by the enrichment this filter itself computed (never by request headers);
/// a requirement that cannot be evaluated — no enrichment to compare, an unmapped method,
/// an unparseable level — DENIES, so degraded state can never open a gated route.
#[cfg(test)]
fn authorize_route(
    reqs: &RouteRequirements,
    roles: &[String],
    entitlements: Option<&[String]>,
    method_level: Option<u8>,
) -> Result<(), &'static str> {
    if let Some(role) = &reqs.role
        && !roles.iter().any(|r| r == role)
    {
        return Err("role");
    }
    if let Some(needed) = &reqs.entitlement {
        match entitlements {
            Some(list) if list.iter().any(|e| e == needed) => {}
            _ => return Err("entitlement"),
        }
    }
    if let Some(min) = &reqs.min_aal {
        let Ok(min) = min.parse::<u8>() else {
            return Err("min_aal_unparseable");
        };
        match method_level {
            Some(level) if level >= min => {}
            _ => return Err("aal"),
        }
    }
    Ok(())
}

/// Gather the comparison inputs from the in-process enrichment state and run
/// [`authorize_route`]. Roles and entitlements are **nexus-authored** (spec R1):
/// sourced ONLY from the live Profile (the AuthzResolver's backing), never the
/// token — so an absent Profile means no roles/entitlements (deny-by-default). The
/// method mirrors the emitted `x-auth-method`.
///
/// `#[cfg(test)]` — the production gate now runs [`decide_route_requirements`] (the PDP);
/// this remains as the parity oracle the tests compare against (adopt-cedar-policy-gate).
#[cfg(test)]
pub(crate) fn enforce_route_requirements(
    reqs: &RouteRequirements,
    profile: Option<&Arc<Profile>>,
    authenticated: bool,
    aal_levels: &HashMap<String, u8>,
) -> Result<(), &'static str> {
    if !reqs.any() {
        return Ok(());
    }
    let roles: &[String] = profile.map_or(&[], |p| &p.roles);
    let entitlements = profile.map(|p| p.entitlements.as_slice());
    let method = if authenticated { "bearer" } else { "none" };
    authorize_route(reqs, roles, entitlements, aal_levels.get(method).copied())
}

/// Translate the in-process enrichment + resolved route requirements into a
/// vendor-agnostic [`PolicyRequest`] for the PDP (adopt-cedar-policy-gate). Pure
/// translation — the sidecar never decides: roles/entitlements are the nexus-authored
/// facts (empty when no Profile ⇒ deny-by-default); the method maps to an assurance
/// level (a method absent from the ordering ⇒ `None` ⇒ any min-AAL requirement fails
/// closed); the resolved `x-auth-*` signals become the resource requirements. `kind` is
/// carried but inert; `account_scoped` is inert in the parity policy (not decided on),
/// so it is passed as `false` rather than threaded through the hot path — a later change
/// that decides on it would carry the real value.
fn build_policy_request(
    reqs: &RouteRequirements,
    profile: Option<&Arc<Profile>>,
    authenticated: bool,
    aal_levels: &HashMap<String, u8>,
) -> PolicyRequest {
    let facts = profile.map(|p| AuthzFacts::from(p.as_ref())).unwrap_or_default();
    let method = if authenticated { "bearer" } else { "none" };
    let aal = aal_levels.get(method).map(|level| i64::from(*level));
    let kind = if authenticated { "authenticated" } else { "anonymous" };
    PolicyRequest {
        principal: PolicyPrincipal::from_facts(&facts, aal, kind),
        action: Action::Access,
        resource: PolicyResource::from_requirements(
            reqs.role.as_deref(),
            reqs.entitlement.as_deref(),
            reqs.min_aal.as_deref(),
            false, // account_scoped — inert in the parity policy (design Non-Goal)
        ),
        context: PolicyContext::default(),
    }
}

/// The production authorization step (adopt-cedar-policy-gate): build the PDP request
/// from the in-process enrichment + resolved requirements and ask the policy engine,
/// mapping a deny to the caller's 403 with the engine's auditable reason. An ungated
/// route (no requirements) short-circuits to pass WITHOUT consulting the PDP — so a
/// failed-to-load policy set (a [`DenyAllPdp`]) refuses only GATED routes, leaving
/// public routes served. Replaces the hand-coded [`enforce_route_requirements`] at
/// strict behavioral parity.
pub(crate) fn decide_route_requirements(
    pdp: &dyn PolicyDecisionPoint,
    reqs: &RouteRequirements,
    profile: Option<&Arc<Profile>>,
    authenticated: bool,
    aal_levels: &HashMap<String, u8>,
) -> Result<(), String> {
    if !reqs.any() {
        return Ok(());
    }
    let request = build_policy_request(reqs, profile, authenticated, aal_levels);
    let decision = pdp.decide(&request);
    if decision.is_permit() {
        Ok(())
    } else {
        Err(decision.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;

    /// Spec "Satisfied requirements pass to the backend" + "Phase-1 parity".
    #[test]
    fn satisfied_requirements_pass() {
        let p = gated_profile(&["admin"], &["pro"]);
        assert_eq!(
            enforce_route_requirements(
                &reqs(Some("admin"), Some("pro"), Some("1")),
                Some(&p),
                true,
                &levels(),
            ),
            Ok(()),
        );
        // No signals -> no enforcement, regardless of enrichment state.
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, None), None, false, &levels()),
            Ok(()),
        );
    }

    /// Spec "Missing role is rejected" — roles are nexus-authored only (spec R1), so
    /// only a role on the Profile satisfies a role requirement; there is no token
    /// path (see `role_claiming_token_confers_nothing`).
    #[test]
    fn missing_role_is_denied_nexus_roles_only() {
        let viewer = gated_profile(&["viewer"], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), Some(&viewer), true, &levels()),
            Err("role"),
        );
        // The same requirement satisfied by a NEXUS-AUTHORED role on the Profile.
        let admin = gated_profile(&["admin"], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), Some(&admin), true, &levels()),
            Ok(()),
        );
    }

    /// Spec "Missing entitlement is rejected (plan gate)".
    #[test]
    fn missing_entitlement_is_denied() {
        let p = gated_profile(&[], &["free"]);
        assert_eq!(
            enforce_route_requirements(&reqs(None, Some("pro"), None), Some(&p), true, &levels()),
            Err("entitlement"),
        );
    }

    /// Spec "Insufficient assurance level is rejected": bearer maps to 1 in the
    /// default ordering, so a min of 2 denies; an unparseable minimum also denies.
    #[test]
    fn insufficient_or_unparseable_aal_is_denied() {
        let p = gated_profile(&[], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("2")), Some(&p), true, &levels()),
            Err("aal"),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("1")), Some(&p), true, &levels()),
            Ok(()),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("high")), Some(&p), true, &levels()),
            Err("min_aal_unparseable"),
        );
    }

    /// Spec "Requirement with absent enrichment fails closed": no profile means
    /// an entitlement requirement cannot be evaluated -> deny, never pass. The
    /// anonymous case (upstream misconfiguration — jwt_authn should have 401'd)
    /// also denies: no roles, and "none" maps below any positive minimum.
    #[test]
    fn requirement_with_absent_enrichment_fails_closed() {
        assert_eq!(
            enforce_route_requirements(&reqs(None, Some("pro"), None), None, true, &levels()),
            Err("entitlement"),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), None, false, &levels()),
            Err("role"),
        );
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("1")), None, false, &levels()),
            Err("aal"),
        );
        // A method absent from the ordering can satisfy nothing (fail-closed).
        assert_eq!(
            enforce_route_requirements(&reqs(None, None, Some("1")), None, true, &HashMap::new()),
            Err("aal"),
        );
    }

    /// Spec R1 / task 8.1: a role-claiming token confers nothing. Roles are
    /// nexus-authored only — sourced from the Profile, never the token — and now ride
    /// ONLY the signed contract's `roles` claim (identity-revocation-integrity): the bare
    /// `x-user-roles` mirror is retired, so there is no forgeable header twin. A subject
    /// nexus holds no roles for is refused a role-gated route; even a Profile role that
    /// isn't the required one denies. (Structurally there is NO token→roles path:
    /// `extract_identity` reads no roles claim and `enforce_route_requirements` takes none.)
    #[test]
    fn role_claiming_token_confers_nothing() {
        // No nexus Profile → deny-by-default. The bare roles mirror is retired: never
        // emitted, and any client-supplied copy is stripped, so a role-claiming header
        // confers nothing structurally. The role route is refused on the nexus-authored set.
        let miss = enrich_response("u1", None, true, None);
        assert!(!set_headers(&miss).contains_key("x-user-roles"), "the bare roles mirror is retired");
        assert!(
            remove_headers(&miss).contains(&"x-user-roles".to_owned()),
            "a client-supplied roles header is stripped",
        );
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), None, true, &levels()),
            Err("role"),
        );
        // A Profile with only a different nexus role still denies the admin route.
        let viewer = gated_profile(&["viewer"], &[]);
        assert_eq!(
            enforce_route_requirements(&reqs(Some("admin"), None, None), Some(&viewer), true, &levels()),
            Err("role"),
        );
        // Even with a profile, the bare header is never emitted — the coarse roles live in
        // the signed contract (`roles` claim, asserted in signer.rs), not a forgeable header.
        assert!(!set_headers(&enrich_response("u1", Some(viewer), true, None)).contains_key("x-user-roles"));
    }

    /// adopt-cedar-policy-gate task 4.1 — the PARITY ORACLE. Run the full gate input
    /// matrix (role/entitlement/AAL present·absent·mismatch, empty requirements,
    /// unparseable AAL, absent enrichment, authenticated·anonymous) through BOTH the
    /// hand-coded `enforce_route_requirements` oracle and the production PDP path
    /// (`decide_route_requirements`), and assert IDENTICAL effects (pass vs deny) for
    /// every combination. Reasons differ (the oracle names the first failing dimension;
    /// the PDP returns a single deny reason) — only the effect must match.
    #[test]
    fn pdp_matches_the_oracle_across_the_full_gate_matrix() {
        let pdp = test_pdp();
        let levels = levels();
        // Profiles span: absent (no enrichment), present-empty, and every combination of
        // the two facts the gate reads (role `admin`, entitlement `pro`).
        let with_both = gated_profile(&["admin"], &["pro"]);
        let with_role = gated_profile(&["admin"], &[]);
        let with_ent = gated_profile(&[], &["pro"]);
        let empty = gated_profile(&[], &[]);
        let profiles: [Option<&Arc<Profile>>; 5] =
            [None, Some(&empty), Some(&with_role), Some(&with_ent), Some(&with_both)];
        // Requirement signals span present-match, present-mismatch, and absent; the AAL
        // requirement spans absent, "0" (present, any level), "1"/"2" (levels), and an
        // unparseable value.
        let role_reqs = [None, Some("admin"), Some("editor")];
        let ent_reqs = [None, Some("pro"), Some("enterprise")];
        let aal_reqs = [None, Some("0"), Some("1"), Some("2"), Some("high")];
        let auth_states = [true, false];

        let mut checked = 0_u32;
        for profile in profiles {
            for role in role_reqs {
                for ent in ent_reqs {
                    for aal in aal_reqs {
                        for authenticated in auth_states {
                            let requirements = reqs(role, ent, aal);
                            let oracle = enforce_route_requirements(
                                &requirements,
                                profile,
                                authenticated,
                                &levels,
                            )
                            .is_ok();
                            let via_pdp = decide_route_requirements(
                                pdp.as_ref(),
                                &requirements,
                                profile,
                                authenticated,
                                &levels,
                            )
                            .is_ok();
                            assert_eq!(
                                oracle, via_pdp,
                                "parity drift: role={role:?} ent={ent:?} aal={aal:?} \
                                 auth={authenticated} profile_present={} \
                                 oracle_pass={oracle} pdp_pass={via_pdp}",
                                profile.is_some(),
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
        // 5 profiles × 3 roles × 3 ents × 5 aals × 2 auth = 450 combinations.
        assert_eq!(checked, 450, "the whole matrix must be exercised");
    }
}
