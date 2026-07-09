//! Cedar adapter for the L2 authorization gate — the concrete
//! [`PolicyDecisionPoint`](identity_core::PolicyDecisionPoint) implementation
//! (adopt-cedar-policy-gate, design Decisions 0/2/3).
//!
//! The `cedar-policy` dependency is confined to this crate: it translates a
//! vendor-agnostic [`PolicyRequest`](identity_core::PolicyRequest) into Cedar
//! entities + a request, evaluates them against the parity policy, and maps the
//! engine's answer back to an [`identity_core::Decision`]. Neither `core` nor the
//! sidecar sees a Cedar type — the engine is a reversible adapter swap behind the
//! port.
//!
//! Policy + schema are DATA (`policies/*.cedar[schema]`): loaded and **validated**
//! at construction. A malformed/unvalidatable set makes construction fail, and the
//! caller installs [`identity_core::DenyAllPdp`] so gated routes fail closed rather
//! than run on an empty/partial set (`authorization-policy-engine` spec).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, Entity, EntityId, EntityTypeName,
    EntityUid, PolicySet, Request, Response, RestrictedExpression, Schema, ValidationMode,
    Validator,
};

use identity_core::{
    Decision, MinAal, PolicyContext, PolicyDecisionPoint, PolicyPrincipal, PolicyRequest,
    PolicyResource,
};

/// The default parity schema, embedded so the sidecar can run without a mounted policy
/// path. Overridable per environment via [`CedarPdp::from_path`].
const DEFAULT_SCHEMA: &str = include_str!("../policies/schema.cedarschema");
/// The default parity policy, embedded alongside the schema.
const DEFAULT_POLICY: &str = include_str!("../policies/policy.cedar");

/// The filename the schema is read from under a configured policy directory.
const SCHEMA_FILE: &str = "schema.cedarschema";
/// The filename the policy set is read from under a configured policy directory.
const POLICY_FILE: &str = "policy.cedar";

/// A failure to LOAD or VALIDATE the policy set. Construction returns this rather than
/// a half-built engine so the caller fails closed (installs a deny-all PDP) instead of
/// evaluating against a partial or empty set.
///
/// Implements only [`fmt::Display`] (not [`std::error::Error`]), matching the workspace
/// convention for domain error types (`SignError`, `KeyProviderError`) — the workspace
/// `missing_trait_methods` lint makes a manual `Error` impl impossible on stable.
#[derive(Debug)]
pub enum PolicyLoadError {
    /// The Cedar schema file could not be parsed.
    Schema(String),
    /// The Cedar policy file could not be parsed.
    Policy(String),
    /// The policy set did not validate against the schema (strict mode).
    Validation(String),
    /// A policy file could not be read from the configured path.
    Io(String),
}

impl fmt::Display for PolicyLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(msg) => write!(f, "cedar schema parse failed: {msg}"),
            Self::Policy(msg) => write!(f, "cedar policy parse failed: {msg}"),
            Self::Validation(msg) => write!(f, "cedar policy validation failed: {msg}"),
            Self::Io(msg) => write!(f, "cedar policy load failed: {msg}"),
        }
    }
}

/// The Cedar-backed policy decision point. Holds the validated schema + policy set and
/// a stateless authorizer; [`decide`](PolicyDecisionPoint::decide) builds per-request
/// entities and evaluates them. Immutable after construction, so it is `Send + Sync`.
pub struct CedarPdp {
    schema: Schema,
    policies: PolicySet,
    authorizer: Authorizer,
}

impl fmt::Debug for CedarPdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CedarPdp")
            .field("policies", &self.policies.policies().count())
            .finish_non_exhaustive()
    }
}

impl CedarPdp {
    /// Build from the embedded default parity policy + schema (the in-crate default set,
    /// design Decision 3). Validated like any other set — fails closed if the embedded
    /// data is somehow malformed.
    pub fn with_default_policies() -> Result<Self, PolicyLoadError> {
        Self::from_sources(DEFAULT_SCHEMA, DEFAULT_POLICY)
    }

    /// Load `schema.cedarschema` + `policy.cedar` from a configured directory (the
    /// per-environment override, design Decision 3), then validate. A read failure or
    /// an invalid set returns `Err` so the caller fails closed.
    pub fn from_path(dir: &Path) -> Result<Self, PolicyLoadError> {
        let schema_src = fs::read_to_string(dir.join(SCHEMA_FILE))
            .map_err(|e| PolicyLoadError::Io(format!("{SCHEMA_FILE}: {e}")))?;
        let policy_src = fs::read_to_string(dir.join(POLICY_FILE))
            .map_err(|e| PolicyLoadError::Io(format!("{POLICY_FILE}: {e}")))?;
        Self::from_sources(&schema_src, &policy_src)
    }

    /// Parse + strict-validate a schema/policy source pair. This is the single load
    /// path: both the embedded default and a configured directory funnel through it,
    /// so validation (and its fail-closed guarantee) is uniform.
    pub fn from_sources(schema_src: &str, policy_src: &str) -> Result<Self, PolicyLoadError> {
        let (schema, _warnings) = Schema::from_cedarschema_str(schema_src)
            .map_err(|e| PolicyLoadError::Schema(e.to_string()))?;
        let policies = PolicySet::from_str(policy_src)
            .map_err(|e| PolicyLoadError::Policy(e.to_string()))?;
        let validator = Validator::new(schema.clone());
        let result = validator.validate(&policies, ValidationMode::Strict);
        if !result.validation_passed() {
            let msgs: Vec<String> =
                result.validation_errors().map(ToString::to_string).collect();
            return Err(PolicyLoadError::Validation(msgs.join("; ")));
        }
        Ok(Self { schema, policies, authorizer: Authorizer::new() })
    }

    /// Evaluate a request, returning the mapped [`Decision`]. Any failure to BUILD the
    /// Cedar request/entities is itself fail-closed: it maps to a deny (never a permit),
    /// so a translation defect can only ever refuse access, not grant it.
    fn evaluate(&self, request: &PolicyRequest) -> Result<Decision, String> {
        let principal = principal_entity(&request.principal)?;
        let resource = resource_entity(&request.resource)?;
        let principal_uid = principal.uid();
        let resource_uid = resource.uid();
        let action_uid = action_uid()?;
        let context = build_context(&request.context)?;
        let entities = Entities::from_entities([principal, resource], Some(&self.schema))
            .map_err(|e| format!("entity build failed: {e}"))?;
        let cedar_request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            context,
            Some(&self.schema),
        )
        .map_err(|e| format!("request build failed: {e}"))?;
        let response = self.authorizer.is_authorized(&cedar_request, &self.policies, &entities);
        Ok(map_response(&response))
    }
}

impl PolicyDecisionPoint for CedarPdp {
    fn decide(&self, request: &PolicyRequest) -> Decision {
        // Fail-closed: a build error is a deny carrying the reason, never a permit.
        self.evaluate(request)
            .unwrap_or_else(|reason| Decision::deny(format!("deny:build-error:{reason}")))
    }
}

/// The single `access` action uid, parsed from a fixed literal (no user input, so the
/// parse cannot realistically fail; a failure still maps to a fail-closed deny above).
fn action_uid() -> Result<EntityUid, String> {
    EntityUid::from_str("Action::\"access\"").map_err(|e| format!("action uid: {e}"))
}

/// Build an entity uid from a type name + a fixed id. The id does not affect the
/// decision (the policy reads attributes, not the uid), so a constant is used — which
/// also avoids escaping an arbitrary subject id.
fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, String> {
    let parsed_type = EntityTypeName::from_str(type_name)
        .map_err(|e| format!("entity type {type_name}: {e}"))?;
    let parsed_id = EntityId::from_str(id).map_err(|e| format!("entity id {id}: {e}"))?;
    Ok(EntityUid::from_type_name_and_id(parsed_type, parsed_id))
}

/// A Cedar `Set<String>` restricted expression from a slice of strings.
fn string_set(items: &[String]) -> RestrictedExpression {
    RestrictedExpression::new_set(
        items.iter().map(|item| RestrictedExpression::new_string(item.clone())),
    )
}

/// Translate the vendor-agnostic principal into a Cedar `User` entity. `aal` is only
/// inserted when present, so an unmapped method leaves the attribute genuinely absent
/// (`principal has aal` = false) and any min-AAL requirement fails closed.
fn principal_entity(principal: &PolicyPrincipal) -> Result<Entity, String> {
    let uid = entity_uid("User", "principal")?;
    let mut pairs: Vec<(String, RestrictedExpression)> = vec![
        ("roles".to_owned(), string_set(&principal.roles)),
        ("entitlements".to_owned(), string_set(&principal.entitlements)),
        ("suspended".to_owned(), RestrictedExpression::new_bool(principal.suspended)),
        ("kind".to_owned(), RestrictedExpression::new_string(principal.kind.clone())),
    ];
    // `aal` is inserted ONLY when present, so an unmapped method leaves the attribute
    // genuinely absent (`principal has aal` = false) and any min-AAL requirement denies.
    if let Some(aal) = principal.aal {
        pairs.push(("aal".to_owned(), RestrictedExpression::new_long(aal)));
    }
    let attrs: HashMap<String, RestrictedExpression> = pairs.into_iter().collect();
    Entity::new(uid, attrs, HashSet::new()).map_err(|e| format!("principal entity: {e}"))
}

/// Translate the vendor-agnostic resource into a Cedar `Route` entity, expanding the
/// three-state min-AAL requirement into the schema's `has_min_aal` / `min_aal` /
/// `min_aal_parseable` flags:
///   - `None`        → not present (`has_min_aal` = false): the AAL dimension is skipped.
///   - `Least(n)`    → present & parseable at level `n`.
///   - `Unparseable` → present but not parseable: the policy denies (fail-closed).
fn resource_entity(resource: &PolicyResource) -> Result<Entity, String> {
    let uid = entity_uid("Route", "resource")?;
    let (has_min_aal, min_aal, parseable) = match resource.min_aal {
        MinAal::None => (false, 0, true),
        MinAal::Least(level) => (true, level, true),
        MinAal::Unparseable => (true, 0, false),
    };
    let attrs: HashMap<String, RestrictedExpression> = [
        (
            "requires_role".to_owned(),
            RestrictedExpression::new_string(resource.requires_role.clone()),
        ),
        (
            "requires_entitlement".to_owned(),
            RestrictedExpression::new_string(resource.requires_entitlement.clone()),
        ),
        ("has_min_aal".to_owned(), RestrictedExpression::new_bool(has_min_aal)),
        ("min_aal".to_owned(), RestrictedExpression::new_long(min_aal)),
        ("min_aal_parseable".to_owned(), RestrictedExpression::new_bool(parseable)),
        (
            "account_scoped".to_owned(),
            RestrictedExpression::new_bool(resource.account_scoped),
        ),
    ]
    .into_iter()
    .collect();
    Entity::new(uid, attrs, HashSet::new()).map_err(|e| format!("resource entity: {e}"))
}

/// Build the Cedar context from the ambient [`PolicyContext`]. geo/plan are only
/// inserted when present; the parity policy references none of them (inert).
fn build_context(context: &PolicyContext) -> Result<Context, String> {
    let mut pairs: Vec<(String, RestrictedExpression)> = Vec::new();
    if let Some(geo) = &context.geo {
        pairs.push(("geo".to_owned(), RestrictedExpression::new_string(geo.clone())));
    }
    if let Some(plan) = &context.plan {
        pairs.push(("plan".to_owned(), RestrictedExpression::new_string(plan.clone())));
    }
    Context::from_pairs(pairs).map_err(|e| format!("context: {e}"))
}

/// Map a Cedar authorization response to a port [`Decision`], carrying an auditable
/// reason: the permitting policy id on allow; on deny, any evaluation error (fail-
/// closed) or the absence of a permitting policy (deny-by-default).
fn map_response(response: &Response) -> Decision {
    match response.decision() {
        CedarDecision::Allow => {
            let reason = response
                .diagnostics()
                .reason()
                .next()
                .map_or_else(|| "permit".to_owned(), |policy_id| format!("permit:{policy_id}"));
            Decision::permit(reason)
        }
        CedarDecision::Deny => response.diagnostics().errors().next().map_or_else(
            || Decision::deny("deny:no-permit"),
            |err| Decision::deny(format!("deny:evaluation-error:{err}")),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity_core::AuthzFacts;

    fn pdp() -> CedarPdp {
        CedarPdp::with_default_policies().expect("default parity policies must load")
    }

    /// Build a request from raw facts + resolved requirement signals, exactly as the
    /// sidecar translator will.
    fn request(
        roles: &[&str],
        entitlements: &[&str],
        aal: Option<i64>,
        req_role: Option<&str>,
        req_entitlement: Option<&str>,
        req_min_aal: Option<&str>,
    ) -> PolicyRequest {
        let facts = AuthzFacts {
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            entitlements: entitlements.iter().map(|e| (*e).to_owned()).collect(),
            is_suspended: false,
        };
        PolicyRequest {
            principal: PolicyPrincipal::from_facts(&facts, aal, "user"),
            action: identity_core::Action::Access,
            resource: PolicyResource::from_requirements(
                req_role,
                req_entitlement,
                req_min_aal,
                false,
            ),
            context: PolicyContext::default(),
        }
    }

    #[test]
    fn no_requirements_permits() {
        let decision = pdp().decide(&request(&[], &[], Some(1), None, None, None));
        assert!(decision.is_permit(), "no requirements should permit: {decision:?}");
    }

    #[test]
    fn deny_by_default_when_role_missing() {
        let decision =
            pdp().decide(&request(&[], &[], Some(1), Some("admin"), None, None));
        assert!(!decision.is_permit(), "missing role must deny: {decision:?}");
    }

    #[test]
    fn permits_when_role_held() {
        let decision =
            pdp().decide(&request(&["admin"], &[], Some(1), Some("admin"), None, None));
        assert!(decision.is_permit(), "held role should permit: {decision:?}");
    }

    #[test]
    fn entitlement_required_but_absent_denies() {
        let decision =
            pdp().decide(&request(&["admin"], &[], Some(1), Some("admin"), Some("pro"), None));
        assert!(!decision.is_permit(), "missing entitlement must deny: {decision:?}");
    }

    #[test]
    fn entitlement_held_permits() {
        let decision = pdp().decide(&request(
            &["admin"],
            &["pro"],
            Some(1),
            Some("admin"),
            Some("pro"),
            None,
        ));
        assert!(decision.is_permit(), "held entitlement should permit: {decision:?}");
    }

    #[test]
    fn aal_met_permits() {
        let decision = pdp().decide(&request(&[], &[], Some(2), None, None, Some("2")));
        assert!(decision.is_permit(), "aal 2 >= 2 should permit: {decision:?}");
    }

    #[test]
    fn aal_below_requirement_denies() {
        let decision = pdp().decide(&request(&[], &[], Some(1), None, None, Some("2")));
        assert!(!decision.is_permit(), "aal 1 < 2 must deny: {decision:?}");
    }

    #[test]
    fn aal_requirement_with_unmapped_method_denies() {
        // Unmapped method → aal None → any present AAL requirement (incl "0") fails closed.
        let decision = pdp().decide(&request(&[], &[], None, None, None, Some("2")));
        assert!(!decision.is_permit(), "unmapped method must deny: {decision:?}");
    }

    #[test]
    fn aal_zero_requirement_with_unmapped_method_denies() {
        // Parity edge case: `Some("0")` is a PRESENT requirement — an unmapped method
        // still denies even though any level would satisfy it.
        let decision = pdp().decide(&request(&[], &[], None, None, None, Some("0")));
        assert!(!decision.is_permit(), "min_aal=0 + unmapped method must deny: {decision:?}");
    }

    #[test]
    fn aal_zero_requirement_with_mapped_method_permits() {
        let decision = pdp().decide(&request(&[], &[], Some(0), None, None, Some("0")));
        assert!(decision.is_permit(), "min_aal=0 + mapped level 0 should permit: {decision:?}");
    }

    #[test]
    fn unparseable_aal_requirement_denies() {
        let decision = pdp().decide(&request(&[], &[], Some(9), None, None, Some("high")));
        assert!(!decision.is_permit(), "unparseable min_aal must deny: {decision:?}");
    }

    #[test]
    fn all_requirements_satisfied_permits() {
        let decision = pdp().decide(&request(
            &["admin"],
            &["pro"],
            Some(2),
            Some("admin"),
            Some("pro"),
            Some("2"),
        ));
        assert!(decision.is_permit(), "all satisfied should permit: {decision:?}");
    }

    #[test]
    fn deny_carries_auditable_reason() {
        let decision =
            pdp().decide(&request(&[], &[], Some(1), Some("admin"), None, None));
        assert!(!decision.reason.is_empty(), "deny must carry a reason");
        assert!(decision.reason.contains("deny"), "reason should mark a deny: {}", decision.reason);
    }

    #[test]
    fn permit_reason_identifies_policy() {
        let decision = pdp().decide(&request(&[], &[], Some(1), None, None, None));
        assert!(decision.reason.contains("permit"), "permit reason: {}", decision.reason);
    }

    #[test]
    fn forbid_overrides_permit() {
        // A permit-all plus a conditional forbid: the forbid must win, proving the
        // engine's forbid-overrides-permit semantics (`authorization-policy-engine`
        // spec). The forbid keys on the (otherwise inert) `suspended` attribute.
        let policy = "permit(principal, action, resource);\n\
             forbid(principal, action, resource) when { principal.suspended };";
        let pdp = CedarPdp::from_sources(DEFAULT_SCHEMA, policy)
            .expect("permit+forbid set validates and loads");

        let suspended = AuthzFacts { roles: vec![], entitlements: vec![], is_suspended: true };
        let denied = PolicyRequest {
            principal: PolicyPrincipal::from_facts(&suspended, Some(1), "user"),
            action: identity_core::Action::Access,
            resource: PolicyResource::from_requirements(None, None, None, false),
            context: PolicyContext::default(),
        };
        assert!(
            !pdp.decide(&denied).is_permit(),
            "a forbid must override the permit-all (deny)",
        );

        let active = PolicyRequest {
            principal: PolicyPrincipal::from_facts(&AuthzFacts::default(), Some(1), "user"),
            action: identity_core::Action::Access,
            resource: PolicyResource::from_requirements(None, None, None, false),
            context: PolicyContext::default(),
        };
        assert!(
            pdp.decide(&active).is_permit(),
            "with no forbid applying, the permit-all allows",
        );
    }

    #[test]
    fn malformed_policy_set_fails_to_load() {
        let bad = CedarPdp::from_sources(DEFAULT_SCHEMA, "this is not a cedar policy");
        assert!(bad.is_err(), "a malformed policy set must fail closed at load");
    }

    #[test]
    fn from_path_fails_closed_on_a_malformed_file_set() {
        // The deploy path (POLICY_DIR): a malformed policy FILE must fail closed at load,
        // exactly as an inline malformed source does — so a bad deploy artifact refuses
        // gated routes rather than serving an unvalidated set (adopt-cedar-policy-gate 5.2).
        use std::env;
        let dir = env::temp_dir().join("nexus_policy_cedar_malformed_test");
        fs::create_dir_all(&dir).expect("create temp policy dir");
        fs::write(dir.join(SCHEMA_FILE), DEFAULT_SCHEMA).expect("write schema");
        fs::write(dir.join(POLICY_FILE), "not a valid cedar policy").expect("write bad policy");
        assert!(
            CedarPdp::from_path(&dir).is_err(),
            "a malformed policy file must fail closed at load",
        );
        // The valid deploy set at the same path loads — proving the path itself is good.
        fs::write(dir.join(POLICY_FILE), DEFAULT_POLICY).expect("write good policy");
        assert!(
            CedarPdp::from_path(&dir).is_ok(),
            "the valid deploy policy set loads from a configured path",
        );
    }

    #[test]
    fn policy_not_validating_against_schema_fails_to_load() {
        // References an attribute the schema does not declare → strict validation rejects.
        let bad = CedarPdp::from_sources(
            DEFAULT_SCHEMA,
            "permit(principal, action, resource) when { resource.nonexistent == \"x\" };",
        );
        assert!(bad.is_err(), "a set that fails schema validation must fail closed at load");
    }
}
