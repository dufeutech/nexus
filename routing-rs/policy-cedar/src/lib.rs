//! Cedar adapter for the admin-plane authorization gate — the concrete
//! [`AdminPolicyDecisionPoint`](router_core::admin_authz::AdminPolicyDecisionPoint)
//! implementation (admin-plane-least-privilege, design D1/D2).
//!
//! The `cedar-policy` dependency is confined to this crate: it translates a
//! vendor-agnostic [`AdminPolicyRequest`](router_core::admin_authz::AdminPolicyRequest)
//! into Cedar entities + a request, evaluates them against the grant policy,
//! and maps the engine's answer back to a
//! [`router_core::admin_authz::Decision`]. Neither `router-core` nor the
//! control plane sees a Cedar type — the engine is a reversible adapter swap
//! behind the port. Structurally a sibling of the identity plane's
//! `policy-cedar` crate (same adopted engine, different PARC): the workspaces
//! stay uncoupled by design (D1 alternatives).
//!
//! Policy + schema are DATA (`policies/admin.cedar[schema]`): loaded and
//! **validated** at construction. A malformed/unvalidatable set makes
//! construction fail, and the caller installs
//! [`router_core::admin_authz::DenyAllAdminPdp`] so gated routes fail closed
//! rather than run on an empty/partial set (spec "A failed policy load denies
//! all gated actions").

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

use router_core::admin_authz::{AdminPolicyDecisionPoint, AdminPolicyRequest, Decision};

/// The default grant schema, embedded so the control plane can run without a
/// mounted policy path. Overridable per environment via [`CedarAdminPdp::from_path`].
const DEFAULT_SCHEMA: &str = include_str!("../policies/admin.cedarschema");
/// The default grant policy, embedded alongside the schema.
const DEFAULT_POLICY: &str = include_str!("../policies/admin.cedar");

/// The filename the schema is read from under a configured policy directory.
const SCHEMA_FILE: &str = "admin.cedarschema";
/// The filename the policy set is read from under a configured policy directory.
const POLICY_FILE: &str = "admin.cedar";

/// A failure to LOAD or VALIDATE the policy set. Construction returns this
/// rather than a half-built engine so the caller fails closed (installs the
/// deny-all PDP) instead of evaluating against a partial or empty set.
///
/// Implements only [`fmt::Display`] (not [`std::error::Error`]), matching the
/// workspace convention for domain error types — the workspace
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
            Self::Schema(msg) => write!(f, "cedar admin schema parse failed: {msg}"),
            Self::Policy(msg) => write!(f, "cedar admin policy parse failed: {msg}"),
            Self::Validation(msg) => write!(f, "cedar admin policy validation failed: {msg}"),
            Self::Io(msg) => write!(f, "cedar admin policy load failed: {msg}"),
        }
    }
}

/// The Cedar-backed admin decision point. Holds the validated schema + policy
/// set and a stateless authorizer;
/// [`decide`](AdminPolicyDecisionPoint::decide) builds per-request entities
/// and evaluates them. Immutable after construction, so it is `Send + Sync`.
pub struct CedarAdminPdp {
    schema: Schema,
    policies: PolicySet,
    authorizer: Authorizer,
}

impl fmt::Debug for CedarAdminPdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CedarAdminPdp")
            .field("policies", &self.policies.policies().count())
            .finish_non_exhaustive()
    }
}

impl CedarAdminPdp {
    /// Build from the embedded default grant policy + schema. Validated like
    /// any other set — fails closed if the embedded data is somehow malformed.
    pub fn with_default_policies() -> Result<Self, PolicyLoadError> {
        Self::from_sources(DEFAULT_SCHEMA, DEFAULT_POLICY)
    }

    /// Load `admin.cedarschema` + `admin.cedar` from a configured directory
    /// (the per-environment override), then validate. A read failure or an
    /// invalid set returns `Err` so the caller fails closed.
    pub fn from_path(dir: &Path) -> Result<Self, PolicyLoadError> {
        let schema_src = fs::read_to_string(dir.join(SCHEMA_FILE))
            .map_err(|e| PolicyLoadError::Io(format!("{SCHEMA_FILE}: {e}")))?;
        let policy_src = fs::read_to_string(dir.join(POLICY_FILE))
            .map_err(|e| PolicyLoadError::Io(format!("{POLICY_FILE}: {e}")))?;
        Self::from_sources(&schema_src, &policy_src)
    }

    /// Parse + strict-validate a schema/policy source pair. This is the single
    /// load path: both the embedded default and a configured directory funnel
    /// through it, so validation (and its fail-closed guarantee) is uniform.
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

    /// Evaluate a request, returning the mapped [`Decision`]. Any failure to
    /// BUILD the Cedar request/entities is itself fail-closed: it maps to a
    /// deny (never a permit), so a translation defect can only ever refuse
    /// access, not grant it.
    fn evaluate(&self, request: &AdminPolicyRequest<'_>) -> Result<Decision, String> {
        let principal = principal_entity(request.scopes)?;
        let resource = resource_entity(request.resource)?;
        let principal_uid = principal.uid();
        let resource_uid = resource.uid();
        let action_uid = action_uid(request.class.as_str())?;
        let entities = Entities::from_entities([principal, resource], Some(&self.schema))
            .map_err(|e| format!("entity build failed: {e}"))?;
        let cedar_request = Request::new(
            principal_uid,
            action_uid,
            resource_uid,
            Context::empty(),
            Some(&self.schema),
        )
        .map_err(|e| format!("request build failed: {e}"))?;
        let response = self.authorizer.is_authorized(&cedar_request, &self.policies, &entities);
        Ok(map_response(&response))
    }
}

impl AdminPolicyDecisionPoint for CedarAdminPdp {
    fn decide(&self, request: &AdminPolicyRequest<'_>) -> Decision {
        // Fail-closed: a build error is a deny carrying the reason, never a permit.
        self.evaluate(request)
            .unwrap_or_else(|reason| Decision::deny(format!("deny:build-error:{reason}")))
    }
}

/// The action uid for a route class. The class word comes from the closed
/// [`router_core::admin_authz::ActionClass`] vocabulary (a fixed literal, no
/// user input), so the parse cannot realistically fail; a failure still maps
/// to a fail-closed deny above.
fn action_uid(class: &str) -> Result<EntityUid, String> {
    EntityUid::from_str(&format!("Action::\"{class}\"")).map_err(|e| format!("action uid: {e}"))
}

/// Build an entity uid from a type name + id.
fn entity_uid(type_name: &str, id: &str) -> Result<EntityUid, String> {
    let parsed_type = EntityTypeName::from_str(type_name)
        .map_err(|e| format!("entity type {type_name}: {e}"))?;
    let parsed_id = EntityId::from_str(id).map_err(|e| format!("entity id: {e}"))?;
    Ok(EntityUid::from_type_name_and_id(parsed_type, parsed_id))
}

/// Translate the actor's grant into the Cedar `AdminToken` principal entity.
/// A fixed uid — the decision reads the `scopes` attribute, not the id, so no
/// arbitrary actor id needs escaping into an entity id.
fn principal_entity(scopes: &[String]) -> Result<Entity, String> {
    let uid = entity_uid("AdminToken", "actor")?;
    let scope_set = RestrictedExpression::new_set(
        scopes.iter().map(|scope| RestrictedExpression::new_string(scope.clone())),
    );
    let attrs = HashMap::from([("scopes".to_owned(), scope_set)]);
    Entity::new(uid, attrs, HashSet::new()).map_err(|e| format!("principal entity: {e}"))
}

/// Translate the (optional) targeted resource into the Cedar `AdminSurface`
/// entity — the per-tenant seam (design D6). The parity policy reads no
/// resource attribute, so the id is carried but inert; a policy that narrows a
/// grant to a workspace becomes a data change against this same entity.
fn resource_entity(resource: Option<&str>) -> Result<Entity, String> {
    let uid = entity_uid("AdminSurface", resource.unwrap_or("control-plane"))?;
    Entity::new(uid, HashMap::new(), HashSet::new())
        .map_err(|e| format!("resource entity: {e}"))
}

/// Map a Cedar authorization response to a port [`Decision`], carrying an
/// auditable reason: the permitting policy id on allow; on deny, any
/// evaluation error (fail-closed) or the absence of a permitting policy
/// (deny-by-default).
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
    use router_core::admin_authz::{ActionClass, Effect, SCOPES};

    use super::*;

    fn pdp() -> CedarAdminPdp {
        CedarAdminPdp::with_default_policies().expect("default grant policies must load")
    }

    fn owned(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|scope| (*scope).to_owned()).collect()
    }

    fn decide(scopes: &[&str], class: ActionClass) -> Decision {
        let scopes = owned(scopes);
        pdp().decide(&AdminPolicyRequest { actor: "atk_test", scopes: &scopes, class, resource: None })
    }

    /// Spec "A granted action executes" / task 3.3: each class permits exactly
    /// when the grant contains its scope, and the reason names the policy.
    #[test]
    fn a_grant_containing_the_class_scope_permits_with_the_policy_reason() {
        let cases = [
            ("read", ActionClass::Read),
            ("provision", ActionClass::Provision),
            ("token-admin", ActionClass::TokenAdmin),
        ];
        for (scope, class) in cases {
            let decision = decide(&[scope], class);
            assert_eq!(decision.effect, Effect::Permit, "{scope} grant must permit {class}");
            assert!(
                decision.reason.starts_with("permit:"),
                "permit reason names the permitting policy: {}",
                decision.reason
            );
        }
    }

    /// Spec "An ungranted action is refused before execution": lacking the
    /// class's scope denies, whatever else the grant holds — in particular no
    /// ordinary grant reaches token-admin (distinguished privilege).
    #[test]
    fn a_grant_lacking_the_class_scope_denies_with_a_reason() {
        let decision = decide(&["read", "provision"], ActionClass::TokenAdmin);
        assert_eq!(decision.effect, Effect::Deny, "read+provision must not reach token-admin");
        assert_eq!(decision.reason, "deny:no-permit", "deny-by-default names the absence");
        assert_eq!(decide(&["read"], ActionClass::Provision).effect, Effect::Deny);
        assert_eq!(decide(&["token-admin"], ActionClass::Read).effect, Effect::Deny);
    }

    /// Fail-closed floor: an empty grant denies every class.
    #[test]
    fn an_empty_grant_denies_everything() {
        for class in [ActionClass::Read, ActionClass::Provision, ActionClass::TokenAdmin] {
            assert_eq!(decide(&[], class).effect, Effect::Deny, "empty grant must deny {class}");
        }
    }

    /// The full grant (the cutover backfill) permits every class — parity.
    #[test]
    fn the_full_grant_permits_every_class() {
        for class in [ActionClass::Read, ActionClass::Provision, ActionClass::TokenAdmin] {
            assert_eq!(decide(&SCOPES, class).effect, Effect::Permit, "full grant permits {class}");
        }
    }

    /// An unknown scope word in a grant confers nothing (only the closed
    /// vocabulary's words appear in policy conditions).
    #[test]
    fn an_unknown_scope_word_confers_nothing() {
        assert_eq!(decide(&["admin", "root", "*"], ActionClass::Provision).effect, Effect::Deny);
    }

    /// The resource seam is inert in the parity set: naming a resource changes
    /// no outcome (design D6 — carried, deliberately unread).
    #[test]
    fn the_resource_seam_is_inert_in_the_parity_set() {
        let scopes = owned(&["provision"]);
        let with_resource = pdp().decide(&AdminPolicyRequest {
            actor: "atk_test",
            scopes: &scopes,
            class: ActionClass::Provision,
            resource: Some("ws_123"),
        });
        assert_eq!(with_resource.effect, Effect::Permit);
    }

    /// Task 3.3: a malformed policy or schema fails CONSTRUCTION (the caller
    /// then installs deny-all) — never a half-built engine.
    #[test]
    fn malformed_sources_fail_construction() {
        assert!(
            CedarAdminPdp::from_sources("entity Broken = {", DEFAULT_POLICY).is_err(),
            "unparseable schema must refuse construction"
        );
        assert!(
            CedarAdminPdp::from_sources(DEFAULT_SCHEMA, "permit(when").is_err(),
            "unparseable policy must refuse construction"
        );
        assert!(
            CedarAdminPdp::from_sources(
                DEFAULT_SCHEMA,
                "permit (principal, action == Action::\"read\", resource) \
                 when { principal.nonexistent.contains(\"read\") };",
            )
            .is_err(),
            "a policy referencing an unknown attribute must fail strict validation"
        );
    }
}
