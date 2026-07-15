//! The admin-plane authorization gate (admin-plane-authorization, design D4).
//!
//! Runs immediately AFTER `require_auth` resolved the actor and its grant:
//! classifies the matched route into its action class via the declarative
//! [`ROUTE_CLASSES`] table (the exact route template axum matched — never
//! prefix parsing), asks the decision port, and 403s with the decision reason
//! on deny. Fail-closed at runtime: a route missing from the table is DENIED
//! for every actor, so a newly added endpoint cannot ship unclassified and
//! open. Authorization denials join the audit ledger attributed to the actor
//! (spec "An authorization refusal leaves an attributed trace"), rate-limited
//! per actor exactly as authentication denials are per source.
//!
//! The decision itself is a pure function ([`gate_decision`]) over the request
//! facts — the middleware only translates HTTP in and out of it.

use axum::extract::{MatchedPath, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use opentelemetry::KeyValue;
use serde_json::json;
use tracing::warn;

use router_core::admin_authz::{
    ActionClass, AdminPolicyDecisionPoint, AdminPolicyRequest, Decision,
};
use router_core::audit::{AuditCtx, AuthzDenialEvent};

use crate::app::{ActorGrant, App, METRICS};

/// The ledger word for a route the table does not classify (the fail-closed
/// runtime backstop — also what the completeness test forbids ever mattering).
const CLASS_UNCLASSIFIED: &str = "unclassified";

/// Every admin route's action class, keyed by (method, matched route
/// template). THE single source of classification (design D4): the gate denies
/// any (method, template) not listed here, so adding an admin route without a
/// row is loudly fail-closed, never silently open. Kept in lockstep with the
/// route registrations in `main.rs` — the completeness test below pins the
/// `token-admin` rows to exactly the `/admin-tokens` surface.
pub(crate) const ROUTE_CLASSES: &[(&str, &str, ActionClass)] = &[
    // Accounts + Workspaces + Memberships (nexus-owned-workspace-tenancy).
    ("POST", "/accounts", ActionClass::Provision),
    ("GET", "/accounts/{id}", ActionClass::Read),
    ("POST", "/workspaces", ActionClass::Provision),
    ("GET", "/workspaces/{id}", ActionClass::Read),
    ("PUT", "/workspaces/{id}", ActionClass::Provision),
    ("POST", "/workspaces/{id}/transfer", ActionClass::Provision),
    ("GET", "/workspaces/{id}/members", ActionClass::Read),
    ("PUT", "/workspaces/{id}/members", ActionClass::Provision),
    ("DELETE", "/workspaces/{id}/members/{sub}", ActionClass::Provision),
    ("GET", "/workspaces/{id}/auth-routes", ActionClass::Read),
    ("PUT", "/workspaces/{id}/auth-routes", ActionClass::Provision),
    ("DELETE", "/workspaces/{id}/auth-routes", ActionClass::Provision),
    // Domains.
    ("POST", "/domains", ActionClass::Provision),
    ("POST", "/domains/declare", ActionClass::Provision),
    ("POST", "/domains/{domain}/verify", ActionClass::Provision),
    ("DELETE", "/domains/{domain}", ActionClass::Provision),
    // Audit ledger read surface.
    ("GET", "/audit/events", ActionClass::Read),
    ("GET", "/audit/events/export", ActionClass::Read),
    // Admin-credential administration — the distinguished class (spec
    // "Credential administration is a distinguished privilege").
    ("GET", "/admin-tokens", ActionClass::TokenAdmin),
    ("POST", "/admin-tokens", ActionClass::TokenAdmin),
    ("POST", "/admin-tokens/{id}/rotate", ActionClass::TokenAdmin),
    ("POST", "/admin-tokens/{id}/revoke", ActionClass::TokenAdmin),
];

/// Look up the action class for a matched route. `None` = unclassified —
/// the caller DENIES (fail-closed), never assumes a class.
fn classify(method: &str, template: &str) -> Option<ActionClass> {
    ROUTE_CLASSES
        .iter()
        .find(|(m, t, _)| *m == method && *t == template)
        .map(|(_, _, class)| *class)
}

/// The gate's outcome for one request — the pure core the middleware renders.
#[derive(Debug, PartialEq, Eq)]
enum GateOutcome {
    /// Permitted; carries the decision reason for the mutation's audit event.
    Permit(String),
    /// Refused; carries the class's ledger word + the decision reason.
    Deny { class_word: &'static str, reason: String },
}

/// Decide one request from its facts: classify, then ask the decision port.
/// Deny-by-default and fail-closed — an unclassified route denies for every
/// actor before the port is even consulted.
fn gate_decision(
    pdp: &dyn AdminPolicyDecisionPoint,
    method: &str,
    template: Option<&str>,
    actor: &str,
    scopes: &[String],
) -> GateOutcome {
    let Some(class) = template.and_then(|t| classify(method, t)) else {
        return GateOutcome::Deny {
            class_word: CLASS_UNCLASSIFIED,
            reason: "deny:unclassified-route".to_owned(),
        };
    };
    let decision: Decision =
        pdp.decide(&AdminPolicyRequest { actor, scopes, class, resource: None });
    if decision.is_permit() {
        GateOutcome::Permit(decision.reason)
    } else {
        GateOutcome::Deny { class_word: class.as_str(), reason: decision.reason }
    }
}

/// The 403 tail: a best-effort, rate-limited (per actor) authorization-denial
/// ledger event. A failed write logs and STAYS a denial — it never converts
/// into an acceptance and never 500s. Mirrors the authentication `deny` path.
async fn deny_authz(
    state: &App,
    actx: &AuditCtx,
    class_word: &'static str,
    reason: String,
) -> Response {
    METRICS.mutations.add(1, &[KeyValue::new("op", "forbidden")]);
    warn!(actor = %actx.actor, class = class_word, reason = %reason, "forbidden control-plane request");
    if state.denials.allow(&actx.actor) {
        let denial = AuthzDenialEvent {
            actor: actx.actor.clone(),
            class: class_word,
            reason: reason.clone(),
            source_ip: actx.source_ip.clone(),
            trace_id: actx.trace_id.clone(),
        };
        if let Err(e) = state.store.record_authz_denial(&denial).await {
            warn!(error = %e, "authz denial event write failed (still denying)");
        }
    }
    (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden", "reason": reason })))
        .into_response()
}

/// Authorization gate middleware (admin-plane-authorization): runs INSIDE
/// [`crate::app::require_auth`] (authentication first — an invalid credential
/// is a 401 before any authorization is observable), evaluates the actor's
/// grant against the matched route's class, and either threads the permitting
/// reason into the request's [`AuditCtx`] (so the mutation's audit event
/// carries why it was allowed) or answers 403. When admin auth is explicitly
/// disabled at startup, authorization is bypassed with it (the whole gate is
/// off by operator decision — trusted-network/dev only).
pub(crate) async fn require_authz(State(s): State<App>, mut req: Request, next: Next) -> Response {
    if s.auth.disabled {
        return next.run(req).await;
    }
    let Some(mut actx) = req.extensions().get::<AuditCtx>().cloned() else {
        // Unreachable behind require_auth; if the invariant ever breaks, the
        // gate refuses rather than authorizing an unattributed request.
        warn!("authorization gate saw no authenticated context; refusing");
        return (StatusCode::FORBIDDEN, Json(json!({ "error": "forbidden" }))).into_response();
    };
    let grant = req.extensions().get::<ActorGrant>().cloned().unwrap_or_default();
    let template = req.extensions().get::<MatchedPath>().map(|path| path.as_str().to_owned());
    match gate_decision(&*s.pdp, req.method().as_str(), template.as_deref(), &actx.actor, &grant.0)
    {
        GateOutcome::Permit(reason) => {
            actx.authz_reason = Some(reason);
            let _prior = req.extensions_mut().insert(actx);
            next.run(req).await
        }
        GateOutcome::Deny { class_word, reason } => deny_authz(&s, &actx, class_word, reason).await,
    }
}

// --------------------------------------------------------------------------- //
// admin-plane-authorization tests: the classification table's completeness
// properties (task 4.4) and the pure gate core over the real Cedar policy set.
// --------------------------------------------------------------------------- //
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use router_core::admin_authz::{ActionClass, DenyAllAdminPdp, SCOPES};
    use routing_policy_cedar::CedarAdminPdp;

    use super::{classify, gate_decision, GateOutcome, ROUTE_CLASSES};

    fn owned(scopes: &[&str]) -> Vec<String> {
        scopes.iter().map(|scope| (*scope).to_owned()).collect()
    }

    /// Task 4.4: the table is duplicate-free, and the `token-admin` class is
    /// EXACTLY the `/admin-tokens` surface — no credential route escapes the
    /// distinguished class, and no other route demands it.
    #[test]
    fn token_admin_class_is_exactly_the_admin_tokens_surface() {
        let unique: BTreeSet<(&str, &str)> =
            ROUTE_CLASSES.iter().map(|(m, t, _)| (*m, *t)).collect();
        assert_eq!(unique.len(), ROUTE_CLASSES.len(), "no duplicate (method, template) rows");
        for (method, template, class) in ROUTE_CLASSES {
            let is_token_surface = template.starts_with("/admin-tokens");
            assert_eq!(
                *class == ActionClass::TokenAdmin,
                is_token_surface,
                "{method} {template}: token-admin iff on the /admin-tokens surface"
            );
        }
    }

    /// GETs are Read (or TokenAdmin on the credential surface) and every
    /// non-GET is a mutation class — a mutating route can never hide in Read.
    #[test]
    fn no_mutating_method_carries_the_read_class() {
        for (method, template, class) in ROUTE_CLASSES {
            if *class == ActionClass::Read {
                assert_eq!(*method, "GET", "{template}: Read rows must be GETs");
            }
            if *method != "GET" {
                assert_ne!(*class, ActionClass::Read, "{method} {template}: mutation in Read");
            }
        }
    }

    /// Fail-closed floor: an unknown route or method classifies as None, and
    /// the gate turns that into a deny BEFORE consulting any policy.
    #[test]
    fn unclassified_routes_deny_for_every_actor() {
        assert_eq!(classify("GET", "/not-registered"), None);
        assert_eq!(classify("PATCH", "/accounts"), None, "unlisted method is unclassified");
        let pdp = CedarAdminPdp::with_default_policies().expect("policies load");
        let full = owned(&SCOPES);
        let outcome = gate_decision(&pdp, "GET", Some("/not-registered"), "atk_x", &full);
        assert_eq!(
            outcome,
            GateOutcome::Deny {
                class_word: "unclassified",
                reason: "deny:unclassified-route".to_owned()
            },
            "even the full grant cannot pass an unclassified route"
        );
        let no_template = gate_decision(&pdp, "GET", None, "atk_x", &full);
        assert!(matches!(no_template, GateOutcome::Deny { .. }), "no matched template denies");
    }

    /// The gate over the REAL policy set (task 4.5's in-process half): a
    /// narrowed grant is refused outside its scopes and permitted within
    /// them; the full grant behaves exactly as before the gate existed.
    #[test]
    fn narrowed_grants_are_enforced_and_full_grant_is_parity() {
        let pdp = CedarAdminPdp::with_default_policies().expect("policies load");
        let read_only = owned(&["read"]);
        // Within grant: permitted, with the permitting policy as the reason.
        match gate_decision(&pdp, "GET", Some("/audit/events"), "atk_r", &read_only) {
            GateOutcome::Permit(reason) => {
                assert!(reason.starts_with("permit:"), "permit carries the policy id: {reason}");
            }
            GateOutcome::Deny { .. } => panic!("read grant must permit the audit read surface"),
        }
        // Outside grant: every mutation and the credential surface refuse.
        for (method, template) in
            [("POST", "/accounts"), ("PUT", "/workspaces/{id}"), ("POST", "/admin-tokens")]
        {
            let outcome = gate_decision(&pdp, method, Some(template), "atk_r", &read_only);
            assert!(
                matches!(outcome, GateOutcome::Deny { .. }),
                "read-only grant must not pass {method} {template}"
            );
        }
        // Parity: the full grant (the cutover backfill) passes every row.
        let full = owned(&SCOPES);
        for (method, template, _) in ROUTE_CLASSES {
            let outcome = gate_decision(&pdp, method, Some(template), "atk_full", &full);
            assert!(
                matches!(outcome, GateOutcome::Permit(_)),
                "full grant must pass {method} {template} (parity)"
            );
        }
        // An empty grant passes nothing (deny-by-default).
        for (method, template, _) in ROUTE_CLASSES {
            let outcome = gate_decision(&pdp, method, Some(template), "atk_none", &[]);
            assert!(
                matches!(outcome, GateOutcome::Deny { .. }),
                "empty grant must be refused on {method} {template}"
            );
        }
    }

    /// Spec "A failed policy load denies all gated actions": with the deny-all
    /// stand-in installed, even the full grant is refused everywhere.
    #[test]
    fn deny_all_pdp_refuses_the_full_grant_everywhere() {
        let full = owned(&SCOPES);
        for (method, template, _) in ROUTE_CLASSES {
            let outcome = gate_decision(&DenyAllAdminPdp, method, Some(template), "atk_f", &full);
            assert!(
                matches!(outcome, GateOutcome::Deny { .. }),
                "deny-all must refuse {method} {template}"
            );
        }
    }
}
