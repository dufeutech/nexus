use std::collections::HashSet;

use envoy_types::pb::envoy::config::core::v3::{
    header_value_option::HeaderAppendAction, HeaderValue, HeaderValueOption,
};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    processing_response, CommonResponse, HeaderMutation, HeadersResponse, ImmediateResponse,
    ProcessingRequest, ProcessingResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;

use router_core::auth::RouteAuth;
use router_core::domain::RoutingDecision;

use crate::extract::request_header_names;
use crate::strip::trusted_family_strip;

// --------------------------------------------------------------------------- //
// ext_proc response builders.
// --------------------------------------------------------------------------- //
pub(crate) fn header(key: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_owned(),
            raw_value: value.as_bytes().to_vec(),
            ..Default::default()
        }),
        append_action: HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        ..Default::default()
    }
}

/// Inject the trusted workspace annotations + the pool selector (RFC §3.12), plus
/// any normalized request-context annotations (`x-geo-*`, `x-locale`, `x-currency`,
/// `x-privacy-*`, `x-device-type`, …) in `extra`. The edge data plane routes on
/// `x-route-pool`; the backend trusts every header we set here. Client-supplied
/// copies of the trusted family are default-dropped by prefix in this same response
/// (`trusted_family_strip`), the authoritative edge-trusted-header-strip control.
//
// The emitted names are the `x-workspace-*` wire contract (task 4.1 cut-over).
// `x-workspace-id` is the domain's RESOLVED workspace; the identity sidecar runs
// after this filter and either re-asserts it (authoritative, member) or strips it
// (non-member), so the value the backend sees is membership-authorized. The C3 edge
// strip removes any client-forged copy before this filter sets the trusted one.
pub(crate) fn route_response(
    req: &ProcessingRequest,
    d: &RoutingDecision,
    extra: &[(&'static str, String)],
) -> ProcessingResponse {
    let mut set = vec![
        header("x-workspace-id", &d.workspace_id),
        header("x-workspace-plan", &d.plan),
        header("x-workspace-features", &d.features.join(",")),
        header("x-route-pool", d.pool.as_str()),
        header("x-routed-by", "tenant-router"),
    ];
    for (k, v) in extra {
        set.push(header(k, v));
    }
    // edge-trusted-header-strip: default-drop every client-supplied trusted-family header
    // that isn't allowlisted and isn't one we author here. The authored names are excluded
    // (they overwrite authoritatively via OverwriteIfExistsOrAdd), keeping the mutation
    // independent of Envoy's set-vs-remove apply order.
    let authored: HashSet<String> = set
        .iter()
        .filter_map(|opt| opt.header.as_ref())
        .map(|h| h.key.to_ascii_lowercase())
        .collect();
    let remove = trusted_family_strip(&request_header_names(req), &authored);
    let common = CommonResponse {
        header_mutation: Some(HeaderMutation {
            set_headers: set,
            remove_headers: remove,
        }),
        // The edge data plane selects the route from x-route-pool, which we just
        // set — so the route computed before this filter ran must be recomputed.
        // Without this, the pool selector would not affect forwarding.
        clear_route_cache: true,
        ..Default::default()
    };
    ProcessingResponse {
        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
            response: Some(common),
        })),
        ..Default::default()
    }
}

/// Per-route auth policy signal names (RFC N4). Hop-internal: emitted here,
/// consumed by the edge (`jwt_authn` branches on the boolean; the identity
/// sidecar enforces the phase-2 requirements), all C3-stripped from client
/// input so they are unforgeable.
const HDR_AUTH_REQUIRED: &str = "x-auth-required";
const HDR_AUTH_REQUIRES_ROLE: &str = "x-auth-requires-role";
const HDR_AUTH_REQUIRES_ENTITLEMENT: &str = "x-auth-requires-entitlement";
const HDR_AUTH_MIN_AAL: &str = "x-auth-min-aal";
/// identity-existence-hiding: marks a protected route as account-scoped (reachable
/// without a workspace membership). Emitted ONLY when set — absence IS the
/// fail-closed workspace-scoped state the sidecar gates on.
const HDR_AUTH_ACCOUNT_SCOPED: &str = "x-auth-account-scoped";

/// The auth-policy signals for one resolved route. The boolean gate is ALWAYS
/// emitted (`true`|`false`) so the contract is explicit; the phase-2 requirement
/// signals are emitted ONLY when the resolved rule sets them — on the wire,
/// absence IS the no-requirement state (mirroring the zero-config default).
pub(crate) fn auth_signals(auth: &RouteAuth) -> Vec<(&'static str, String)> {
    let mut signals = vec![(
        HDR_AUTH_REQUIRED,
        if auth.required { "true" } else { "false" }.to_owned(),
    )];
    if let Some(role) = &auth.requires_role {
        signals.push((HDR_AUTH_REQUIRES_ROLE, role.clone()));
    }
    if let Some(entitlement) = &auth.requires_entitlement {
        signals.push((HDR_AUTH_REQUIRES_ENTITLEMENT, entitlement.clone()));
    }
    if let Some(aal) = auth.min_aal {
        signals.push((HDR_AUTH_MIN_AAL, aal.to_string()));
    }
    // identity-existence-hiding: emit account-scoped ONLY when set, so its wire
    // absence is the fail-closed (workspace-scoped, membership-gated) default.
    if auth.account_scoped {
        signals.push((HDR_AUTH_ACCOUNT_SCOPED, "true".to_owned()));
    }
    signals
}

/// Reject at the edge before any backend is selected (RFC C18 / tenant isolation).
/// identity-existence-hiding: the body is the SAME minimal `"not found"` the identity
/// sidecar's non-member `not_found_404()` emits, so an authenticated prober cannot
/// distinguish "tenant does not exist" (this path) from "tenant exists, not a member"
/// (the sidecar path) by response body. Operational detail (which host, why) stays in
/// logs/metrics, never the client-facing body.
pub(crate) fn reject_unknown_host() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 404 }),
                body: b"not found".to_vec(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

pub(crate) fn warming_503() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 503 }),
                body: b"routing plane warming up".to_vec(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_core::auth::AuthPolicy;

    /// Spec "Requirements ride the resolved rule": a gated rule emits exactly the
    /// signals it sets, alongside the always-present boolean gate.
    #[test]
    fn gated_rule_emits_only_its_requirement_signals() {
        let auth = RouteAuth {
            required: true,
            requires_role: Some("admin".into()),
            requires_entitlement: None,
            min_aal: Some(2),
            ..RouteAuth::PASS_THROUGH
        };
        let signals = auth_signals(&auth);
        assert_eq!(
            signals,
            vec![
                ("x-auth-required", "true".to_owned()),
                ("x-auth-requires-role", "admin".to_owned()),
                ("x-auth-min-aal", "2".to_owned()),
            ],
        );
    }

    /// identity-existence-hiding: an account-scoped rule emits the extra signal so
    /// the sidecar skips the membership gate; a workspace-scoped rule (the default)
    /// emits nothing extra, so its wire absence is the fail-closed gated state.
    #[test]
    fn account_scoped_rule_emits_its_signal_only_when_set() {
        let account =
            RouteAuth { required: true, account_scoped: true, ..RouteAuth::PASS_THROUGH };
        assert_eq!(
            auth_signals(&account),
            vec![
                ("x-auth-required", "true".to_owned()),
                ("x-auth-account-scoped", "true".to_owned()),
            ],
        );
        let workspace_scoped = RouteAuth { required: true, ..RouteAuth::PASS_THROUGH };
        assert_eq!(
            auth_signals(&workspace_scoped),
            vec![("x-auth-required", "true".to_owned())],
        );
    }

    /// Spec "Phase-1 rules are unchanged": no requirement fields -> only the
    /// boolean gate goes on the wire (absence IS the no-requirement state).
    /// Convergence after a rule change needs no new test: the policy rides the
    /// cached RoutingDecision, which the existing `routing_invalidations`
    /// machinery already drops and reloads.
    #[test]
    fn phase1_rule_emits_only_the_boolean_gate() {
        let public = RouteAuth::PASS_THROUGH;
        assert_eq!(auth_signals(&public), vec![("x-auth-required", "false".to_owned())]);

        let protected = RouteAuth { required: true, ..RouteAuth::PASS_THROUGH };
        assert_eq!(auth_signals(&protected), vec![("x-auth-required", "true".to_owned())]);
    }

    /// `route_response` wires the strip into the ext_proc reply: a forged trusted header on
    /// the incoming request is default-dropped, while the values the router authors ride in
    /// set_headers and are never also removed.
    #[test]
    fn route_response_strips_forged_trusted_headers_and_preserves_authored() {
        use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
        use envoy_types::pb::envoy::service::ext_proc::v3::{processing_request, HttpHeaders};
        use super::{processing_response, ProcessingRequest, RoutingDecision};
        use router_core::domain::Pool;

        let hv = |k: &str| HeaderValue { key: k.to_owned(), ..Default::default() };
        let req = ProcessingRequest {
            request: Some(processing_request::Request::RequestHeaders(HttpHeaders {
                headers: Some(HeaderMap {
                    headers: vec![
                        hv("x-user-suspended"),      // forged -> must be stripped
                        hv("x-identity-contract"),   // forged -> must be stripped
                        hv("x-requested-workspace"), // allowlisted -> kept
                        hv("authorization"),         // ordinary -> kept
                    ],
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let decision = RoutingDecision {
            workspace_id: "ws-1".to_owned(),
            plan: "pro".to_owned(),
            pool: Pool::new("evenout"),
            features: Vec::new(),
            auth: AuthPolicy::default(),
        };
        let resp = route_response(&req, &decision, &[]);
        let Some(processing_response::Response::RequestHeaders(headers)) = &resp.response else {
            unreachable!("route_response always returns a RequestHeaders response");
        };
        let mutation =
            headers.response.as_ref().and_then(|c| c.header_mutation.as_ref()).expect("mutation set");
        let removed: HashSet<&str> = mutation.remove_headers.iter().map(String::as_str).collect();
        let set: HashSet<String> = mutation
            .set_headers
            .iter()
            .filter_map(|opt| opt.header.as_ref())
            .map(|h| h.key.to_ascii_lowercase())
            .collect();

        // Forged trusted headers on client input are dropped.
        assert!(removed.contains("x-user-suspended"), "forged suspension dropped");
        assert!(removed.contains("x-identity-contract"), "forged contract dropped");
        // Allowlisted hint + ordinary headers survive.
        assert!(!removed.contains("x-requested-workspace"), "allowlisted hint survives");
        assert!(!removed.contains("authorization"), "ordinary header survives");
        // The router's authored values ride set_headers and are never also on the remove list.
        assert!(set.contains("x-workspace-id") && !removed.contains("x-workspace-id"));
        assert!(set.contains("x-route-pool") && !removed.contains("x-route-pool"));
    }
}
