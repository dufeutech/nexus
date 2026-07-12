//! Request-side extraction (C11): pull the verified subject/service/api-key, the
//! trusted routing headers (acting workspace, route pool), the boolean gate flags,
//! and the per-route requirement signals out of the ext_proc request. The token is
//! never parsed here — only the metadata Envoy's `jwt_authn` already verified.

use tonic::metadata::MetadataMap;

use envoy_types::pb::envoy::config::core::v3::HeaderMap;
use envoy_types::pb::envoy::service::ext_proc::v3::{
    processing_request, HttpHeaders, ProcessingRequest,
};

use crate::state::{
    HDR_MIN_AAL, HDR_REQUIRES_ENTITLEMENT, HDR_REQUIRES_ROLE, JWT_NS, PAYLOAD_KEY, SVC_PAYLOAD_KEY,
};

// --------------------------------------------------------------------------- //
// Metadata extraction (C11): the verified `sub` and whether the request is
// authenticated. The token answers ONLY "who am I" — the `roles` claim is
// deliberately NOT read (nexus-native-authorization spec R1): roles, entitlements,
// and suspension are nexus-authored and sourced from the live Profile via the
// AuthzResolver, so a provider-asserted role confers nothing and a grant/revoke
// takes effect within seconds without a token refresh.
// --------------------------------------------------------------------------- //
pub(crate) fn extract_identity(req: &ProcessingRequest) -> (String, bool) {
    use envoy_types::pb::google::protobuf::value::Kind;
    let fields = match req
        .metadata_context
        .as_ref()
        .and_then(|md| md.filter_metadata.get(JWT_NS))
    {
        // No verified-credential metadata at all → anonymous.
        Some(ns) => match ns.fields.get(PAYLOAD_KEY).and_then(|v| v.kind.as_ref()) {
            Some(Kind::StructValue(s)) => &s.fields,
            _ => &ns.fields,
        },
        None => return ("anonymous".to_owned(), true),
    };
    // A verified `sub` is the authority for "authenticated": its presence flips
    // is-anonymous to false. Absence (no sub claim) stays anonymous. No authorization
    // claim (`roles`/`:roles`) is read here — authorization is nexus-sourced (R1).
    match fields.get("sub").and_then(|v| v.kind.as_ref()) {
        Some(Kind::StringValue(s)) if !s.is_empty() => (s.clone(), true),
        _ => ("anonymous".to_owned(), false),
    }
}

/// The SECOND authenticator in the chain (normalized-principal task 4.1): read the
/// verified service identity the core-service `jwt_authn` provider wrote under
/// [`SVC_PAYLOAD_KEY`]. The verified `sub` (`system:serviceaccount:ns:name` for a K8s
/// SA token) is the opaque service id — nexus-authored, never client-asserted, since it
/// comes from Envoy's verified-JWT metadata, not a request header. `None` when the
/// service provider did not verify a token on this request. Consulted only AFTER the
/// human branch declines, so a human token always wins.
pub(crate) fn extract_service(req: &ProcessingRequest) -> Option<String> {
    use envoy_types::pb::google::protobuf::value::Kind;
    let ns = req
        .metadata_context
        .as_ref()
        .and_then(|md| md.filter_metadata.get(JWT_NS))?;
    let fields = match ns.fields.get(SVC_PAYLOAD_KEY).and_then(|v| v.kind.as_ref()) {
        Some(Kind::StructValue(s)) => &s.fields,
        _ => return None,
    };
    match fields.get("sub").and_then(|v| v.kind.as_ref()) {
        Some(Kind::StringValue(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// The THIRD authenticator in the chain (`customer-api-keys` task 4.1): read the opaque
/// Personal Access Token secret a client presents in the dedicated `x-api-key` request
/// header. A PAT is not a ZITADEL JWT, so it never appears in `jwt_authn` metadata — it
/// arrives as this header, verified in the sidecar (design.md `/opsx:decide`). Consulted
/// only AFTER the human branch declines (a human token always wins), and its raw value is
/// STRIPPED before the backend (defense-in-depth) so the secret never reaches a box.
/// `None` when the request carries no `x-api-key`.
pub(crate) fn extract_api_key(req: &ProcessingRequest) -> Option<String> {
    let Some(processing_request::Request::RequestHeaders(HttpHeaders { headers: Some(map), .. })) =
        &req.request
    else {
        return None;
    };
    find_header(map, "x-api-key")
}

/// Read one request header by (case-insensitive) name from the ext_proc
/// `HttpHeaders` payload. Envoy carries the value in `raw_value` (bytes) on modern
/// wire versions and the legacy `value` (string) otherwise — accept either. An
/// empty value is treated as absent.
fn find_header(map: &HeaderMap, name: &str) -> Option<String> {
    map.headers
        .iter()
        .find(|h| h.key.eq_ignore_ascii_case(name))
        .and_then(|h| {
            if h.raw_value.is_empty() {
                Some(h.value.clone())
            } else {
                String::from_utf8(h.raw_value.clone()).ok()
            }
        })
        .filter(|v| !v.is_empty())
}

/// The edge propagates each request's trace context as gRPC METADATA on the ext_proc
/// call (it traces the call itself as an egress span). The ext_proc HTTP headers do
/// NOT carry `traceparent` at this point — the edge injects that toward the backend
/// AFTER the ext_proc filters run — so the gRPC metadata is the correct source. One
/// ext_proc gRPC stream per HTTP request, so this metadata is this request's context.
pub(crate) fn trace_metadata(metadata: &MetadataMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in ["traceparent", "tracestate"] {
        if let Some(value) = metadata.get(name).and_then(|value| value.to_str().ok()) {
            out.push((name.to_owned(), value.to_owned()));
        }
    }
    out
}

/// The workspace the request is acting in, as resolved by the routing plane and
/// carried on a TRUSTED header (never a client-forged value — the edge strips the
/// client's copy and the routing stage overwrites it authoritatively, C3). Prefer
/// the post-cut-over `x-workspace-id`; fall back to the routing plane's current
/// `x-tenant-id` so this works both before and after the header rename (task 4.1).
/// `None` when the request carries no resolved workspace (e.g. a public route) — no
/// acting scope is then authorized.
pub(crate) fn extract_acting_workspace(req: &ProcessingRequest) -> Option<String> {
    let Some(processing_request::Request::RequestHeaders(HttpHeaders { headers: Some(map), .. })) =
        &req.request
    else {
        return None;
    };
    find_header(map, "x-workspace-id").or_else(|| find_header(map, "x-tenant-id"))
}

/// The destination box for this request, from the tenant-router's trusted
/// `x-route-pool` (edge-stripped from client input). Used as the signed contract's
/// `aud` so a token minted for one box cannot be replayed at another. `None` when no
/// pool is resolved — then no token is minted (the request is not a routed data door).
pub(crate) fn extract_route_pool(req: &ProcessingRequest) -> Option<String> {
    let Some(processing_request::Request::RequestHeaders(HttpHeaders { headers: Some(map), .. })) =
        &req.request
    else {
        return None;
    };
    find_header(map, "x-route-pool")
}

/// True when a trusted boolean route-policy signal is present and equals `"true"`.
/// Absence is `false` — the fail-closed reading for `x-auth-account-scoped`
/// (absent ⇒ workspace-scoped ⇒ gated) and the not-enriched reading for
/// `x-auth-required`. These headers are C3-stripped from client input, so a
/// present value is authoritative (a client can neither forge nor suppress it).
pub(crate) fn trusted_flag(req: &ProcessingRequest, name: &str) -> bool {
    let Some(processing_request::Request::RequestHeaders(HttpHeaders { headers: Some(map), .. })) =
        &req.request
    else {
        return false;
    };
    find_header(map, name).as_deref() == Some("true")
}

/// The per-route requirements resolved by the tenant-router for THIS request,
/// read from its trusted signals. `min_aal` is kept raw: an unparseable value is
/// a requirement we cannot evaluate, which must DENY (fail-closed), not vanish.
#[derive(Default)]
pub(crate) struct RouteRequirements {
    pub(crate) role: Option<String>,
    pub(crate) entitlement: Option<String>,
    pub(crate) min_aal: Option<String>,
}

impl RouteRequirements {
    pub(crate) const fn any(&self) -> bool {
        self.role.is_some() || self.entitlement.is_some() || self.min_aal.is_some()
    }
}

pub(crate) fn extract_requirements(req: &ProcessingRequest) -> RouteRequirements {
    let Some(processing_request::Request::RequestHeaders(HttpHeaders { headers: Some(map), .. })) =
        &req.request
    else {
        return RouteRequirements::default();
    };
    RouteRequirements {
        role: find_header(map, HDR_REQUIRES_ROLE),
        entitlement: find_header(map, HDR_REQUIRES_ENTITLEMENT),
        min_aal: find_header(map, HDR_MIN_AAL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::collections::HashMap;
    use crate::state::{HDR_ACCOUNT_SCOPED, HDR_AUTH_REQUIRED};

    #[test]
    fn service_metadata_is_read_from_the_second_provider_key() {
        // Task 4.1: extract_service reads the verified sub the 2nd jwt_authn provider
        // wrote under SVC_PAYLOAD_KEY — not the human `verified` key.
        use envoy_types::pb::envoy::config::core::v3::Metadata;
        use envoy_types::pb::google::protobuf::{value::Kind, Struct, Value};
        let mut svc_fields = HashMap::new();
        svc_fields.insert(
            "sub".to_owned(),
            Value { kind: Some(Kind::StringValue("system:serviceaccount:nexus:events-writer".to_owned())) },
        );
        let mut ns_fields = HashMap::new();
        ns_fields.insert(
            SVC_PAYLOAD_KEY.to_owned(),
            Value { kind: Some(Kind::StructValue(Struct { fields: svc_fields })) },
        );
        let req = ProcessingRequest {
            metadata_context: Some(Metadata {
                filter_metadata: {
                    let mut m = HashMap::new();
                    m.insert(JWT_NS.to_owned(), Struct { fields: ns_fields });
                    m
                },
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            extract_service(&req).as_deref(),
            Some("system:serviceaccount:nexus:events-writer"),
        );
        // A request with only the human `verified` key yields no service.
        let human = req_with_headers(&[]);
        assert!(extract_service(&human).is_none());
    }

    #[test]
    fn caller_cannot_self_assert_service_kind() {
        // Task 5.3 / spec R "kind is system-authored, never caller-asserted": a client
        // sending forged `x-user-type: service` + acting-scope headers confers NOTHING.
        // The service kind comes ONLY from the verified 2nd-provider metadata
        // (extract_service reads metadata, never a header), and the enrich path strips
        // any client-authored acting scope on the unresolved (here anonymous) path.
        let forged = req_with_headers(&[
            ("x-user-type", "service"),
            ("x-workspace-id", "ws-forged"),
            ("x-identity-contract", "client.forged.jws"),
        ]);
        // No verified service metadata -> not a service principal.
        assert!(extract_service(&forged).is_none());
        // Anonymous enrich (no authority) strips the forged acting scope + contract.
        let resp = enrich_response("anonymous", None, false, None);
        assert!(!set_headers(&resp).contains_key("x-user-type"));
        let r = remove_headers(&resp);
        for hh in ["x-workspace-id", "x-user-type", "x-user-role", "x-identity-contract"] {
            assert!(r.contains(&hh.to_owned()), "a self-asserted {hh} must be stripped");
        }
    }

    #[test]
    fn acting_workspace_prefers_x_workspace_id_then_x_tenant_id() {
        // The post-cut-over authoritative name wins over the routing plane's current
        // x-tenant-id.
        let both = req_with_headers(&[("x-tenant-id", "ws_routing"), ("x-workspace-id", "ws_new")]);
        assert_eq!(extract_acting_workspace(&both).as_deref(), Some("ws_new"));
        // Falls back to the routing plane's current header before the rename.
        let legacy = req_with_headers(&[("X-Tenant-Id", "ws_routing")]);
        assert_eq!(extract_acting_workspace(&legacy).as_deref(), Some("ws_routing"));
        // An empty value is treated as absent (no acting workspace).
        let empty = req_with_headers(&[("x-workspace-id", "")]);
        assert_eq!(extract_acting_workspace(&empty), None);
    }

    #[test]
    fn requirement_signals_are_read_and_stripped() {
        // The tenant-router's trusted signals parse out of the request…
        let req = req_with_headers(&[
            ("x-auth-requires-role", "admin"),
            ("x-auth-min-aal", "2"),
        ]);
        let r = extract_requirements(&req);
        assert_eq!(r.role.as_deref(), Some("admin"));
        assert_eq!(r.entitlement, None);
        assert_eq!(r.min_aal.as_deref(), Some("2"));
        // …and every forwarded response strips them (policy detail never
        // reaches the backend), alongside the phase-1 boolean.
        let resp = enrich_response("u1", None, true, None);
        let removed = remove_headers(&resp);
        for h in ["x-auth-required", "x-auth-requires-role", "x-auth-requires-entitlement", "x-auth-min-aal"] {
            assert!(removed.contains(&h.to_owned()), "must strip {h}");
        }
    }

    /// 5.8: the trusted flags are read only from the exact value "true"; anything
    /// else — a client-set "false", a bogus value, or an absent header — reads
    /// false. Combined with the edge C3 strip, a client can neither forge nor
    /// suppress the gate: absence of account-scoped is the fail-closed gated state.
    #[test]
    fn trusted_flag_reads_only_literal_true() {
        let yes = req_with_headers(&[(HDR_AUTH_REQUIRED, "true")]);
        assert!(trusted_flag(&yes, HDR_AUTH_REQUIRED));
        let no = req_with_headers(&[(HDR_AUTH_REQUIRED, "false")]);
        assert!(!trusted_flag(&no, HDR_AUTH_REQUIRED));
        let bogus = req_with_headers(&[(HDR_ACCOUNT_SCOPED, "1")]);
        assert!(!trusted_flag(&bogus, HDR_ACCOUNT_SCOPED));
        // Absent -> false (account-scoped absence = workspace-scoped = fail-closed).
        let absent = req_with_headers(&[("x-other", "true")]);
        assert!(!trusted_flag(&absent, HDR_ACCOUNT_SCOPED));
    }

}
