//! The enrichment core: turn a resolved principal ([`Enriched`]) + plan + signing
//! context into the ext_proc header mutation ([`enrich_response`]), the immediate
//! 503/403/404 response builders, the pure existence-hiding predicate, and the
//! route-requirement authorization (the production PDP path + the `#[cfg(test)]`
//! parity oracle).

use std::sync::Arc;

use tracing::warn;

use envoy_types::pb::envoy::config::core::v3::{
    header_value_option::HeaderAppendAction, HeaderValue, HeaderValueOption,
};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    processing_response, CommonResponse, HeaderMutation, HeadersResponse, ImmediateResponse,
    ProcessingResponse,
};
use envoy_types::pb::envoy::r#type::v3::HttpStatus;

use identity_core::{PrincipalKind, Profile, ResolvedMembership};

use crate::signer;
use crate::state::{HDR_MIN_AAL, HDR_REQUIRES_ENTITLEMENT, HDR_REQUIRES_ROLE};
use crate::token_cache::ContractTokenCache;

// --------------------------------------------------------------------------- //
// ext_proc response builders.
// --------------------------------------------------------------------------- //
fn header(key: &str, value: &str) -> HeaderValueOption {
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

/// The resolved acting authority the enrich path authors (normalized-principal task
/// 4.x). Computed by the caller from the principal kind + resolution, and consumed
/// uniformly by [`enrich_response`]: a `Some` authors the acting scope + mints a
/// contract; `None` (unresolved) STRIPS the acting scope and mints nothing (fail-closed).
pub(crate) enum Acting {
    /// Workspace authority (user / api-key): the matched live membership. Authors
    /// `x-user-type` = staff|customer + `x-user-role`.
    Workspace(ResolvedMembership),
    /// Platform authority (core service): the acting workspace (from the trusted
    /// `x-workspace-id`) + the least-privilege permission set. Authors
    /// `x-user-type` = `service` and NO workspace role.
    Platform {
        workspace_id: String,
        permissions: Vec<String>,
    },
}

/// The resolved principal the enrich path authors from — bundled so `enrich_response`
/// stays within the argument budget (the same discipline as [`SignContext`]). Produced
/// by the kind-branched resolution; `acting = None` means no authority resolved
/// (fail-closed: acting scope stripped, no contract minted).
pub(crate) struct Enriched<'a> {
    /// The subject to author as `x-user-id` — a user `sub`, a service id, or an api-key id.
    pub(crate) sub: &'a str,
    /// The principal-kind label (`user`/`service`/`apikey`); `None` when anonymous.
    pub(crate) kind: Option<&'static str>,
    /// The subject this principal acts **on behalf of** — the creating user for an
    /// api-key principal (`customer-api-keys`); `None` for user/service. Authored as the
    /// `on_behalf_of` contract claim + `x-user-on-behalf-of` header alongside the acting
    /// scope.
    pub(crate) on_behalf_of: Option<&'a str>,
    /// The live Profile backing the user authz headers; `None` for a service, a
    /// profile miss, or an anonymous request.
    pub(crate) profile: Option<Arc<Profile>>,
    /// Whether the caller is authenticated (a user OR a service).
    pub(crate) authenticated: bool,
    /// The resolved acting authority to author + mint; `None` = fail-closed.
    pub(crate) acting: Option<Acting>,
}

/// The inputs for minting the signed identity contract, bundled so `enrich_response`
/// stays within the argument budget: the configured signer (absent = signing off),
/// the destination box (`aud`, from `x-route-pool`), and the current epoch seconds.
pub(crate) struct SignContext<'a> {
    pub(crate) signer: Option<&'a signer::Signer>,
    /// hot-path-rps-optimization: the contract reuse cache. When `Some`, a resolved mint
    /// goes through it (reuse a cached token or mint+cache); when `None`, sign per request
    /// (cache disabled, or the enrich unit tests). Sign-per-request behavior is unchanged.
    pub(crate) cache: Option<&'a ContractTokenCache>,
    pub(crate) route_pool: Option<&'a str>,
    pub(crate) now: u64,
}

pub(crate) fn enrich_response(
    who: &Enriched<'_>,
    plan: Option<&str>,
    sign_ctx: &SignContext<'_>,
) -> ProcessingResponse {
    // Rebind the resolved-principal bundle to the names the authoring body reads. The
    // `Arc` clone is cheap; the body only ever borrows the profile (never moves it).
    let sub = who.sub;
    let principal_kind = who.kind;
    let on_behalf_of = who.on_behalf_of;
    let profile = who.profile.clone();
    let authenticated = who.authenticated;
    let acting = who.acting.as_ref();
    // Trusted auth-state, emitted on EVERY request (incl. the no-credential path)
    // so a backend never has to infer it from the absence of a header. Standards:
    // RFC 6750 bearer presence drives is-anonymous; richer assurance (NIST
    // SP 800-63B AAL, mTLS) can extend `x-auth-method` later. These are stripped
    // from client input (C3) so a client cannot self-assert as authenticated.
    // `x-identity-contract` is NO LONGER authored here unconditionally: since
    // identity-contract-signing it is a signed token minted only for a resolved
    // identity (see the mint-or-strip block after the acting-scope resolution).
    let mut set = vec![
        header("x-auth-anonymous", if authenticated { "false" } else { "true" }),
        header("x-auth-method", if authenticated { "bearer" } else { "none" }),
        header("x-user-id", sub),
    ];
    // Roles are NEXUS-AUTHORED (spec R1) and now ride ONLY the signed contract's `roles`
    // claim (identity-revocation-integrity): the bare `x-user-roles` mirror is RETIRED, so
    // there is no unsigned twin a client or on-path party could forge. The sidecar always
    // STRIPS any client-supplied `x-user-roles` (below) — a box reads roles from the
    // verified contract, never a header. (`x-user-roles-source` was already retired.)
    // COARSE DEFENSE-IN-DEPTH strip (edge-trusted-header-strip, design D2): the
    // AUTHORITATIVE default-drop of the trusted family is a single-sourced PREFIX drop
    // in the tenant-router ext_proc (`routing-rs`, `trusted_family_strip`), the first
    // component every box-bound request crosses. This exact-name denylist is a
    // belt-and-suspenders re-strip in case the sidecar is somehow reached without the
    // tenant-router/edge in front — it is NOT the load-bearing control, so its
    // completeness is no longer a maintenance invariant. It removes any client-supplied
    // identity header this filter does NOT itself author on THIS path. Headers we DO set
    // below are overwritten authoritatively (OverwriteIfExistsOrAdd), so they are
    // deliberately kept OUT of this remove list — keeping the result independent of
    // Envoy's set-vs-remove apply order (a header in both lists could otherwise be wiped
    // after we set it).
    // `x-auth-required` is consumed by jwt_authn upstream and never authored
    // here, so it is always stripped before forwarding to the backend. The
    // phase-2 requirement signals are consumed by THIS filter's gate and are
    // policy detail no backend needs — stripped the same way (design D5).
    let mut remove = vec![
        "x-auth-required".to_owned(),
        HDR_REQUIRES_ROLE.to_owned(),
        HDR_REQUIRES_ENTITLEMENT.to_owned(),
        HDR_MIN_AAL.to_owned(),
        // The revocation-sensitive signals + coarse roles now ride ONLY the signed
        // contract (identity-revocation-integrity). Their bare header mirrors are retired
        // and ALWAYS stripped from client input on every path, so no unsigned twin can be
        // forged and a box only ever trusts the value carried over the signature.
        "x-user-roles".to_owned(),
        "x-user-entitlements".to_owned(),
        "x-user-suspended".to_owned(),
    ];
    // The nexus-owned acting scope (workspace-tenancy 3.2). Authored ONLY from a
    // LIVE membership check of the resolved workspace against the Profile — never
    // from the token — so a revoked/changed membership takes effect within seconds
    // (like suspension). A non-member, an absent profile, or no resolved workspace
    // authors nothing and STRIPS any client/forged copy, so the sidecar can never
    // let an unauthorized acting scope reach the backend (fail-closed; the
    // reject-vs-anonymous-vs-signup policy for a non-member is the backend's, per
    // the surface). `x-user-type`/`x-user-role` are the matched relationship's, not
    // a global role; the coarse global roles now ride ONLY the signed contract's
    // `roles` claim (the bare `x-user-roles` mirror is retired, stripped above). For a
    // SERVICE (Platform authority, normalized-principal task 4.4) the
    // acting `x-user-type` is `service` — the principal kind the box branches its write
    // door on — and there is NO workspace role, so `x-user-role` is stripped.
    match acting {
        Some(Acting::Workspace(m)) => {
            set.push(header("x-workspace-id", &m.workspace_id));
            set.push(header("x-user-type", m.member_type.as_str()));
            set.push(header("x-user-role", &m.role));
        }
        Some(Acting::Platform { workspace_id, .. }) => {
            set.push(header("x-workspace-id", workspace_id));
            set.push(header("x-user-type", PrincipalKind::Service.as_str()));
            remove.push("x-user-role".to_owned());
        }
        None => {
            remove.push("x-workspace-id".to_owned());
            remove.push("x-user-type".to_owned());
            remove.push("x-user-role".to_owned());
        }
    }
    // The on-behalf-of subject (customer-api-keys): authored ONLY alongside a resolved
    // acting authority (an api-key principal), so audit/attribution rides with the
    // contract. On every other path — user, service, or an unresolved key — it is absent
    // and any client copy is STRIPPED (a caller can never self-assert who it acts for).
    // The raw `x-api-key` credential is ALWAYS stripped before the backend so the secret
    // never reaches a box (defense-in-depth; the edge should also strip it).
    remove.push("x-api-key".to_owned());
    match (on_behalf_of, acting.is_some()) {
        (Some(obo), true) => set.push(header("x-user-on-behalf-of", obo)),
        _ => remove.push("x-user-on-behalf-of".to_owned()),
    }
    // The acting workspace's plan tier (workspace-plan-tier). NEXUS-AUTHORED from the
    // resident routing-plane snapshot (`resolve_plan`), never a client hint — so any
    // client-supplied `x-workspace-plan` is STRIPPED when nexus resolves none. Authored
    // ONLY alongside a resolved acting authority (the caller passes `Some` only then), so
    // the header and the signed `plan` claim always agree. An unresolved/unknown workspace
    // (or plan projection unconfigured) omits the header — a box treats absence as
    // not-provisioned (fail-soft, design D2; NOT a 503, unlike missing membership).
    match plan {
        Some(p) => set.push(header("x-workspace-plan", p)),
        None => remove.push("x-workspace-plan".to_owned()),
    }
    // The signed identity contract (identity-contract-signing). `x-identity-contract` is
    // ALWAYS a signed token — there is no plain-string form. It is minted ONLY for a
    // fully-resolved request (authenticated AND a member of the acting workspace, with a
    // signer configured and a destination box for `aud`, which scopes replay per box). On
    // every other path — anonymous, profile-miss, non-member, a signing failure, or no
    // signer configured — nothing is authored and any client copy is STRIPPED, so a
    // verifying box fails closed.
    // The mint guard is GENERALIZED (normalized-principal task 4.3) from "has a
    // membership" to "has a RESOLVED AUTHORITY" — a Workspace membership (user/api-key)
    // OR a Platform permission set (service). A service mints despite having no
    // membership, using the acting `x-workspace-id`; the claims omit member_type/role
    // and carry the platform `permissions` + `principal_kind: service`.
    let kind = principal_kind.unwrap_or(PrincipalKind::User.as_str());
    let minted = match (sign_ctx.signer, acting, sign_ctx.route_pool) {
        (Some(active_signer), Some(a), Some(aud)) if authenticated => {
            let input = match a {
                Acting::Workspace(m) => signer::MintInput {
                    sub,
                    aud,
                    principal_kind: kind,
                    on_behalf_of,
                    workspace_id: &m.workspace_id,
                    member_type: Some(m.member_type.as_str()),
                    role: Some(m.role.as_str()),
                    roles: profile.as_ref().map_or(&[], |p| p.roles.as_slice()),
                    permissions: &[],
                    // Same nexus-resolved plan as the header — omitted when unresolved.
                    plan,
                    // identity-revocation-integrity: the revocation-sensitive signals ride
                    // the signature, sourced from the SAME per-request Profile that used to
                    // author the bare `x-user-entitlements`/`x-user-suspended` headers.
                    // Omitted when the profile is unresolved so absence reads as "unknown".
                    entitlements: profile.as_ref().map(|p| p.entitlements.as_slice()),
                    suspended: profile.as_ref().map(|p| p.is_suspended),
                    now: sign_ctx.now,
                },
                Acting::Platform { workspace_id, permissions } => signer::MintInput {
                    sub,
                    aud,
                    principal_kind: PrincipalKind::Service.as_str(),
                    on_behalf_of: None,
                    workspace_id,
                    member_type: None,
                    role: None,
                    roles: &[],
                    permissions,
                    plan,
                    // A service principal is not a suspendable user and carries no
                    // entitlement set — omit both so the box reads them as N/A, not `false`.
                    entitlements: None,
                    suspended: None,
                    now: sign_ctx.now,
                },
            };
            // hot-path-rps-optimization: reuse a cached signed contract when the cache is
            // enabled (a skipped ES256 sign); otherwise sign per request. Both paths mint
            // the identical claims — the cache only changes WHETHER we re-sign.
            let signed = match sign_ctx.cache {
                Some(cache) => cache.get_or_mint(active_signer, &input, sign_ctx.now),
                None => active_signer.mint(&input),
            };
            signed
                .map_err(|e| {
                    warn!(error = %e, "contract signing failed -> no token stamped (fail-closed)");
                })
                .ok()
        }
        _ => None,
    };
    if let Some(token) = &minted {
        set.push(header("x-identity-contract", token));
    } else {
        remove.push("x-identity-contract".to_owned());
    }
    // `x-user-org` is retired (workspace-tenancy): the fixed home org is no longer
    // an authorization input, so it is NEVER authored and ALWAYS stripped from
    // client input, on every path.
    remove.push("x-user-org".to_owned());
    // The revocation-sensitive signals (entitlements/suspended) are NO LONGER emitted as
    // bare headers — they ride the signed contract's `entitlements`/`suspended` claims
    // (identity-revocation-integrity), minted above from this SAME `profile`. Their bare
    // twins are unconditionally stripped (see the `remove` seed), so a box can only trust
    // the nexus-authored, unforgeable value carried over the signature, and the
    // profile-miss path omits the signed claim entirely (absence reads as "unknown",
    // never a client-asserted "false"). We keep only the enrichment marker.
    set.push(header(
        "x-user-enriched-by",
        if profile.is_some() { "identity-sidecar-rs" } else { "identity-sidecar-rs:miss" },
    ));
    let common = CommonResponse {
        header_mutation: Some(HeaderMutation {
            set_headers: set,
            remove_headers: remove,
        }),
        ..Default::default()
    };
    ProcessingResponse {
        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
            response: Some(common),
        })),
        ..Default::default()
    }
}

fn immediate_503(body: &'static str) -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 503 }),
                body: body.as_bytes().to_vec(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

pub(crate) fn warming_503() -> ProcessingResponse {
    immediate_503("identity plane warming up")
}

/// Fail-closed block: the request is authenticated but the subject's profile
/// (incl. its revocation-sensitive `is_suspended`) could not be read. Refuse
/// rather than serve a trust decision we cannot make (see `AppState::fail_open`).
pub(crate) fn unavailable_503() -> ProcessingResponse {
    immediate_503("identity store unavailable")
}

/// N4 phase-2 rejection: the route's resolved requirements are not satisfied by
/// this request's enrichment. The body deliberately names no requirement — the
/// policy detail stays at the edge.
pub(crate) fn forbidden_403() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::ImmediateResponse(
            ImmediateResponse {
                status: Some(HttpStatus { code: 403 }),
                body: b"forbidden".to_vec(),
                ..Default::default()
            },
        )),
        ..Default::default()
    }
}

/// identity-existence-hiding decision (pure, unit-tested like `must_fail_closed`):
/// hide the workspace behind a 404 when the route is **enriched** (`auth_required`)
/// AND **workspace-scoped** (`!account_scoped`) AND a workspace was resolved
/// (`has_workspace`) AND **no acting authority resolved** (`!acting_resolved` — the
/// caller holds no live membership of that workspace, uniform across every
/// principal kind). A member (`acting_resolved`) is never hidden: they fall through
/// to the honest 403 for a missing role. Public (`!auth_required`) and
/// account-scoped routes are never gated. `account_scoped` defaults false on the
/// wire, so its absence is the fail-closed (gated) reading.
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "a pure decision over four independent, named trusted route/enrichment flags — a struct would not clarify a single-expression predicate"
)]
pub(crate) const fn hide_nonmember_as_404(
    auth_required: bool,
    account_scoped: bool,
    has_workspace: bool,
    acting_resolved: bool,
) -> bool {
    auth_required && !account_scoped && has_workspace && !acting_resolved
}

/// identity-existence-hiding: refuse a non-member of the routed workspace with a
/// 404 that is byte-identical to the not-found a nonexistent workspace yields — so
/// a caller with no membership cannot distinguish "forbidden" from "does not
/// exist". The body is a fixed minimal literal and NO header is set (uniform
/// envelope): the response leaks nothing through status, body, or headers, and the
/// two producing branches (non-member vs nonexistent) are one code path, so they
/// also converge in timing. Mirrors `forbidden_403()`; the honest 403 is reserved
/// for a *member* who merely lacks a required role/entitlement.
pub(crate) fn not_found_404() -> ProcessingResponse {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, reason = "test helpers legitimately panic on the impossible branch")]
    use super::*;
    use crate::test_support::*;
    use crate::test_support::enrich_response;
    use crate::jwks;
    use crate::state::now_secs;
    use identity_core::{MemberType, Membership};
    use tokio::sync::watch;
    use tower::util::ServiceExt;

    #[test]
    fn strips_unauthored_identity_headers_defense_in_depth() {
        // x-auth-required is consumed by jwt_authn upstream and is never authored
        // by the sidecar -> always stripped before the backend, on every path.
        let some = enrich_response(
            "u1",
            Some(Arc::new(Profile { sub: "u1".into(), ..Default::default() })),
            true,
            None,
        );
        let r_some = remove_headers(&some);
        assert!(r_some.contains(&"x-auth-required".to_owned()));
        // identity-revocation-integrity: the bare entitlements/suspended/roles mirrors are
        // RETIRED — those signals ride the signed contract now — so their client copies are
        // ALWAYS stripped, even on the profile-present path, and never re-emitted as headers.
        for h in ["x-user-suspended", "x-user-entitlements", "x-user-roles"] {
            assert!(r_some.contains(&h.to_owned()), "retired mirror {h} must always be stripped");
            assert!(!set_headers(&some).contains_key(h), "retired mirror {h} must not be emitted");
        }
        // `x-user-org` is retired: never authored, so ALWAYS stripped — even on the
        // profile-present path.
        assert!(r_some.contains(&"x-user-org".to_owned()));
        // edge-trusted-header-strip: the allowlisted client hint `x-requested-workspace`
        // is NOT a trusted-family header — the sidecar must never strip it (the
        // authoritative prefix drop in the tenant-router likewise preserves it).
        assert!(
            !r_some.contains(&"x-requested-workspace".to_owned()),
            "the allowlisted client hint must survive the sidecar strip",
        );
        // No acting workspace resolved -> no membership -> the acting scope is
        // stripped, never asserted.
        for h in ["x-workspace-id", "x-user-type", "x-user-role"] {
            assert!(r_some.contains(&h.to_owned()), "non-member must strip {h}");
        }

        // On a profile MISS the sidecar authors none of those, so any client copy
        // must be stripped — suspension especially (absent == unknown).
        let miss = enrich_response("u1", None, true, None);
        let r_miss = remove_headers(&miss);
        for h in ["x-auth-required", "x-user-org", "x-user-entitlements", "x-user-suspended"] {
            assert!(r_miss.contains(&h.to_owned()), "miss path must strip {h}");
        }
        // And it must still not ASSERT a suspension on the miss path.
        assert!(!set_headers(&miss).contains_key("x-user-suspended"));
    }

    #[test]
    fn enrich_signs_live_suspension_from_profile_and_retires_the_bare_header() {
        // identity-revocation-integrity: the revocation gate rides the SIGNED contract,
        // sourced live from the Profile — never a bare header a client could forge. A
        // suspended, resolved member's contract carries suspended=true (and its
        // entitlements), while the bare x-user-suspended/x-user-entitlements are RETIRED
        // (never emitted, always stripped).
        let signer = test_signer();
        let ctx = SignContext { signer: Some(&signer), cache: None, route_pool: Some("evenout"), now: now_secs() };
        let suspended = Arc::new(Profile {
            sub: "u1".into(),
            is_suspended: true,
            entitlements: vec!["beta".into()],
            memberships: vec![Membership {
                workspace_id: "ws-1".into(),
                member_type: MemberType::Staff,
                role: "admin".into(),
                entitlements: Vec::new(),
            }],
            ..Default::default()
        });
        let resp = enrich_signed("u1", Some(suspended), true, Some("ws-1"), &ctx);
        let h = set_headers(&resp);
        assert_eq!(h.get("x-auth-anonymous").map(String::as_str), Some("false"));
        // The bare mirrors are gone; a box reads the gate from the verified claim only.
        assert!(!h.contains_key("x-user-suspended"), "the bare suspension header is retired");
        assert!(!h.contains_key("x-user-entitlements"), "the bare entitlements header is retired");
        let token = h.get("x-identity-contract").expect("a resolved member carries a contract");
        let claims = decode_contract(token);
        assert_eq!(claims.suspended, Some(true), "the suspension rides the signed contract");
        assert_eq!(claims.entitlements, Some(vec!["beta".to_owned()]), "entitlements ride it too");

        // A profile MISS (no row) must NOT assert a suspension either way — the signed
        // claim is OMITTED (absence == unknown), which is exactly why a store outage that
        // collapses to "miss" is dangerous and must instead fail closed.
        let h_miss = set_headers(&enrich_response("u1", None, true, None));
        assert!(!h_miss.contains_key("x-user-suspended"));
    }

    #[test]
    fn unavailable_503_is_a_blocking_503() {
        assert!(is_immediate_503(&unavailable_503()));
        assert!(is_immediate_503(&warming_503()));
    }

    #[test]
    fn member_gets_authoritative_workspace_scope() {
        // Member of the resolved workspace -> authoritative scope is emitted and
        // NOT in the strip list (it was authored).
        let resp = enrich_response(
            "u1",
            Some(member_profile("ws_1", MemberType::Staff, "admin")),
            true,
            Some("ws_1"),
        );
        let h = set_headers(&resp);
        assert_eq!(h.get("x-workspace-id").map(String::as_str), Some("ws_1"));
        assert_eq!(h.get("x-user-type").map(String::as_str), Some("staff"));
        assert_eq!(h.get("x-user-role").map(String::as_str), Some("admin"));
        let r = remove_headers(&resp);
        for hh in ["x-workspace-id", "x-user-type", "x-user-role"] {
            assert!(!r.contains(&hh.to_owned()), "authored {hh} must not be stripped");
        }
    }

    #[test]
    fn member_type_and_role_are_workspace_scoped() {
        // Customer of ws_2 resolves to the customer type + the ws-scoped role.
        let resp = enrich_response(
            "u1",
            Some(member_profile("ws_2", MemberType::Customer, "buyer")),
            true,
            Some("ws_2"),
        );
        let h = set_headers(&resp);
        assert_eq!(h.get("x-user-type").map(String::as_str), Some("customer"));
        assert_eq!(h.get("x-user-role").map(String::as_str), Some("buyer"));
    }

    #[test]
    fn non_member_of_acting_workspace_is_fail_closed() {
        // Member of ws_1, but the request resolves to a DIFFERENT workspace -> no
        // authoritative scope, and any forged copy is stripped (fail-closed).
        let resp = enrich_response(
            "u1",
            Some(member_profile("ws_1", MemberType::Staff, "admin")),
            true,
            Some("ws_other"),
        );
        assert!(!set_headers(&resp).contains_key("x-workspace-id"));
        let r = remove_headers(&resp);
        for hh in ["x-workspace-id", "x-user-type", "x-user-role"] {
            assert!(r.contains(&hh.to_owned()), "non-member must strip {hh}");
        }
    }

    #[test]
    fn service_authors_service_type_and_no_workspace_role() {
        // Task 4.4: a resolved service authors x-user-type=service + the acting
        // workspace, and has NO workspace role (x-user-role stripped). With no profile
        // it asserts no suspension/entitlements either (stripped).
        let acting = service_acting("ws-acting", &["events:write"]);
        let resp = super::enrich_response(
            &service_enriched("system:serviceaccount:nexus:events-writer", Some(acting)),
            None,
            &SignContext { signer: None, cache: None, route_pool: None, now: 0 },
        );
        let h = set_headers(&resp);
        assert_eq!(
            h.get("x-user-id").map(String::as_str),
            Some("system:serviceaccount:nexus:events-writer"),
        );
        assert_eq!(h.get("x-workspace-id").map(String::as_str), Some("ws-acting"));
        assert_eq!(h.get("x-user-type").map(String::as_str), Some("service"));
        assert_eq!(h.get("x-auth-anonymous").map(String::as_str), Some("false"));
        assert!(!h.contains_key("x-user-role"), "a service has no workspace role");
        let r = remove_headers(&resp);
        for hh in ["x-user-role", "x-user-suspended", "x-user-entitlements"] {
            assert!(r.contains(&hh.to_owned()), "service path must strip {hh}");
        }
    }

    #[test]
    fn resolved_service_mints_a_contract_unresolved_fails_closed() {
        // Task 4.3: the mint guard is generalized to "has a resolved authority" — a
        // Platform authority mints despite no membership. An unresolved service
        // (absent from the registry, or no acting workspace) mints nothing and strips
        // the acting scope, exactly like a non-member user (fail closed).
        let signer = test_signer();
        let ctx = || SignContext { signer: Some(&signer), cache: None, route_pool: Some("evenout"), now: 1_000_000 };

        let acting = service_acting("ws-acting", &["events:write"]);
        let resolved = super::enrich_response(&service_enriched("svc-1", Some(acting)), None, &ctx());
        let token = set_headers(&resolved)
            .get("x-identity-contract")
            .cloned()
            .expect("a resolved service must carry a signed contract");
        assert_eq!(token.split('.').count(), 3, "must be a compact JWS");
        assert!(!remove_headers(&resolved).contains(&"x-identity-contract".to_owned()));

        // Unresolved: no acting authority -> no contract, acting scope stripped.
        let unresolved = super::enrich_response(&service_enriched("svc-unknown", None), None, &ctx());
        assert!(!set_headers(&unresolved).contains_key("x-identity-contract"));
        let r = remove_headers(&unresolved);
        for hh in ["x-identity-contract", "x-workspace-id", "x-user-type", "x-user-role"] {
            assert!(r.contains(&hh.to_owned()), "unresolved service must strip {hh}");
        }
    }

    #[test]
    fn enrich_authors_plan_as_header_and_signed_claim() {
        // Tasks 4.2 / 4.4: a resolved plan is authored as `x-workspace-plan` AND carried in
        // the signed contract's `plan` claim — a box can trust it cryptographically. The
        // header and the claim are the SAME nexus-resolved value.
        let signer = test_signer();
        let acting = Acting::Workspace(ResolvedMembership {
            workspace_id: "ws-1".to_owned(),
            member_type: MemberType::Staff,
            role: "admin".to_owned(),
        });
        let resp = super::enrich_response(
            &Enriched {
                sub: "u1",
                kind: Some(PrincipalKind::User.as_str()),
                on_behalf_of: None,
                profile: None,
                authenticated: true,
                acting: Some(acting),
            },
            Some("pro"),
            // Real-clock `now` so the minted token verifies (decode_contract validates exp).
            &SignContext { signer: Some(&signer), cache: None, route_pool: Some("evenout"), now: now_secs() },
        );
        let h = set_headers(&resp);
        assert_eq!(h.get("x-workspace-plan").map(String::as_str), Some("pro"));
        let token = h.get("x-identity-contract").expect("a resolved request carries a contract");
        assert_eq!(decode_contract(token).plan.as_deref(), Some("pro"), "the claim matches the header");
        // The authored plan header must never also be stripped.
        assert!(
            !remove_headers(&resp).contains(&"x-workspace-plan".to_owned()),
            "an authored plan must not be stripped",
        );
    }

    #[test]
    fn unresolved_plan_omits_header_and_claim_and_strips_client_copy() {
        // Task 4.3 (fail-soft) + 4.2 (nexus-authored): with no plan resolved, `x-workspace-plan`
        // is omitted (NOT defaulted) and any client-supplied copy is STRIPPED — even though an
        // authority resolved and a contract is minted. The `plan` claim is likewise omitted, not
        // defaulted (no 503, unlike missing membership).
        let signer = test_signer();
        let acting = Acting::Workspace(ResolvedMembership {
            workspace_id: "ws-1".to_owned(),
            member_type: MemberType::Staff,
            role: "admin".to_owned(),
        });
        let resp = super::enrich_response(
            &Enriched {
                sub: "u1",
                kind: Some(PrincipalKind::User.as_str()),
                on_behalf_of: None,
                profile: None,
                authenticated: true,
                acting: Some(acting),
            },
            None,
            &SignContext { signer: Some(&signer), cache: None, route_pool: Some("evenout"), now: now_secs() },
        );
        assert!(!set_headers(&resp).contains_key("x-workspace-plan"), "unresolved plan is omitted");
        assert!(
            remove_headers(&resp).contains(&"x-workspace-plan".to_owned()),
            "a client-supplied plan is stripped when nexus resolves none",
        );
        let token = set_headers(&resp)
            .get("x-identity-contract")
            .cloned()
            .expect("the request still resolves an authority -> a contract is minted");
        assert!(decode_contract(&token).plan.is_none(), "the claim is omitted, not defaulted");
    }

    #[test]
    fn resolved_api_key_authors_on_behalf_of_and_mints_an_apikey_contract() {
        // Tasks 4.2 / 5.1: a resolved api-key authors x-user-id=key-id, the intersected
        // membership's type+role, and x-user-on-behalf-of=creator, and mints a signed
        // contract (principal_kind=apikey carried inside; asserted in signer.rs). The key
        // acts on the workspace its scope ∩ the creator's membership admitted.
        let signer = test_signer();
        let acting = Acting::Workspace(ResolvedMembership {
            workspace_id: "ws-1".to_owned(),
            member_type: MemberType::Staff,
            role: "admin".to_owned(),
        });
        let resp = super::enrich_response(
            &api_key_enriched("pak_key7", "u-creator", Some(acting)),
            None,
            &signed_ctx(&signer),
        );
        let h = set_headers(&resp);
        assert_eq!(h.get("x-user-id").map(String::as_str), Some("pak_key7"));
        assert_eq!(h.get("x-user-on-behalf-of").map(String::as_str), Some("u-creator"));
        assert_eq!(h.get("x-workspace-id").map(String::as_str), Some("ws-1"));
        assert_eq!(h.get("x-user-type").map(String::as_str), Some("staff"));
        assert_eq!(h.get("x-user-role").map(String::as_str), Some("admin"));
        let token = h.get("x-identity-contract").expect("a resolved api key must carry a contract");
        assert_eq!(token.split('.').count(), 3, "must be a compact JWS");
        // The authored on-behalf-of + acting scope must never also be stripped.
        let r = remove_headers(&resp);
        for hh in ["x-user-on-behalf-of", "x-workspace-id", "x-identity-contract"] {
            assert!(!r.contains(&hh.to_owned()), "authored {hh} must not be stripped");
        }
        // The raw credential is ALWAYS stripped before the backend.
        assert!(r.contains(&"x-api-key".to_owned()), "the raw x-api-key must be stripped");
    }

    #[test]
    fn unresolved_api_key_strips_acting_scope_and_mints_nothing() {
        // Task 4.3: a presented key that resolved to a candidate but whose scope ∩ the
        // creator's membership is EMPTY (out-of-scope workspace, or the creator lost the
        // membership) authors NO acting scope, mints NO contract, and strips
        // on-behalf-of + the acting family + the raw credential (fail closed).
        let signer = test_signer();
        let resp = super::enrich_response(
            &api_key_enriched("pak_key7", "u-creator", None),
            None,
            &signed_ctx(&signer),
        );
        assert!(!set_headers(&resp).contains_key("x-identity-contract"), "no authority -> no contract");
        assert!(!set_headers(&resp).contains_key("x-user-on-behalf-of"), "no acting -> no on-behalf-of");
        let r = remove_headers(&resp);
        for hh in [
            "x-identity-contract",
            "x-user-on-behalf-of",
            "x-workspace-id",
            "x-user-type",
            "x-user-role",
            "x-api-key",
        ] {
            assert!(r.contains(&hh.to_owned()), "unresolved api key must strip {hh}");
        }
    }

    #[test]
    fn api_key_credential_is_stripped_on_every_path() {
        // Defense-in-depth: x-api-key is a client credential and must never reach the
        // backend, on ANY path — including the plain human/anonymous paths.
        assert!(remove_headers(&enrich_response("u1", None, true, None)).contains(&"x-api-key".to_owned()));
        assert!(remove_headers(&enrich_response("anonymous", None, false, None)).contains(&"x-api-key".to_owned()));
    }

    #[test]
    fn signed_contract_is_minted_only_for_a_resolved_member() {
        // identity-contract-signing: the signed x-identity-contract is minted ONLY
        // when authenticated AND a member of the acting workspace (there is an
        // authoritative scope to sign). Member path -> a compact JWS is stamped and
        // NOT stripped.
        let signer = test_signer();
        let member = enrich_signed(
            "u1",
            Some(member_profile("ws_1", MemberType::Staff, "admin")),
            true,
            Some("ws_1"),
            &signed_ctx(&signer),
        );
        let h = set_headers(&member);
        let token = h
            .get("x-identity-contract")
            .expect("member path must carry a signed contract");
        assert_eq!(
            token.split('.').count(),
            3,
            "must be a compact JWS (header.payload.signature)",
        );
        assert!(
            !remove_headers(&member).contains(&"x-identity-contract".to_owned()),
            "an authored token must never be stripped",
        );

        // Non-member, anonymous, and profile-miss have no resolved identity to sign:
        // NO token is stamped and the header is STRIPPED so a client copy cannot
        // survive — a verifying box then fails closed on an enriched route.
        let non_member = enrich_signed(
            "u1",
            Some(member_profile("ws_1", MemberType::Staff, "admin")),
            true,
            Some("ws_other"),
            &signed_ctx(&signer),
        );
        let anon = enrich_signed("anonymous", None, false, None, &signed_ctx(&signer));
        let miss = enrich_signed("u1", None, true, None, &signed_ctx(&signer));
        for (label, resp) in [("non_member", &non_member), ("anonymous", &anon), ("miss", &miss)] {
            assert!(
                !set_headers(resp).contains_key("x-identity-contract"),
                "{label} path must not stamp a contract",
            );
            assert!(
                remove_headers(resp).contains(&"x-identity-contract".to_owned()),
                "{label} path must strip any client-supplied contract",
            );
        }
    }

    #[test]
    fn no_contract_and_stripped_without_a_signer() {
        // identity-contract-signing: there is NO plain-string contract. With no signer
        // configured, x-identity-contract is authored by no one on every path and any
        // client copy is stripped, so a verifying box fails closed.
        let cases = [
            (
                "member",
                enrich_response(
                    "u1",
                    Some(member_profile("ws_1", MemberType::Staff, "admin")),
                    true,
                    Some("ws_1"),
                ),
            ),
            ("anonymous", enrich_response("anonymous", None, false, None)),
        ];
        for (label, resp) in &cases {
            assert!(
                !set_headers(resp).contains_key("x-identity-contract"),
                "{label}: no contract is authored without a signer",
            );
            assert!(
                remove_headers(resp).contains(&"x-identity-contract".to_owned()),
                "{label}: any client-supplied contract is stripped without a signer",
            );
        }
    }

    #[tokio::test]
    async fn e2e_minted_token_verifies_against_the_served_jwks() {
        // End-to-end within the process: load the key from a FILE (as in prod via a
        // mounted secret), mint a token, publish it through the REAL JWKS HTTP handler,
        // fetch the document over HTTP, and verify the token against the fetched keys —
        // the full sign→publish→verify chain a box performs, minus the Envoy hop.
        use std::env;
        use std::fs;
        use std::process;
        use std::sync::Arc;
        use axum::body::{to_bytes, Body};
        use axum::http::Request as HttpRequest;
        use jsonwebtoken::jwk::JwkSet;
        use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

        // Load the signing key from a real file (exercises Signer::from_pem_file).
        let mut key_path = env::temp_dir();
        key_path.push(format!("nexus-e2e-signer-{}.pem", process::id()));
        fs::write(&key_path, TEST_PEM).expect("write temp key");
        let signer = signer::Signer::from_pem_file(
            key_path.to_str().expect("utf8 path"),
            "test-key-1".to_owned(),
            "https://identity.nexus".to_owned(),
            "v1".to_owned(),
            60,
        )
        .expect("load key from file");

        // Mint a token for a member routed to the `evenout` box.
        let token = signer
            .mint(&signer::MintInput {
                sub: "user-e2e",
                aud: "evenout",
                principal_kind: "user",
                on_behalf_of: None,
                workspace_id: "ws-e2e",
                member_type: Some("staff"),
                role: Some("admin"),
                roles: &["ops".to_owned()],
                permissions: &[],
                plan: Some("pro"),
                entitlements: Some(&["beta".to_owned()]),
                suspended: Some(false),
                now: now_secs(),
            })
            .expect("mint");

        // Publish the JWKS through the real handler and fetch the document over HTTP.
        let (_jwks_tx, jwks_rx) = watch::channel(Arc::new(TEST_JWKS.to_owned()));
        let app = jwks::router(jwks_rx);
        let resp = app
            .oneshot(HttpRequest::builder().uri(jwks::JWKS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let jwks: JwkSet = serde_json::from_slice(body.as_ref()).expect("parse served JWKS");

        // Verify the minted token against the FETCHED keys (what a box actually does).
        let kid = decode_header(&token).unwrap().kid.expect("kid in header");
        let jwk = jwks.find(&kid).expect("served JWKS must contain the signing kid");
        let key = DecodingKey::from_jwk(jwk).expect("decoding key from jwk");
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&["evenout"]);
        validation.set_issuer(&["https://identity.nexus"]);
        let claims = decode::<identity_core::ContractClaims>(&token, &key, &validation)
            .expect("token must verify against the served JWKS")
            .claims;
        assert_eq!(claims.sub, "user-e2e");
        assert_eq!(claims.workspace_id, "ws-e2e");
        assert_eq!(claims.aud, "evenout");
        assert_eq!(claims.ctr, "v1");
        // workspace-plan-tier task 4.4: a box reads the trusted plan from the signed
        // contract served/verified end-to-end (not an unsigned header).
        assert_eq!(claims.plan.as_deref(), Some("pro"));

        let _ = fs::remove_file(&key_path);
    }

    #[test]
    fn forbidden_403_is_an_immediate_403() {
        matches!(
            &forbidden_403().response,
            Some(processing_response::Response::ImmediateResponse(r))
                if r.status.as_ref().map(|s| s.code) == Some(403)
        )
        .then_some(())
        .expect("expected an immediate 403");
    }

    /// The existence-hiding 404 helper: an immediate 404 with a fixed minimal body
    /// and NO header mutation — a uniform envelope that leaks nothing through
    /// status, body, or headers. Because it is a single helper, the non-member and
    /// the nonexistent-workspace responses are byte-identical by construction.
    #[test]
    fn not_found_404_is_a_uniform_immediate_404() {
        let Some(processing_response::Response::ImmediateResponse(r)) = &not_found_404().response
        else {
            panic!("expected an immediate response");
        };
        assert_eq!(r.status.as_ref().map(|s| s.code), Some(404));
        assert_eq!(r.body, b"not found");
        // No header mutation on the envelope (nothing to distinguish existence).
        assert!(r.headers.is_none(), "the 404 envelope must set no headers");
        // Two emissions are byte-identical (non-member ≡ nonexistent workspace).
        assert_eq!(not_found_404(), not_found_404());
    }

    /// The 404 (hidden non-member) and the 403 (honest under-privileged member) are
    /// distinct outcomes: a member is never hidden, and a non-member is never told
    /// "forbidden". The two envelopes therefore differ by design.
    #[test]
    fn hidden_404_and_honest_403_are_distinct() {
        assert_ne!(not_found_404(), forbidden_403());
    }

    /// The gate decision truth table (maps to the spec scenarios). A non-member on a
    /// private, workspace-scoped route is hidden (404); everyone else is not.
    #[test]
    fn existence_hiding_gate_truth_table() {
        // (auth_required, account_scoped, has_workspace, acting_resolved) -> hidden?
        // 5.1/5.2/5.4 non-member on a private workspace route (no acting) -> 404.
        assert!(hide_nonmember_as_404(true, false, true, false));
        // 5.3 member (acting resolved) -> not hidden; falls through to the 403 path.
        assert!(!hide_nonmember_as_404(true, false, true, true));
        // 5.5 public route (auth not required) -> never gated, even for a non-member.
        assert!(!hide_nonmember_as_404(false, false, true, false));
        // 5.6 account-scoped route (e.g. /me) -> never gated on membership.
        assert!(!hide_nonmember_as_404(true, true, true, false));
        // 5.7 fail-closed: account_scoped absent reads false -> a non-member is gated.
        //     (absence is decoded to `false` by `trusted_flag`, exercised below.)
        assert!(hide_nonmember_as_404(true, false, true, false));
        // No resolved workspace -> nothing to hide; not gated.
        assert!(!hide_nonmember_as_404(true, false, false, false));
    }

}
