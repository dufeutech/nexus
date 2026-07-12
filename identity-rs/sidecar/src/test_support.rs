//! Shared test toolkit (`#[cfg(test)]`): response inspectors, request/profile/state
//! builders, the embedded signing key + JWKS, and the enrich wrappers that keep the
//! pre-normalized-principal call shapes terse. `pub(crate)` so every module's test
//! block shares one copy.
#![allow(clippy::panic, reason = "test helpers legitimately panic on the impossible branch")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::Instant;

use moka::future::Cache;
use tokio::sync::watch;

use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
use envoy_types::pb::envoy::service::ext_proc::v3::{
    processing_request, processing_response, HttpHeaders, ProcessingRequest, ProcessingResponse,
};

use identity_core::store::{BoxError, ChangeFeed, ProfileStore, WatchToken};
use identity_core::{
    MemberType, Membership, PlatformScope, PolicyDecisionPoint, PrincipalKind, Profile,
};
use policy_cedar::CedarPdp;

use crate::enrich::{self, Acting, Enriched, SignContext};
use crate::extract::RouteRequirements;
use crate::signer;
use crate::state::{parse_aal_levels, AppState, DEFAULT_AAL_LEVELS};

/// Embedded test signing key (matches `testdata/test-jwks.json`), for the
/// signed-contract tests.
pub(crate) const TEST_PEM: &str = include_str!("testdata/test-ec-p256.pem");
/// The public JWKS matching `TEST_PEM`, for the end-to-end verify test.
pub(crate) const TEST_JWKS: &str = include_str!("testdata/test-jwks.json");

/// The real Cedar PDP over the embedded parity policy — the production engine, so a
/// gated route in any test decides exactly as it will in production (adopt-cedar-
/// policy-gate).
pub(crate) fn test_pdp() -> Arc<dyn PolicyDecisionPoint> {
    Arc::new(CedarPdp::with_default_policies().expect("default parity policies load"))
}

/// A signer over the embedded test key (identity-contract-signing tests).
pub(crate) fn test_signer() -> signer::Signer {
    signer::Signer::from_pem(
        TEST_PEM.as_bytes(),
        "test-key-1".to_owned(),
        "https://identity.nexus".to_owned(),
        "v1".to_owned(),
        60,
    )
    .expect("valid test key")
}

/// Test wrapper preserving the pre-normalized-principal user call shape: given a
/// profile + acting workspace, it resolves the WORKSPACE authority exactly as the
/// enrich path does, with no signer/route-pool (no token minted →
/// `x-identity-contract` stripped). Shadows the wider `crate::enrich::enrich_response` for
/// the many user-path tests that do not exercise signing or the service kind.
pub(crate) fn enrich_response(
    sub: &str,
    profile: Option<Arc<Profile>>,
    authenticated: bool,
    acting_workspace: Option<&str>,
) -> ProcessingResponse {
    let acting = acting_workspace
        .zip(profile.as_ref())
        .and_then(|(w, p)| p.resolve_membership(w))
        .map(Acting::Workspace);
    enrich::enrich_response(
        &Enriched {
            sub,
            kind: authenticated.then_some(PrincipalKind::User.as_str()),
            on_behalf_of: None,
            profile,
            authenticated,
            acting,
        },
        None,
        &SignContext { signer: None, cache: None, route_pool: None, now: 0 },
    )
}

/// The signing counterpart of the user-path wrapper: resolves the workspace
/// authority from `profile` + `acting_workspace` and mints through `sign_ctx`.
pub(crate) fn enrich_signed(
    sub: &str,
    profile: Option<Arc<Profile>>,
    authenticated: bool,
    acting_workspace: Option<&str>,
    sign_ctx: &SignContext<'_>,
) -> ProcessingResponse {
    let acting = acting_workspace
        .zip(profile.as_ref())
        .and_then(|(w, p)| p.resolve_membership(w))
        .map(Acting::Workspace);
    enrich::enrich_response(
        &Enriched {
            sub,
            kind: authenticated.then_some(PrincipalKind::User.as_str()),
            on_behalf_of: None,
            profile,
            authenticated,
            acting,
        },
        None,
        sign_ctx,
    )
}

/// Build an `Enriched` for a resolved SERVICE principal (Platform authority),
/// keeping the service-path tests terse.
pub(crate) fn service_enriched(sub: &str, acting: Option<Acting>) -> Enriched<'_> {
    Enriched {
        sub,
        kind: Some(PrincipalKind::Service.as_str()),
        on_behalf_of: None,
        profile: None,
        authenticated: true,
        acting,
    }
}

/// Build a service `Acting::Platform` for the service-path tests.
pub(crate) fn service_acting(workspace: &str, permissions: &[&str]) -> Acting {
    Acting::Platform {
        workspace_id: workspace.to_owned(),
        permissions: permissions.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// Build an `Enriched` for a resolved API-KEY principal (customer-api-keys): the key
/// id is the subject, the creating user is `on_behalf_of`, and the acting authority is
/// the intersected membership. `acting: None` models an unresolved key (revoked/
/// expired/out-of-scope) — the fail-closed path.
pub(crate) fn api_key_enriched<'a>(key_id: &'a str, creator: &'a str, acting: Option<Acting>) -> Enriched<'a> {
    Enriched {
        sub: key_id,
        kind: Some(PrincipalKind::ApiKey.as_str()),
        on_behalf_of: Some(creator),
        // Least-privilege: an api key carries none of the creator's coarse global roles.
        profile: None,
        authenticated: true,
        acting,
    }
}

/// Build a `SignContext` wired to the embedded test signer, aud `evenout`.
pub(crate) fn signed_ctx(signer: &signer::Signer) -> SignContext<'_> {
    SignContext { signer: Some(signer), cache: None, route_pool: Some("evenout"), now: 1_000_000 }
}

/// A Profile holding one workspace membership, for the resolution matrix.
pub(crate) fn member_profile(ws: &str, ty: MemberType, role: &str) -> Arc<Profile> {
    Arc::new(Profile {
        sub: "u1".into(),
        memberships: vec![Membership {
            workspace_id: ws.into(),
            member_type: ty,
            role: role.into(),
            entitlements: vec![],
        }],
        ..Default::default()
    })
}

/// Collect the response's set headers into a map for assertions.
pub(crate) fn set_headers(resp: &ProcessingResponse) -> HashMap<String, String> {
    let Some(processing_response::Response::RequestHeaders(h)) = &resp.response else {
        panic!("expected RequestHeaders response");
    };
    h.response
        .as_ref()
        .and_then(|c| c.header_mutation.as_ref())
        .map(|m| {
            m.set_headers
                .iter()
                .filter_map(|opt| opt.header.as_ref())
                .map(|hv| {
                    (hv.key.clone(), String::from_utf8_lossy(&hv.raw_value).into_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Collect the response's removed header names.
pub(crate) fn remove_headers(resp: &ProcessingResponse) -> Vec<String> {
    let Some(processing_response::Response::RequestHeaders(h)) = &resp.response else {
        panic!("expected RequestHeaders response");
    };
    h.response
        .as_ref()
        .and_then(|c| c.header_mutation.as_ref())
        .map(|m| m.remove_headers.clone())
        .unwrap_or_default()
}

pub(crate) fn is_immediate_503(resp: &ProcessingResponse) -> bool {
    matches!(
        &resp.response,
        Some(processing_response::Response::ImmediateResponse(r))
            if r.status.as_ref().map(|s| s.code) == Some(503)
    )
}

/// Build a RequestHeaders ext_proc message carrying the given headers.
pub(crate) fn req_with_headers(pairs: &[(&str, &str)]) -> ProcessingRequest {
    ProcessingRequest {
        request: Some(processing_request::Request::RequestHeaders(HttpHeaders {
            headers: Some(HeaderMap {
                headers: pairs
                    .iter()
                    .map(|(k, v)| HeaderValue {
                        key: (*k).to_owned(),
                        raw_value: v.as_bytes().to_vec(),
                        ..Default::default()
                    })
                    .collect(),
            }),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// A profile store stub for the few tests that must build a real `AppState`
/// (the enrich unit tests call `enrich_response` directly and need none).
pub(crate) struct EmptyStore;
#[tonic::async_trait]
impl ProfileStore for EmptyStore {
    async fn get(&self, _sub: &str) -> Result<Option<Profile>, BoxError> { Ok(None) }
    async fn put(&self, _p: &Profile) -> Result<(), BoxError> { Ok(()) }
    async fn delete(&self, _sub: &str) -> Result<(), BoxError> { Ok(()) }
    async fn scan_all(&self) -> Result<Vec<Profile>, BoxError> { Ok(vec![]) }
    async fn watch(
        &self,
        _after: Option<WatchToken>,
    ) -> Result<ChangeFeed, BoxError> {
        use futures::stream::pending;
        Ok(Box::pin(pending()))
    }
}

/// Build an `AppState` wired to an empty store, optionally carrying a resident
/// platform registry — for the registry-lookup tests.
pub(crate) fn state_with_platform(
    platform: Option<watch::Receiver<Arc<HashMap<String, PlatformScope>>>>,
) -> AppState {
    AppState {
        cache: Cache::new(16),
        store: Arc::new(EmptyStore),
        ready: Arc::new(AtomicBool::new(true)),
        last_apply_ms: Arc::new(AtomicU64::new(0)),
        warm_ms: Arc::new(AtomicU64::new(0)),
        start: Instant::now(),
        fail_open: false,
        aal_levels: Arc::new(parse_aal_levels(DEFAULT_AAL_LEVELS)),
        pdp: test_pdp(),
        signer: None,
        contract_cache: None,
        platform,
        plans: None,
        api_keys: None,
    }
}

/// Build an `AppState` carrying a resident workspace→plan snapshot, for the
/// plan-resolution tests. Mirrors [`state_with_platform`].
pub(crate) fn state_with_plans(plans: Option<watch::Receiver<Arc<HashMap<String, String>>>>) -> AppState {
    AppState {
        cache: Cache::new(16),
        store: Arc::new(EmptyStore),
        ready: Arc::new(AtomicBool::new(true)),
        last_apply_ms: Arc::new(AtomicU64::new(0)),
        warm_ms: Arc::new(AtomicU64::new(0)),
        start: Instant::now(),
        fail_open: false,
        aal_levels: Arc::new(parse_aal_levels(DEFAULT_AAL_LEVELS)),
        pdp: test_pdp(),
        signer: None,
        contract_cache: None,
        platform: None,
        plans,
        api_keys: None,
    }
}

/// Decode a minted contract against the embedded test JWKS, returning its claims —
/// the box's-eye view of the signed token (task 4.4).
pub(crate) fn decode_contract(token: &str) -> identity_core::ContractClaims {
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    let jwks: JwkSet = serde_json::from_str(TEST_JWKS).unwrap();
    let kid = decode_header(token).unwrap().kid.unwrap();
    let key = DecodingKey::from_jwk(jwks.find(&kid).unwrap()).unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["evenout"]);
    validation.set_issuer(&["https://identity.nexus"]);
    decode::<identity_core::ContractClaims>(token, &key, &validation).unwrap().claims
}

/// A profile carrying coarse roles + entitlements for the gate matrix.
pub(crate) fn gated_profile(roles: &[&str], entitlements: &[&str]) -> Arc<Profile> {
    Arc::new(Profile {
        sub: "u1".into(),
        roles: roles.iter().map(|s| (*s).to_owned()).collect(),
        entitlements: entitlements.iter().map(|s| (*s).to_owned()).collect(),
        ..Default::default()
    })
}

pub(crate) fn levels() -> HashMap<String, u8> {
    parse_aal_levels(DEFAULT_AAL_LEVELS)
}

pub(crate) fn reqs(role: Option<&str>, ent: Option<&str>, aal: Option<&str>) -> RouteRequirements {
    RouteRequirements {
        role: role.map(str::to_owned),
        entitlement: ent.map(str::to_owned),
        min_aal: aal.map(str::to_owned),
    }
}
