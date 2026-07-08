//! The signed identity-contract port (`identity-contract-signing` capability).
//!
//! WHAT, not HOW: this module defines the *claims* a signed `x-identity-contract`
//! token conveys and the [`ContractSigner`] port that mints one. The concrete
//! signing mechanism (algorithm, key material, JWS encoding) lives entirely behind
//! this port in the sidecar's `signer` adapter — no crypto-library type appears
//! here, so a signer swap never touches core.
//!
//! Invariant (design.md): a token is minted ONLY for an authenticated request that
//! resolved to an AUTHORITY — either an acting-workspace membership (user/api-key) or a
//! platform permission set (service). The claims therefore always carry the
//! authoritative acting `workspace_id` and the `principal_kind`; a user/api-key
//! principal additionally carries `member_type` + `role`, while a service carries its
//! platform `permissions` and OMITS `member_type`/`role` (a service has no membership).
//! An unresolved request has no claims to sign and carries no token (normalized-principal).

use std::fmt;

use serde::{Deserialize, Serialize};

/// The claims conveyed by a signed `x-identity-contract` token. Field names are the
/// on-the-wire claim keys (JWT registered claims `iss`/`aud`/`sub`/`iat`/`exp`/`jti`
/// plus the nexus identity claims). Built from the SAME resolved values the
/// `x-user-*`/`x-workspace-*` headers are authored from (single source of truth —
/// the header set and the token cannot drift).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContractClaims {
    /// Issuer — identifies nexus as the origin. The verifier pins this exact value.
    pub iss: String,
    /// Audience — the destination box (derived from `x-route-pool`); scopes replay
    /// so a token minted for one box cannot be presented to another.
    pub aud: String,
    /// Verified subject (`sub`) — the authenticated user id.
    pub sub: String,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: u64,
    /// Expiry, seconds since the Unix epoch. Short (per-request mint) so a captured
    /// token is unusable beyond its window.
    pub exp: u64,
    /// Token id — unique per mint; aids audit correlation (replay is primarily
    /// defeated by `aud` + short `exp`).
    pub jti: String,
    /// Contract version (the value the plain `x-identity-contract` header used to
    /// carry). The single coordination gate for the `x-workspace-*`/`x-user-*`
    /// header family's shape.
    pub ctr: String,
    /// The authoritative acting workspace. For a user/api-key a live membership of it
    /// was resolved; for a service it is the workspace the service acts on this request
    /// (from the trusted `x-workspace-id`), authorized by its platform permissions.
    pub workspace_id: String,
    /// The principal kind this assertion conveys (`user`/`apikey`/`service`) —
    /// nexus-authored, never caller-asserted (normalized-principal). A box authorizes
    /// on it (e.g. admit a service as a writer while gating a human by role).
    pub principal_kind: String,
    /// The subject this principal acts **on behalf of** — the creating user for an
    /// `apikey` principal, so a box (and audit) can attribute the action to the human
    /// behind the automation (`customer-api-keys`). ABSENT for a `user`/`service`
    /// principal (they act only as themselves) — omitted from the token while `None`, so
    /// adding it is a value change, not a contract bump. nexus-authored, never
    /// key-asserted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub on_behalf_of: Option<String>,
    /// The acting relationship type in that workspace (e.g. `staff`/`customer`).
    /// ABSENT for a service principal (a `Platform` authority has no member type) —
    /// omitted from the token while `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub member_type: Option<String>,
    /// The acting, workspace-scoped role. ABSENT for a service principal (no role) —
    /// omitted while `None`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub role: Option<String>,
    /// Coarse nexus-authored global roles (mirrors `x-user-roles`). Empty for a service.
    pub roles: Vec<String>,
    /// The service's platform permission set (a `Platform` authority only) — the
    /// least-privilege named permissions a box maps its write door onto. Empty/omitted
    /// for a user/api-key principal.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub permissions: Vec<String>,
    /// RESERVED — the workspace plan tier. Populated by a later change (no plan-tier
    /// model exists yet); omitted from the token while `None` so adding it later is a
    /// value change, not a contract bump.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub plan: Option<String>,
}

/// A signing failure. Deliberately opaque (carries a message for logs, not a typed
/// cause) so no key material or crypto internals leak to callers; the sidecar treats
/// any signing error as fail-closed (emit no token → the box rejects the request).
#[derive(Debug)]
pub struct SignError(String);

impl SignError {
    /// Wrap a human-readable reason.
    #[must_use]
    pub const fn new(message: String) -> Self {
        Self(message)
    }
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The port the identity plane mints a signed contract through. Implemented by the
/// sidecar's ES256 adapter; `identity_core` knows only "sign these claims".
pub trait ContractSigner: Send + Sync {
    /// Mint a signed compact token for `claims`, or fail closed.
    ///
    /// # Errors
    /// Returns [`SignError`] if the claims cannot be encoded or signed.
    fn sign(&self, claims: &ContractClaims) -> Result<String, SignError>;
}
