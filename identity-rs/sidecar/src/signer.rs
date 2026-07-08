//! ES256 signer adapter (`identity-contract-signing`) — the ONLY place the sidecar
//! touches `jsonwebtoken`. It implements the `identity_core::ContractSigner` port and
//! assembles the [`ContractClaims`] policy (issuer, contract version, short expiry,
//! per-mint `jti`) around it, so `main.rs` only calls [`Signer::mint`] with the
//! already-resolved identity.
//!
//! Key custody (design.md): the private key is a runtime-injected secret loaded once
//! at startup into a warm [`EncodingKey`]; it never leaves this process. The matching
//! public key is published separately as an operator-supplied JWKS document (served by
//! `jwks.rs`) — this module never derives or exposes it.

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

use identity_core::{ContractClaims, ContractSigner, SignError};

/// The everything-needed-to-mint bundle, so [`Signer::mint`] stays a single call from
/// the hot path (avoids a wide positional argument list).
pub(crate) struct MintInput<'a> {
    /// Verified subject (a user `sub` or a service id).
    pub sub: &'a str,
    /// Destination box audience (from `x-route-pool`).
    pub aud: &'a str,
    /// The principal kind (`user`/`apikey`/`service`) — nexus-authored (normalized-principal).
    pub principal_kind: &'a str,
    /// The subject an `apikey` principal acts on behalf of (the creating user); `None`
    /// for a `user`/`service` (`customer-api-keys`). Authored into the `on_behalf_of`
    /// claim, omitted while `None`.
    pub on_behalf_of: Option<&'a str>,
    /// Authoritative acting workspace (membership workspace for a user/api-key; the
    /// acting `x-workspace-id` for a service).
    pub workspace_id: &'a str,
    /// Acting relationship type (`staff`/`customer`/…). `None` for a service (a
    /// `Platform` authority has no member type).
    pub member_type: Option<&'a str>,
    /// Acting, workspace-scoped role. `None` for a service.
    pub role: Option<&'a str>,
    /// Coarse nexus-authored global roles. Empty for a service.
    pub roles: &'a [String],
    /// The service's platform permission set (least-privilege). Empty for a
    /// user/api-key.
    pub permissions: &'a [String],
    /// Current time, seconds since the Unix epoch (injected for testability).
    pub now: u64,
}

/// A warm ES256 signing context: the parsed key + the fixed header (algorithm +
/// `kid`) + the config-driven claim policy (issuer, contract version, token TTL).
pub(crate) struct Signer {
    key: EncodingKey,
    header: Header,
    issuer: String,
    contract_version: String,
    ttl_secs: u64,
    /// Per-process monotonic counter giving each mint a unique `jti` (combined with
    /// `iat`). `jti` is for audit correlation; replay is defeated by `aud` + `exp`.
    counter: AtomicU64,
}

impl Signer {
    /// Load the PEM private key once and build the warm signing context.
    ///
    /// # Errors
    /// Returns [`SignError`] if the key file cannot be read or is not a valid EC
    /// (P-256) PKCS#8 private key.
    pub(crate) fn from_pem_file(
        key_path: &str,
        kid: String,
        issuer: String,
        contract_version: String,
        ttl_secs: u64,
    ) -> Result<Self, SignError> {
        let pem = fs::read(key_path)
            .map_err(|e| SignError::new(format!("read signing key {key_path}: {e}")))?;
        Self::from_pem(&pem, kid, issuer, contract_version, ttl_secs)
    }

    /// Build the warm signing context from PEM bytes already in memory.
    ///
    /// # Errors
    /// Returns [`SignError`] if the bytes are not a valid EC (P-256) PKCS#8 key.
    pub(crate) fn from_pem(
        pem: &[u8],
        kid: String,
        issuer: String,
        contract_version: String,
        ttl_secs: u64,
    ) -> Result<Self, SignError> {
        let key = EncodingKey::from_ec_pem(pem)
            .map_err(|e| SignError::new(format!("parse ES256 signing key: {e}")))?;
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid);
        Ok(Self {
            key,
            header,
            issuer,
            contract_version,
            ttl_secs,
            counter: AtomicU64::new(0),
        })
    }

    /// Assemble the claims for a resolved identity and mint a signed compact token.
    ///
    /// # Errors
    /// Returns [`SignError`] if encoding/signing fails (treated as fail-closed by the
    /// caller — no token is then stamped and the box rejects the request).
    pub(crate) fn mint(&self, input: &MintInput<'_>) -> Result<String, SignError> {
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        let claims = ContractClaims {
            iss: self.issuer.clone(),
            aud: input.aud.to_owned(),
            sub: input.sub.to_owned(),
            iat: input.now,
            exp: input.now.saturating_add(self.ttl_secs),
            jti: format!("{}-{seq}", input.now),
            ctr: self.contract_version.clone(),
            workspace_id: input.workspace_id.to_owned(),
            principal_kind: input.principal_kind.to_owned(),
            on_behalf_of: input.on_behalf_of.map(str::to_owned),
            member_type: input.member_type.map(str::to_owned),
            role: input.role.map(str::to_owned),
            roles: input.roles.to_vec(),
            permissions: input.permissions.to_vec(),
            plan: None,
        };
        self.sign(&claims)
    }
}

impl ContractSigner for Signer {
    fn sign(&self, claims: &ContractClaims) -> Result<String, SignError> {
        encode(&self.header, claims, &self.key)
            .map_err(|e| SignError::new(format!("sign contract: {e}")))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "tests legitimately unwrap on fixtures known to be valid"
    )]
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use jsonwebtoken::errors::{ErrorKind, Result as JwtResult};
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};

    /// Real wall-clock seconds — positive tests mint at "now" so `exp` is in the
    /// future and validation turns only on the property under test.
    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    const TEST_PEM: &str = include_str!("testdata/test-ec-p256.pem");
    const TEST_JWKS: &str = include_str!("testdata/test-jwks.json");
    const OTHER_JWKS: &str = include_str!("testdata/other-jwks.json");
    const TEST_KID: &str = "test-key-1";
    const ISSUER: &str = "https://identity.nexus";
    const AUD: &str = "evenout";

    /// Build a signer over the embedded test key, TTL 60s.
    fn test_signer() -> Signer {
        Signer::from_pem(
            TEST_PEM.as_bytes(),
            TEST_KID.to_owned(),
            ISSUER.to_owned(),
            "v1".to_owned(),
            60,
        )
        .unwrap()
    }

    fn mint_at(signer: &Signer, aud: &str, now: u64) -> String {
        signer
            .mint(&MintInput {
                sub: "user-1",
                aud,
                principal_kind: "user",
                on_behalf_of: None,
                workspace_id: "ws-1",
                member_type: Some("staff"),
                role: Some("admin"),
                roles: &["ops".to_owned()],
                permissions: &[],
                now,
            })
            .unwrap()
    }

    /// Verify a token against a published JWKS, returning the decode result so
    /// negative tests can assert the specific failure.
    fn verify_with(jwks_json: &str, token: &str) -> JwtResult<ContractClaims> {
        let jwks: JwkSet = serde_json::from_str(jwks_json).unwrap();
        let header = decode_header(token).unwrap();
        let kid = header.kid.unwrap_or_default();
        let Some(jwk) = jwks.find(&kid) else {
            // Unknown key: the verifier has no key for this token's kid.
            return Err(ErrorKind::InvalidSignature.into());
        };
        let key = DecodingKey::from_jwk(jwk).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[AUD]);
        validation.set_issuer(&[ISSUER]);
        decode::<ContractClaims>(token, &key, &validation).map(|d| d.claims)
    }

    #[test]
    fn sign_verify_roundtrip_against_published_jwks() {
        // Task 4.2 / 6.3: a token minted by the signer verifies against the operator
        // JWKS, and every claim survives the round-trip.
        let signer = test_signer();
        let token = mint_at(&signer, AUD, now_secs());
        let claims = verify_with(TEST_JWKS, &token).expect("must verify");
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.aud, AUD);
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.workspace_id, "ws-1");
        assert_eq!(claims.principal_kind, "user");
        assert_eq!(claims.member_type.as_deref(), Some("staff"));
        assert_eq!(claims.role.as_deref(), Some("admin"));
        assert_eq!(claims.ctr, "v1");
        assert_eq!(claims.roles, vec!["ops".to_owned()]);
        assert!(claims.permissions.is_empty(), "a user carries no platform permissions");
        assert!(claims.plan.is_none(), "plan is reserved, not populated");
    }

    #[test]
    fn service_contract_conveys_platform_authority_not_a_member_role() {
        // Task 5.2: for a Platform authority the token carries principal_kind=service,
        // the acting workspace, and the permission set — and OMITS member_type/role
        // (a service has no membership). The omitted claims deserialize to None.
        let signer = test_signer();
        let token = signer
            .mint(&MintInput {
                sub: "system:serviceaccount:nexus:events-writer",
                aud: AUD,
                principal_kind: "service",
                on_behalf_of: None,
                workspace_id: "ws-acting",
                member_type: None,
                role: None,
                roles: &[],
                permissions: &["events:write".to_owned()],
                now: now_secs(),
            })
            .unwrap();
        let claims = verify_with(TEST_JWKS, &token).expect("service token must verify");
        assert_eq!(claims.principal_kind, "service");
        assert_eq!(claims.workspace_id, "ws-acting");
        assert_eq!(claims.permissions, vec!["events:write".to_owned()]);
        assert!(claims.member_type.is_none(), "a service must not claim a member_type");
        assert!(claims.role.is_none(), "a service must not claim a workspace role");
        assert!(claims.roles.is_empty());
        assert!(claims.on_behalf_of.is_none(), "a service acts as itself, not on behalf of");
        // The omitted claims must not appear on the wire: re-serializing the claims
        // exercises the same `skip_serializing_if` the mint used to build the payload.
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("\"member_type\""), "member_type omitted on the wire");
        assert!(!json.contains("\"role\""), "role omitted on the wire");
        assert!(!json.contains("\"on_behalf_of\""), "on_behalf_of omitted for a non-key");
        assert!(json.contains("\"principal_kind\""));
        assert!(json.contains("\"permissions\""));
    }

    #[test]
    fn api_key_contract_names_the_key_and_the_creator() {
        // Task 5.1 / 5.2 (identity-contract-signing ADDED delta): an apikey principal's
        // contract carries principal_kind=apikey, the key id as `sub`, and the creating
        // user as `on_behalf_of` — alongside the acting workspace membership the key
        // resolved to. A non-key principal omits `on_behalf_of` (asserted above).
        let signer = test_signer();
        let token = signer
            .mint(&MintInput {
                sub: "pak_deadbeef",
                aud: AUD,
                principal_kind: "apikey",
                on_behalf_of: Some("u-creator"),
                workspace_id: "ws-1",
                member_type: Some("staff"),
                role: Some("admin"),
                // Least-privilege: an api key carries no coarse global roles of its own.
                roles: &[],
                permissions: &[],
                now: now_secs(),
            })
            .unwrap();
        let claims = verify_with(TEST_JWKS, &token).expect("apikey token must verify");
        assert_eq!(claims.principal_kind, "apikey");
        assert_eq!(claims.sub, "pak_deadbeef");
        assert_eq!(claims.on_behalf_of.as_deref(), Some("u-creator"));
        assert_eq!(claims.workspace_id, "ws-1");
        assert_eq!(claims.member_type.as_deref(), Some("staff"));
        assert_eq!(claims.role.as_deref(), Some("admin"));
        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("\"on_behalf_of\""), "an apikey contract carries on_behalf_of");
    }

    #[test]
    fn tampered_token_is_rejected() {
        let signer = test_signer();
        // Flip a character in the payload segment — signature no longer matches.
        let mut bad = mint_at(&signer, AUD, now_secs());
        let mid = bad.len() / 2;
        let ch = if bad.as_bytes()[mid] == b'A' { 'B' } else { 'A' };
        bad.replace_range(mid..=mid, &ch.to_string());
        assert!(verify_with(TEST_JWKS, &bad).is_err(), "tampered token must fail");
    }

    #[test]
    fn expired_token_is_rejected() {
        let signer = test_signer();
        // Minted at epoch 1000 (exp = 1060) while the verifier's clock is the real
        // present, so exp is far beyond the default 60s leeway → ExpiredSignature.
        let stale = mint_at(&signer, AUD, 1000);
        assert!(verify_with(TEST_JWKS, &stale).is_err(), "expired token must fail");
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let signer = test_signer();
        // Minted for a different box (with a valid future exp so aud is the only
        // failing check); presenting it where aud is expected fails.
        let token = mint_at(&signer, "some-other-box", now_secs());
        assert!(
            verify_with(TEST_JWKS, &token).is_err(),
            "a token for another audience must be rejected"
        );
    }

    #[test]
    fn from_pem_rejects_a_non_key() {
        // The basis for build_signer's fail-fast: an unloadable key surfaces as an error
        // (so main exits) rather than being swallowed into a silent unsigned mode.
        let bad = Signer::from_pem(
            b"-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n",
            "k1".to_owned(),
            ISSUER.to_owned(),
            "v1".to_owned(),
            60,
        );
        assert!(bad.is_err(), "a malformed key must be rejected, not silently accepted");
    }

    #[test]
    fn unknown_signing_key_is_rejected() {
        let signer = test_signer();
        let token = mint_at(&signer, AUD, now_secs());
        // The token's kid is absent from this (unrelated) JWKS → no key to verify with.
        assert!(
            verify_with(OTHER_JWKS, &token).is_err(),
            "a token whose signing key is not published must be rejected"
        );
    }
}
