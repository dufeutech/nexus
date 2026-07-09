//! The signing-key **provider port** (`identity-contract-signing`,
//! automate-signing-key-rotation). This is the seam that isolates *where signing keys
//! come from* — a managed OpenBao Transit engine in production
//! ([`crate::transit`]), a generated in-memory fake in tests — from the rotation
//! manager that drives cut-over and JWKS publication ([`crate::rotation`]).
//!
//! Mode B (design.md Decision 1): the plane pulls key **material** and signs
//! **locally** (no per-request Bao hop). The port therefore exposes two reads with
//! deliberately different exposure:
//!   - [`KeyProvider::public_versions`] — the PUBLIC half of every live version, as a
//!     ready-to-publish JWK, so the JWKS is *generated* from the source rather than
//!     hand-synced (killing the manual `kid` ↔ JWKS drift).
//!   - [`KeyProvider::export_private_pem`] — the PRIVATE PEM of ONE version, fetched
//!     only for the active key the plane actually signs with, so a retired version's
//!     private material is never pulled.
//!
//! Abstraction discipline: no `vaultrs`/`p256` type crosses this port — the manager
//! depends only on [`PublicKeyVersion`] + PEM strings, so the Transit adapter and the
//! fake are swappable without touching rotation logic.

use std::fmt;

/// One live key version's PUBLIC verification material, as returned by the provider.
/// `version` is the provider's monotonic version number (the HIGHEST is the active
/// signing key); `kid` is the stable identifier published in the JWKS and stamped in
/// the token header; `public_jwk` is a complete JWK object (`kty`/`crv`/`x`/`y` +
/// `kid`/`use`/`alg`) ready to drop into the published `keys` array.
pub(crate) struct PublicKeyVersion {
    /// Provider-assigned monotonic version; the maximum is the active signer.
    pub(crate) version: u64,
    /// Stable key id — published in the JWKS, stamped in the token header.
    pub(crate) kid: String,
    /// The public key as a complete JWK object, ready to publish.
    pub(crate) public_jwk: serde_json::Value,
}

/// A provider failure — opaque (message for logs only) so no key material or client
/// internals leak to callers. The rotation manager treats any provider error as
/// "cannot refresh": it keeps serving the last-published signer + JWKS and, at
/// startup, falls back to the break-glass PEM (design.md Risk: Bao unreachable).
#[derive(Debug)]
pub(crate) struct KeyProviderError(String);

impl KeyProviderError {
    /// Wrap a human-readable reason.
    pub(crate) const fn new(message: String) -> Self {
        Self(message)
    }
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The port the rotation manager reads key material through. Implemented by the
/// `vaultrs` OpenBao Transit adapter ([`crate::transit::TransitKeyProvider`]) in
/// production and by [`FakeKeyProvider`] in tests.
#[async_trait::async_trait]
pub(crate) trait KeyProvider: Send + Sync {
    /// The PUBLIC half of every non-destroyed version, ascending by `version`. The
    /// highest version is the active signing key; lower ones are retained for the
    /// verification overlap. Used to generate the published JWKS.
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] if the source is unreachable or returns material
    /// that cannot be parsed into a JWK.
    async fn public_versions(&self) -> Result<Vec<PublicKeyVersion>, KeyProviderError>;

    /// Export the PRIVATE PKCS#8 PEM for one version — Mode B signs locally with it.
    /// Called only for the active version at each cut-over, so a retired version's
    /// private key is never exported.
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] if the version is unknown or not exportable.
    async fn export_private_pem(&self, version: u64) -> Result<String, KeyProviderError>;

    /// Create a new highest version (it becomes the active signing key on the next
    /// [`KeyProvider::public_versions`]). Drives scheduled and on-demand rotation.
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] if the source rejects the rotation.
    async fn rotate(&self) -> Result<(), KeyProviderError>;
}

/// Build a complete published JWK object from a P-256 public key: the `kty`/`crv`/`x`/`y`
/// the key itself carries, plus the `kid`/`use`/`alg` a verifier selects and validates on.
fn jwk_from_public_key(
    public: &p256::PublicKey,
    kid: &str,
) -> Result<serde_json::Value, KeyProviderError> {
    let mut value = serde_json::to_value(public.to_jwk())
        .map_err(|e| KeyProviderError::new(format!("serialize P-256 JWK: {e}")))?;
    let serde_json::Value::Object(map) = &mut value else {
        return Err(KeyProviderError::new(
            "P-256 JWK did not serialize to a JSON object".to_owned(),
        ));
    };
    let _prev_kid = map.insert("kid".to_owned(), serde_json::Value::String(kid.to_owned()));
    let _prev_use = map.insert("use".to_owned(), serde_json::Value::String("sig".to_owned()));
    let _prev_alg = map.insert("alg".to_owned(), serde_json::Value::String("ES256".to_owned()));
    Ok(value)
}

/// Parse an EC P-256 SPKI public-key PEM (as exported by Transit's `export/public-key`)
/// into a complete published JWK. The one place the adapter turns provider PEM into the
/// JWK the JWKS publishes.
///
/// # Errors
/// Returns [`KeyProviderError`] if `pem` is not a valid P-256 SPKI public key.
pub(crate) fn jwk_from_public_pem(
    kid: &str,
    pem: &str,
) -> Result<serde_json::Value, KeyProviderError> {
    use p256::pkcs8::spki::DecodePublicKey as _;
    let public = p256::PublicKey::from_public_key_pem(pem)
        .map_err(|e| KeyProviderError::new(format!("parse P-256 public key PEM: {e}")))?;
    jwk_from_public_key(&public, kid)
}

/// Normalize an EC P-256 private-key PEM to **PKCS#8** PEM. OpenBao's Transit
/// `export/signing-key` returns the ECDSA key as **SEC1** (`-----BEGIN EC PRIVATE KEY-----`),
/// but `jsonwebtoken`/`ring` accept only PKCS#8 (`-----BEGIN PRIVATE KEY-----`) — so the
/// adapter re-encodes here before building a signer. Accepts either input form (SEC1 or
/// already-PKCS#8) so the signer never has to care which the source produced.
///
/// # Errors
/// Returns [`KeyProviderError`] if `pem` is neither a valid SEC1 nor PKCS#8 P-256 key.
pub(crate) fn ec_private_pem_to_pkcs8(pem: &str) -> Result<String, KeyProviderError> {
    use p256::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _, LineEnding};
    let secret = match p256::SecretKey::from_sec1_pem(pem) {
        Ok(secret) => secret,
        // Not SEC1 — accept an already-PKCS#8 key too (some sources/versions emit it).
        Err(_) => p256::SecretKey::from_pkcs8_pem(pem).map_err(|e| {
            KeyProviderError::new(format!("parse EC private key PEM (tried SEC1 then PKCS#8): {e}"))
        })?,
    };
    secret
        .to_pkcs8_pem(LineEnding::LF)
        .map(|encoded| encoded.to_string())
        .map_err(|e| KeyProviderError::new(format!("re-encode EC private key as PKCS#8: {e}")))
}

#[cfg(test)]
pub(crate) use fake::FakeKeyProvider;

#[cfg(test)]
mod fake {
    //! An in-memory [`KeyProvider`] that GENERATES EC P-256 keys — the test double the
    //! overlap/retire/`kid`-consistency invariants are proven against without a live
    //! OpenBao (design.md: "a fake in-memory provider backs the unit tests"). It mirrors
    //! Transit's shape: monotonic versions, the highest is active, `rotate` appends a new
    //! highest version, and public/private material is exported separately.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "the fake generates fixtures known-valid; test-only code"
    )]

    use std::sync::Mutex;

    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
    use rand_core::OsRng;

    use super::{jwk_from_public_key, KeyProvider, KeyProviderError, PublicKeyVersion};

    /// One generated version: its public JWK (for publication) + its private PKCS#8 PEM
    /// (for local signing).
    struct FakeVersion {
        kid: String,
        public_jwk: serde_json::Value,
        private_pem: String,
    }

    /// A generated in-memory provider. `versions` grows on each [`FakeKeyProvider::rotate`];
    /// index + 1 is the version number, so the last element is always the active key.
    pub(crate) struct FakeKeyProvider {
        versions: Mutex<Vec<FakeVersion>>,
        /// Set to make `public_versions` fail — exercises the "provider unreachable" path.
        unreachable: bool,
    }

    impl FakeKeyProvider {
        /// A provider that already holds one generated version (a normal running state).
        pub(crate) fn with_one_key() -> Self {
            let provider = Self {
                versions: Mutex::new(Vec::new()),
                unreachable: false,
            };
            provider.generate();
            provider
        }

        /// A provider whose reads always fail — for the startup break-glass fallback test.
        pub(crate) fn unreachable() -> Self {
            Self {
                versions: Mutex::new(Vec::new()),
                unreachable: true,
            }
        }

        /// Generate a fresh EC P-256 key and append it as the new highest version.
        fn generate(&self) {
            let secret = p256::SecretKey::random(&mut OsRng);
            let private_pem = secret
                .to_pkcs8_pem(LineEnding::LF)
                .expect("encode P-256 PKCS#8 PEM")
                .to_string();
            let mut guard = self.versions.lock().expect("fake key lock");
            let version = guard.len().saturating_add(1) as u64;
            let kid = format!("fake-v{version}");
            let public_jwk =
                jwk_from_public_key(&secret.public_key(), &kid).expect("build fake JWK");
            guard.push(FakeVersion {
                kid,
                public_jwk,
                private_pem,
            });
        }
    }

    #[async_trait::async_trait]
    impl KeyProvider for FakeKeyProvider {
        async fn public_versions(&self) -> Result<Vec<PublicKeyVersion>, KeyProviderError> {
            if self.unreachable {
                return Err(KeyProviderError::new("fake provider unreachable".to_owned()));
            }
            let guard = self.versions.lock().expect("fake key lock");
            Ok(guard
                .iter()
                .enumerate()
                .map(|(idx, entry)| PublicKeyVersion {
                    version: (idx as u64).saturating_add(1),
                    kid: entry.kid.clone(),
                    public_jwk: entry.public_jwk.clone(),
                })
                .collect())
        }

        async fn export_private_pem(&self, version: u64) -> Result<String, KeyProviderError> {
            let guard = self.versions.lock().expect("fake key lock");
            let idx = usize::try_from(version.saturating_sub(1))
                .map_err(|e| KeyProviderError::new(format!("version index: {e}")))?;
            guard
                .get(idx)
                .map(|entry| entry.private_pem.clone())
                .ok_or_else(|| KeyProviderError::new(format!("no fake version {version}")))
        }

        async fn rotate(&self) -> Result<(), KeyProviderError> {
            self.generate();
            Ok(())
        }
    }
}
