//! The OpenBao **Transit** adapter (`identity-contract-signing`,
//! automate-signing-key-rotation) — the production [`KeyProvider`], Mode B.
//!
//! Adopt, not build (design.md Decision 1): OpenBao runs in-infra regardless, and its
//! Transit engine gives versioned-key rotation nearly turnkey — each key version is a
//! `kid`, `ecdsa-p256` matches the ES256 signer, and public keys are exportable so the
//! JWKS is *generated* rather than hand-synced. `vaultrs` is the maintained async client.
//!
//! Mode B keeps signing LOCAL (no per-request Bao hop, no hot-path dependency on Bao
//! uptime): the plane EXPORTS an `exportable` signing key's private PEM for the active
//! version and mints in-process. Only the active version's private material is pulled;
//! every version's PUBLIC key is exported to build the published JWKS.
//!
//! This is the ONLY module that touches `vaultrs` — it implements the [`KeyProvider`]
//! port so the rotation manager and its tests never see a Transit type.

use vaultrs::api::transit::requests::{ExportKeyType, ExportVersion};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::transit::key;

use crate::keyprovider::{
    ec_private_pem_to_pkcs8, jwk_from_public_pem, KeyProvider, KeyProviderError, PublicKeyVersion,
};

/// A Transit-backed signing-key provider: a `vaultrs` client bound to one Transit mount
/// + key name. `ecdsa-p256`, `exportable = true` (Mode B local signing), and — for the
/// JWKS — public keys exported per version.
pub(crate) struct TransitKeyProvider {
    client: VaultClient,
    /// The Transit mount path (e.g. `transit`).
    mount: String,
    /// The Transit key name whose versions are the signing `kid`s.
    key_name: String,
}

impl TransitKeyProvider {
    /// Build the client for `address` (the OpenBao API URL) authenticated with `token`,
    /// bound to `mount`/`key_name`. The private key never leaves this process beyond the
    /// export the plane itself requests (Mode B custody trade, design.md).
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] if the client settings or the client cannot be built.
    pub(crate) fn new(
        address: String,
        token: String,
        mount: String,
        key_name: String,
    ) -> Result<Self, KeyProviderError> {
        let settings = VaultClientSettingsBuilder::default()
            .address(address)
            .token(token)
            .build()
            .map_err(|e| KeyProviderError::new(format!("build OpenBao client settings: {e}")))?;
        let client = VaultClient::new(settings)
            .map_err(|e| KeyProviderError::new(format!("build OpenBao client: {e}")))?;
        Ok(Self {
            client,
            mount,
            key_name,
        })
    }

    /// The `kid` for a version — the Transit key name plus the version number, stable and
    /// distinct across versions (the value stamped in the token header and the JWKS).
    fn kid_for(&self, version: u64) -> String {
        format!("{}-v{version}", self.key_name)
    }
}

#[async_trait::async_trait]
impl KeyProvider for TransitKeyProvider {
    async fn public_versions(&self) -> Result<Vec<PublicKeyVersion>, KeyProviderError> {
        // Export every published version's PUBLIC key (no private material pulled here).
        let exported = key::export(
            &self.client,
            &self.mount,
            &self.key_name,
            ExportKeyType::PublicKey,
            ExportVersion::All,
        )
        .await
        .map_err(|e| KeyProviderError::new(format!("Transit export public keys: {e}")))?;

        let mut versions = Vec::with_capacity(exported.keys.len());
        for (version_str, pem) in exported.keys {
            let version = version_str.parse::<u64>().map_err(|e| {
                KeyProviderError::new(format!("Transit version '{version_str}' not numeric: {e}"))
            })?;
            let kid = self.kid_for(version);
            let public_jwk = jwk_from_public_pem(&kid, &pem)?;
            versions.push(PublicKeyVersion {
                version,
                kid,
                public_jwk,
            });
        }
        Ok(versions)
    }

    async fn export_private_pem(&self, version: u64) -> Result<String, KeyProviderError> {
        // Export ONLY the active version's private (signing) key — Mode B local signing.
        let exported = key::export(
            &self.client,
            &self.mount,
            &self.key_name,
            ExportKeyType::SigningKey,
            ExportVersion::Version(version),
        )
        .await
        .map_err(|e| KeyProviderError::new(format!("Transit export signing key v{version}: {e}")))?;
        let sec1_or_pkcs8 = exported.keys.get(&version.to_string()).ok_or_else(|| {
            KeyProviderError::new(format!("Transit returned no signing key for v{version}"))
        })?;
        // Transit exports ECDSA keys as SEC1 PEM; normalize to the PKCS#8 the ES256 signer
        // (jsonwebtoken/ring) requires.
        ec_private_pem_to_pkcs8(sec1_or_pkcs8)
    }

    async fn rotate(&self) -> Result<(), KeyProviderError> {
        key::rotate(&self.client, &self.mount, &self.key_name)
            .await
            .map_err(|e| KeyProviderError::new(format!("Transit rotate {}: {e}", self.key_name)))
    }
}
