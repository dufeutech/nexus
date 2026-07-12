//! Startup wiring, resolved once from the environment: the ES256 contract signer
//! (break-glass PEM or OpenBao Transit managed rotation), the api-key authenticator,
//! the operator JWKS document, and the L2 policy engine. Each arm fails closed / off
//! rather than run half-configured.

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::Arc;

use tokio::sync::watch;
use tracing::{error, info, warn};

use identity_core::{DenyAllPdp, PolicyDecisionPoint};
use policy_cedar::CedarPdp;
use store_postgres::{HmacSecretHasher, PgApiKeyReader};

use crate::state::{ApiKeyAuth, IDENTITY_CONTRACT_VERSION};
use crate::{rotation, signer, transit};

/// Construct the ES256 contract signer from the environment (identity-contract-signing).
///
/// Fail-fast on MISCONFIGURATION: when `SIGNING_KEY_PATH` is set but the key cannot be
/// loaded, return an error so the process exits at startup rather than silently running
/// unsigned — which would reject every authenticated request at the box, at request time.
///
/// When `SIGNING_KEY_PATH` is unset, signing is explicitly OFF (a deliberate dev/eval
/// choice): return `None`. Anonymous traffic is unaffected either way — the signing key is
/// only ever used to mint a token for an authenticated member — so keyless mode still
/// serves anonymous requests normally; only authenticated requests then carry no contract.
fn build_signer() -> Result<Option<Arc<signer::Signer>>, Box<dyn Error>> {
    let Some(key_path) = env::var("SIGNING_KEY_PATH").ok().filter(|p| !p.is_empty()) else {
        warn!("SIGNING_KEY_PATH unset -> x-identity-contract signing OFF (anonymous unaffected; authenticated requests carry no contract)");
        return Ok(None);
    };
    let kid = env::var("SIGNING_KID").unwrap_or_else(|_| "nexus-1".to_owned());
    let issuer =
        env::var("SIGNING_ISSUER").unwrap_or_else(|_| "https://identity.nexus".to_owned());
    let ttl = env::var("CONTRACT_TOKEN_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let built = signer::Signer::from_pem_file(
        &key_path,
        kid,
        issuer,
        IDENTITY_CONTRACT_VERSION.to_owned(),
        ttl,
    )
    .map_err(|e| {
        format!("SIGNING_KEY_PATH={key_path} is set but the signing key could not be loaded: {e}")
    })?;
    info!(ttl_s = ttl, "x-identity-contract ES256 signing ENABLED");
    Ok(Some(Arc::new(built)))
}

/// Construct the api-key authenticator from the environment (`customer-api-keys`).
///
/// `None` (api-key auth OFF) when `APIKEY_PG_RO_URL` is unset — a deliberate
/// human/service-only deployment. When the URL is set but the setup is incomplete or
/// broken (`APIKEY_HMAC_PEPPER` unset ⇒ cannot verify secrets; or the store connect
/// fails), api-key auth is DISABLED with a warning rather than run half-configured — fail
/// closed: an `x-api-key` then simply never resolves, and the human/service paths are
/// unaffected.
pub(crate) async fn build_api_key_auth() -> Option<ApiKeyAuth> {
    let url = env::var("APIKEY_PG_RO_URL").ok().filter(|u| !u.is_empty())?;
    let Some(pepper) = env::var("APIKEY_HMAC_PEPPER").ok().filter(|p| !p.is_empty()) else {
        warn!("APIKEY_PG_RO_URL set but APIKEY_HMAC_PEPPER unset -> api-key auth OFF (cannot verify secrets)");
        return None;
    };
    match PgApiKeyReader::connect(&url).await {
        Ok(reader) => {
            info!("customer-api-key authentication ENABLED (live per-request resolve)");
            Some(ApiKeyAuth {
                reader: Arc::new(reader),
                hasher: Arc::new(HmacSecretHasher::new(pepper.into_bytes())),
            })
        }
        Err(e) => {
            error!(error = %e, "APIKEY_PG_RO_URL set but api-key store connect failed -> api-key auth OFF");
            None
        }
    }
}

/// Load the operator-supplied break-glass JWKS document (identity-contract-signing).
/// `None` (endpoint not started) when `JWKS_FILE` is unset or unreadable. Used only on
/// the break-glass PEM path; the Transit path GENERATES the JWKS from key material.
fn load_jwks() -> Option<Arc<String>> {
    let path = env::var("JWKS_FILE").ok().filter(|p| !p.is_empty())?;
    match fs::read_to_string(&path) {
        Ok(doc) => Some(Arc::new(doc)),
        Err(e) => {
            error!(error = %e, path, "failed to read JWKS document -> JWKS endpoint DISABLED");
            None
        }
    }
}

/// The signer + JWKS publication the plane runs with, resolved once at startup — a
/// swap-able active signer and a republish-able JWKS document, both as `watch` receivers
/// so the hot path and the JWKS listener share one shape whether keys are managed
/// (Transit) or static (break-glass PEM). `None` on either arm means that surface is off.
pub(crate) struct SigningSetup {
    pub(crate) signer: Option<watch::Receiver<Arc<signer::Signer>>>,
    pub(crate) jwks: Option<watch::Receiver<Arc<String>>>,
}

/// Resolve the signing wiring in precedence order (automate-signing-key-rotation):
///
///   1. **OpenBao Transit** (managed custody + automated rotation) when
///      `SIGNING_TRANSIT_KEY` is set: the plane pulls key material and signs locally
///      (Mode B), the rotation manager generates the JWKS and enforces the overlap
///      window, and a background task drives scheduled/on-demand rotation. If Transit is
///      unreachable at startup it FALLS BACK to the break-glass PEM (design.md Risk: Bao
///      unreachable) — fail loud, never silently unsigned.
///   2. **Break-glass `SIGNING_KEY_PATH` PEM** (the pre-rotation manual path): a static
///      signer + the operator-supplied `JWKS_FILE`, each wrapped in a never-changing
///      `watch`.
///   3. **Signing off** when neither is configured.
pub(crate) async fn build_signing() -> Result<SigningSetup, Box<dyn Error>> {
    if let Some(key_name) = env::var("SIGNING_TRANSIT_KEY").ok().filter(|v| !v.is_empty()) {
        match build_transit_rotation(key_name).await {
            Ok(setup) => return Ok(setup),
            Err(e) => error!(
                error = %e,
                "OpenBao Transit signing unavailable at startup -> falling back to break-glass SIGNING_KEY_PATH PEM"
            ),
        }
    }
    // Break-glass / static path: wrap the static signer + operator JWKS in never-changing
    // `watch` channels (the sender drops immediately; `borrow()` keeps serving the value).
    let signer = build_signer()?.map(|active| watch::channel(active).1);
    let jwks = load_jwks().map(|doc| watch::channel(doc).1);
    Ok(SigningSetup { signer, jwks })
}

/// Stand up the OpenBao Transit provider + rotation manager (Mode B) and spawn its poll
/// loop. Returns the swap-able signer + generated-JWKS receivers. Any startup failure
/// (Bao unreachable, missing token, no exportable key) is surfaced so [`build_signing`]
/// can fall back to the break-glass PEM.
async fn build_transit_rotation(key_name: String) -> Result<SigningSetup, Box<dyn Error>> {
    let address = env::var("BAO_ADDR")
        .or_else(|_| env::var("VAULT_ADDR"))
        .unwrap_or_else(|_| "http://127.0.0.1:8200".to_owned());
    let token = env::var("BAO_TOKEN")
        .or_else(|_| env::var("VAULT_TOKEN"))
        .map_err(|_| "SIGNING_TRANSIT_KEY set but neither BAO_TOKEN nor VAULT_TOKEN is set")?;
    let mount = env::var("SIGNING_TRANSIT_MOUNT").unwrap_or_else(|_| "transit".to_owned());
    let issuer =
        env::var("SIGNING_ISSUER").unwrap_or_else(|_| "https://identity.nexus".to_owned());
    let ttl_secs: u64 = env::var("CONTRACT_TOKEN_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    // The overlap window MUST cover a token's whole in-flight life: its TTL plus the max
    // clock skew between the plane and a verifying box, so no token signed just before a
    // cut-over is rejected mid-rotation (spec: rotation preserves the overlap guarantee).
    let skew_secs: u64 = env::var("CONTRACT_MAX_CLOCK_SKEW_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let overlap_secs = ttl_secs.saturating_add(skew_secs);
    let poll_secs: u64 = env::var("SIGNING_KEY_POLL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    // Optional plane-driven scheduled rotation. Unset ⇒ the plane only mirrors rotations
    // triggered at the source (Transit auto-rotate, or an operator on suspected compromise).
    let rotation_period_secs = env::var("SIGNING_ROTATION_PERIOD_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok());

    let provider = transit::TransitKeyProvider::new(address, token, mount, key_name)
        .map_err(|e| format!("build OpenBao Transit provider: {e}"))?;
    let cfg = rotation::RotationConfig {
        issuer,
        contract_version: IDENTITY_CONTRACT_VERSION.to_owned(),
        ttl_secs,
        overlap_secs,
        rotation_period_secs,
        poll_secs,
    };
    let (manager, handles) = rotation::RotationManager::bootstrap(Arc::new(provider), cfg)
        .await
        .map_err(|e| format!("bootstrap signing-key rotation: {e}"))?;
    drop(tokio::spawn(manager.run()));
    info!(
        ttl_s = ttl_secs,
        overlap_s = overlap_secs,
        poll_s = poll_secs,
        "x-identity-contract signing via OpenBao Transit ENABLED (automated rotation, Mode B local signing)"
    );
    Ok(SigningSetup {
        signer: Some(handles.signer_rx),
        jwks: Some(handles.jwks_rx),
    })
}

/// Load the L2 authorization policy engine (adopt-cedar-policy-gate). Reads the parity
/// Cedar policy set from `POLICY_DIR` when configured (the per-environment override,
/// design Decision 3), else the embedded default set. A malformed/unvalidatable set
/// FAILS CLOSED: install [`DenyAllPdp`] so gated routes are refused (403) rather than
/// served against an empty or partial policy set; ungated routes never consult the PDP
/// and still pass.
pub(crate) fn build_policy_pdp() -> Arc<dyn PolicyDecisionPoint> {
    let loaded = match env::var("POLICY_DIR").ok().filter(|dir| !dir.is_empty()) {
        Some(dir) => CedarPdp::from_path(Path::new(&dir)),
        None => CedarPdp::with_default_policies(),
    };
    match loaded {
        Ok(pdp) => {
            info!("L2 authorization policy engine loaded (Cedar parity policy)");
            Arc::new(pdp)
        }
        Err(e) => {
            error!(
                error = %e,
                "L2 policy set failed to load -> failing closed (gated routes denied)"
            );
            Arc::new(DenyAllPdp)
        }
    }
}
