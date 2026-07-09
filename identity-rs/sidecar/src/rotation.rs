//! The rotation manager (`identity-contract-signing`, automate-signing-key-rotation):
//! turns a [`KeyProvider`]'s versioned keys into a **swap-able active signer** + a
//! **generated, republish-able JWKS**, and enforces the two-key overlap invariant so
//! automated rotation never rejects an in-flight token.
//!
//! What it owns (design.md Decision 1, "Structure"):
//!   - **Cut-over.** The highest provider version is the active signer. When it changes,
//!     the manager exports that version's private PEM, builds a fresh [`Signer`], and
//!     swaps it atomically over a `watch` channel — the hot path reads the current signer
//!     with a cheap `Arc` clone, never a lock held across a mint.
//!   - **Overlap / retirement.** A rotated-AWAY key stays in the published JWKS for
//!     `overlap_secs` (≥ `CONTRACT_TOKEN_TTL_SECONDS` + max clock skew), so a box still
//!     verifies tokens signed by it while they are in flight; only after the window does
//!     it drop. The manager CACHES each version's public JWK so it can keep publishing a
//!     rotated-away key even if the source stops returning it (Transit advancing
//!     `min_decryption_version`).
//!   - **Generated JWKS.** The published document is regenerated from the provider's
//!     public keys every refresh — there is no hand-synced `kid` ↔ JWKS step to drift.
//!
//! Rotation is driven by polling: a scheduled plane-side period (optional) triggers
//! `rotate` on the provider, and every poll `refresh`es — so an OUT-OF-BAND rotation (an
//! operator rotating the Transit key on suspected compromise, design.md On-demand
//! scenario) is picked up within one bounded poll interval without hand-editing anything.

use std::collections::{HashMap, HashSet};
use std::iter;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;
use tokio::sync::watch;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::keyprovider::{KeyProvider, KeyProviderError};
use crate::signer::Signer;

/// Wall-clock seconds since the Unix epoch — the basis for overlap/retirement timing
/// (the poll loop's clock; tests inject `now` into `step`/`refresh` directly).
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Static configuration for a [`RotationManager`]: the claim policy the built signers
/// carry, the overlap window, and the poll/rotation cadence.
pub(crate) struct RotationConfig {
    /// The `iss` the minted contract carries (pinned by the verifier).
    pub(crate) issuer: String,
    /// The contract-version (`ctr`) claim — the header-family coordination gate.
    pub(crate) contract_version: String,
    /// Token TTL in seconds — the signer stamps `exp = iat + ttl`.
    pub(crate) ttl_secs: u64,
    /// How long a rotated-away key stays published. MUST be ≥ `ttl_secs` + max clock
    /// skew so no in-flight token is rejected mid-rotation (design.md Risk 1).
    pub(crate) overlap_secs: u64,
    /// Plane-driven scheduled rotation period. `None` = the plane never initiates a
    /// rotation itself; it only mirrors versions the operator/Transit rotate out of band.
    pub(crate) rotation_period_secs: Option<u64>,
    /// How often the manager re-reads the provider (bounds how fast an out-of-band
    /// rotation is adopted — the design's "bounded poll interval v1").
    pub(crate) poll_secs: u64,
}

/// The mutable bookkeeping the overlap invariant turns on, isolated from the I/O so the
/// timing logic is unit-testable with an injected clock.
#[derive(Default)]
struct RotationState {
    /// The kid currently signing (`None` before the first successful refresh).
    active_kid: Option<String>,
    /// Rotated-away kids still inside their overlap window: kid → retire-at (epoch secs).
    retiring: HashMap<String, u64>,
    /// Last-seen public JWK per publishable kid — so a rotated-away key stays publishable
    /// even after the source stops returning it.
    jwk_cache: HashMap<String, serde_json::Value>,
    /// Kids past their overlap window — never republished (guards against a source that
    /// still lists a version we already retired by time).
    retired: HashSet<String>,
}

/// The result of one refresh step, surfaced for the run loop's logging and for tests.
struct StepOutcome {
    /// `Some` only when the active key changed this step (the caller swaps the signer).
    new_signer: Option<Arc<Signer>>,
    /// The regenerated JWKS document to publish.
    jwks: String,
    /// The kids in the published set, sorted — for deterministic logging/assertions.
    published_kids: Vec<String>,
}

/// Drives cut-over, overlap-retirement, and JWKS regeneration off a [`KeyProvider`].
pub(crate) struct RotationManager {
    provider: Arc<dyn KeyProvider>,
    cfg: RotationConfig,
    state: RotationState,
    signer_tx: watch::Sender<Arc<Signer>>,
    jwks_tx: watch::Sender<Arc<String>>,
}

/// The receivers the rest of the plane consumes: the hot-path signer and the published
/// JWKS document, both swapped atomically on rotation.
pub(crate) struct RotationHandles {
    /// The current active signer — the hot path clones it per mint.
    pub(crate) signer_rx: watch::Receiver<Arc<Signer>>,
    /// The current published JWKS document — the JWKS listener serves it.
    pub(crate) jwks_rx: watch::Receiver<Arc<String>>,
}

impl RotationManager {
    /// Perform the FIRST key load and seed the swap channels. Returns the manager (ready
    /// to `run`) and the receivers the plane wires into `AppState`/the JWKS listener.
    ///
    /// # Errors
    /// Returns [`KeyProviderError`] if the provider cannot be read at startup or exposes
    /// no key version — the caller then falls back to the break-glass PEM (fail loud,
    /// never unsigned).
    pub(crate) async fn bootstrap(
        provider: Arc<dyn KeyProvider>,
        cfg: RotationConfig,
    ) -> Result<(Self, RotationHandles), KeyProviderError> {
        let mut state = RotationState::default();
        let outcome = Self::step(provider.as_ref(), &cfg, &mut state, now_secs()).await?;
        let signer = outcome.new_signer.ok_or_else(|| {
            KeyProviderError::new("provider returned no signable key version".to_owned())
        })?;
        let (signer_tx, signer_rx) = watch::channel(signer);
        let (jwks_tx, jwks_rx) = watch::channel(Arc::new(outcome.jwks));
        info!(
            published = ?outcome.published_kids,
            active = ?state.active_kid,
            "signing-key rotation bootstrapped from provider"
        );
        Ok((
            Self {
                provider,
                cfg,
                state,
                signer_tx,
                jwks_tx,
            },
            RotationHandles { signer_rx, jwks_rx },
        ))
    }

    /// One refresh: re-read the provider, cut over the active signer if it changed,
    /// retire keys past their overlap window, and regenerate the JWKS. Pure of wall-clock
    /// (takes `now`) so the overlap timing is unit-testable.
    async fn step(
        provider: &dyn KeyProvider,
        cfg: &RotationConfig,
        state: &mut RotationState,
        now: u64,
    ) -> Result<StepOutcome, KeyProviderError> {
        let mut versions = provider.public_versions().await?;
        versions.sort_by_key(|entry| entry.version);
        let active = versions
            .last()
            .ok_or_else(|| KeyProviderError::new("provider lists no key versions".to_owned()))?;
        let active_kid = active.kid.clone();
        let active_version = active.version;

        // Refresh the publishable-JWK cache from the source (skip already-retired kids).
        for entry in &versions {
            if !state.retired.contains(&entry.kid) {
                let _prev = state
                    .jwk_cache
                    .insert(entry.kid.clone(), entry.public_jwk.clone());
            }
        }

        // Cut over when the active (highest) version changed.
        let mut new_signer = None;
        if state.active_kid.as_deref() != Some(active_kid.as_str()) {
            let pem = provider.export_private_pem(active_version).await?;
            let signer = Signer::from_pem(
                pem.as_bytes(),
                active_kid.clone(),
                cfg.issuer.clone(),
                cfg.contract_version.clone(),
                cfg.ttl_secs,
            )
            .map_err(|e| KeyProviderError::new(format!("build signer for {active_kid}: {e}")))?;
            new_signer = Some(Arc::new(signer));
            let retire_at = now.saturating_add(cfg.overlap_secs);
            match state.active_kid.take() {
                // A normal rotation: the previous active enters its overlap window.
                Some(previous) if previous != active_kid => {
                    let _prev = state.retiring.insert(previous, retire_at);
                }
                Some(_) => {}
                // First adoption at startup: keep every OTHER live version published for
                // one overlap window, so tokens signed just before this process started
                // still verify.
                None => {
                    for entry in &versions {
                        if entry.kid != active_kid {
                            let _prev = state
                                .retiring
                                .entry(entry.kid.clone())
                                .or_insert(retire_at);
                        }
                    }
                }
            }
            state.active_kid = Some(active_kid.clone());
        }

        // Retire keys whose overlap window has elapsed — drop them from publication.
        let expired: Vec<String> = state
            .retiring
            .iter()
            .filter(|&(_, &retire_at)| retire_at <= now)
            .map(|(kid, _)| kid.clone())
            .collect();
        for kid in expired {
            let _removed = state.retiring.remove(&kid);
            let _dropped = state.jwk_cache.remove(&kid);
            let _inserted = state.retired.insert(kid);
        }

        // The published set = active + every key still inside its overlap window.
        let mut published_kids: Vec<String> = iter::once(active_kid.clone())
            .chain(state.retiring.keys().cloned())
            .collect();
        published_kids.sort();
        published_kids.dedup();
        let keys: Vec<serde_json::Value> = published_kids
            .iter()
            .filter_map(|kid| state.jwk_cache.get(kid).cloned())
            .collect();
        let jwks = serde_json::to_string(&json!({ "keys": keys }))
            .map_err(|e| KeyProviderError::new(format!("serialize JWKS: {e}")))?;

        Ok(StepOutcome {
            new_signer,
            jwks,
            published_kids,
        })
    }

    /// Re-read the provider and publish the result: swap the signer if it changed and
    /// republish the JWKS. Used by the run loop and by tests (with an injected clock).
    async fn refresh(&mut self, now: u64) -> Result<(), KeyProviderError> {
        let outcome = Self::step(self.provider.as_ref(), &self.cfg, &mut self.state, now).await?;
        if let Some(signer) = outcome.new_signer {
            // A send error means every receiver dropped (plane shutting down) — benign.
            let _sent = self.signer_tx.send(signer);
            info!(active = ?self.state.active_kid, "signing key cut over to a new version");
        }
        let _sent = self.jwks_tx.send(Arc::new(outcome.jwks));
        Ok(())
    }

    /// The poll loop: on each tick, initiate a scheduled rotation if the period elapsed,
    /// then refresh (which also adopts any out-of-band / on-demand rotation). Runs for the
    /// process lifetime; a provider blip logs and is retried on the next tick (the plane
    /// keeps serving the last-published signer + JWKS).
    pub(crate) async fn run(mut self) {
        let poll = Duration::from_secs(self.cfg.poll_secs.max(1));
        let mut last_rotation = now_secs();
        loop {
            sleep(poll).await;
            let now = now_secs();
            if let Some(period) = self.cfg.rotation_period_secs
                && now.saturating_sub(last_rotation) >= period
            {
                match self.provider.rotate().await {
                    Ok(()) => {
                        last_rotation = now;
                        info!("scheduled signing-key rotation triggered");
                    }
                    Err(e) => warn!(error = %e, "scheduled rotation failed -> will retry"),
                }
            }
            if let Err(e) = self.refresh(now).await {
                error!(error = %e, "signing-key refresh failed -> keeping last-published keys");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "tests unwrap on fixtures known to be valid"
    )]
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

    use identity_core::ContractClaims;

    use super::{RotationConfig, RotationManager};
    use crate::keyprovider::{FakeKeyProvider, KeyProvider as _};
    use crate::signer::{MintInput, Signer};
    use std::sync::Arc;

    const ISSUER: &str = "https://identity.nexus";
    const AUD: &str = "evenout";
    const TTL: u64 = 60;
    const OVERLAP: u64 = 120; // ttl + a 60s skew budget

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn cfg() -> RotationConfig {
        RotationConfig {
            issuer: ISSUER.to_owned(),
            contract_version: "v1".to_owned(),
            ttl_secs: TTL,
            overlap_secs: OVERLAP,
            rotation_period_secs: None,
            poll_secs: 30,
        }
    }

    fn mint(signer: &Signer) -> String {
        signer
            .mint(&MintInput {
                sub: "user-1",
                aud: AUD,
                principal_kind: "user",
                on_behalf_of: None,
                workspace_id: "ws-1",
                member_type: Some("staff"),
                role: Some("admin"),
                roles: &[],
                permissions: &[],
                plan: None,
                entitlements: None,
                suspended: None,
                now: now_secs(),
            })
            .unwrap()
    }

    /// Does `token` verify against the published `jwks` (kid selected, signature +
    /// iss/aud checked)? The exact box-side verification path.
    fn verifies(jwks_json: &str, token: &str) -> bool {
        let jwks: JwkSet = serde_json::from_str(jwks_json).unwrap();
        let Ok(header) = decode_header(token) else { return false };
        let Some(kid) = header.kid else { return false };
        let Some(jwk) = jwks.find(&kid) else { return false };
        let key = DecodingKey::from_jwk(jwk).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[AUD]);
        validation.set_issuer(&[ISSUER]);
        decode::<ContractClaims>(token, &key, &validation).is_ok()
    }

    fn published_kids(jwks_json: &str) -> Vec<String> {
        let value: serde_json::Value = serde_json::from_str(jwks_json).unwrap();
        let mut kids: Vec<String> = value["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|jwk| jwk["kid"].as_str().unwrap().to_owned())
            .collect();
        kids.sort();
        kids
    }

    #[tokio::test]
    async fn rotation_publishes_both_keys_and_a_token_from_either_verifies() {
        // Task 1.6: during the overlap, both keys are published and a token signed by
        // EITHER the old or the new key verifies — no in-flight token is rejected.
        let provider = Arc::new(FakeKeyProvider::with_one_key());
        let (mut manager, handles) = RotationManager::bootstrap(provider.clone(), cfg())
            .await
            .unwrap();
        // The pre-rotation signer, captured before cut-over so we can prove ITS tokens
        // still verify after the rotation.
        let old_signer = handles.signer_rx.borrow().clone();
        let old_token = mint(&old_signer);

        // Rotate at the source, then refresh at t0 (well inside the overlap window).
        provider.rotate().await.unwrap();
        let t0 = now_secs();
        manager.refresh(t0).await.unwrap();

        let new_signer = handles.signer_rx.borrow().clone();
        let new_token = mint(&new_signer);
        let jwks = handles.jwks_rx.borrow().as_str().to_owned();

        assert_eq!(
            published_kids(&jwks),
            vec!["fake-v1".to_owned(), "fake-v2".to_owned()],
            "both the retiring and the active key are published during overlap"
        );
        assert!(verifies(&jwks, &old_token), "a token from the OLD key still verifies");
        assert!(verifies(&jwks, &new_token), "a token from the NEW key verifies");
    }

    #[tokio::test]
    async fn old_key_is_retired_only_after_the_overlap_window() {
        // Task 1.3/1.6: the rotated-away key stays published until ttl+skew has elapsed,
        // then drops. Retirement is never premature (which would reject in-flight tokens).
        let provider = Arc::new(FakeKeyProvider::with_one_key());
        let (mut manager, handles) = RotationManager::bootstrap(provider.clone(), cfg())
            .await
            .unwrap();
        provider.rotate().await.unwrap();
        let t0 = now_secs();
        manager.refresh(t0).await.unwrap();

        // Just before the window closes: the old key is STILL published.
        manager.refresh(t0 + OVERLAP - 1).await.unwrap();
        assert!(
            published_kids(&handles.jwks_rx.borrow()).contains(&"fake-v1".to_owned()),
            "the old key must stay published for the full overlap window"
        );

        // At the window boundary: the old key is retired and dropped from the JWKS.
        manager.refresh(t0 + OVERLAP).await.unwrap();
        assert_eq!(
            published_kids(&handles.jwks_rx.borrow()),
            vec!["fake-v2".to_owned()],
            "after ttl+skew only the active key remains published"
        );
    }

    #[tokio::test]
    async fn kid_and_jwks_stay_consistent_across_a_rotation() {
        // Task 1.6: the active signer's kid is ALWAYS present in the published JWKS —
        // there is no hand-sync step, so the signer and the key set never drift.
        let provider = Arc::new(FakeKeyProvider::with_one_key());
        let (mut manager, handles) = RotationManager::bootstrap(provider.clone(), cfg())
            .await
            .unwrap();

        for _ in 0..3 {
            let token = mint(&handles.signer_rx.borrow().clone());
            let header = decode_header(&token).unwrap();
            let kid = header.kid.unwrap();
            assert!(
                published_kids(&handles.jwks_rx.borrow()).contains(&kid),
                "the active signer's kid must be published in the JWKS"
            );
            assert!(verifies(&handles.jwks_rx.borrow(), &token), "the active token verifies");
            provider.rotate().await.unwrap();
            manager.refresh(now_secs()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn on_demand_rotation_is_adopted_on_the_next_refresh() {
        // Task 1.3 (on-demand / suspected compromise): an out-of-band rotation at the
        // source is picked up by the plane's next refresh — a NEW kid becomes active and
        // is published, with no hand-editing.
        let provider = Arc::new(FakeKeyProvider::with_one_key());
        let (mut manager, handles) = RotationManager::bootstrap(provider.clone(), cfg())
            .await
            .unwrap();
        let before = decode_header(&mint(&handles.signer_rx.borrow().clone()))
            .unwrap()
            .kid
            .unwrap();

        // An operator rotates the key directly at the source (compromise response).
        provider.rotate().await.unwrap();
        manager.refresh(now_secs()).await.unwrap();

        let after = decode_header(&mint(&handles.signer_rx.borrow().clone()))
            .unwrap()
            .kid
            .unwrap();
        assert_ne!(before, after, "the plane adopts the new active key on refresh");
        assert!(
            published_kids(&handles.jwks_rx.borrow()).contains(&after),
            "the new active key is published"
        );
    }

    #[tokio::test]
    async fn bootstrap_fails_when_the_provider_is_unreachable() {
        // Task 1.6: an unreachable provider yields no signer at startup, so bootstrap
        // errors — main then falls back to the break-glass PEM (fail loud, never unsigned).
        let provider = Arc::new(FakeKeyProvider::unreachable());
        let result = RotationManager::bootstrap(provider, cfg()).await;
        assert!(result.is_err(), "an unreachable provider must fail bootstrap so main can fall back");
    }

    /// Task 2.2 — end-to-end against a LIVE OpenBao (the real `vaultrs` Transit adapter,
    /// not the fake). Skipped unless `TEST_BAO_ADDR` is set, so `cargo test` stays green in
    /// CI without a server. Requires the Transit key provisioned per the runbook
    /// (`transit/keys/identity-contract-signing`, `ecdsa-p256`, `exportable=true`).
    ///
    /// Run it:
    ///   docker compose --profile signing up -d openbao   # or any dev OpenBao on :8200
    ///   TEST_BAO_ADDR=http://127.0.0.1:8200 TEST_BAO_TOKEN=root \
    ///     cargo test -p identity-sidecar --  rotation::tests::live_transit --nocapture
    ///
    /// It proves the real adapter's wire path: bootstrap builds a working signer + JWKS
    /// from Transit's exported material, a rotation publishes BOTH keys and a token from
    /// either verifies during the overlap, and the old key drops only after the window.
    #[tokio::test]
    async fn live_transit_rotation_publishes_both_and_retires_after_overlap() {
        use std::env;

        use rustls::crypto::ring;

        use crate::keyprovider::KeyProvider;
        use crate::transit::TransitKeyProvider;

        // Skipped silently unless TEST_BAO_ADDR is set, so CI stays green without a server.
        let Ok(address) = env::var("TEST_BAO_ADDR") else {
            return;
        };
        // main() installs this in production (vaultrs uses rustls-no-provider); the test
        // harness never runs main(), so install the ring provider here too.
        drop(ring::default_provider().install_default());
        let token = env::var("TEST_BAO_TOKEN").unwrap_or_else(|_| "root".to_owned());
        let key_name = "identity-contract-signing".to_owned();

        // The real vaultrs Transit adapter (Mode B). Keep the concrete Arc so we can
        // `rotate()` it directly, and hand an upcast clone to the rotation manager.
        let provider = Arc::new(
            TransitKeyProvider::new(address, token, "transit".to_owned(), key_name)
                .expect("build Transit provider"),
        );
        let dyn_provider: Arc<dyn KeyProvider> = provider.clone();

        // Bootstrap: exercises public_versions (public PEM -> JWK) + export_private_pem
        // (SEC1 PEM -> ES256 signer) against real Transit.
        let (mut manager, handles) = RotationManager::bootstrap(dyn_provider, cfg())
            .await
            .expect("bootstrap against live Transit");
        let old_signer = handles.signer_rx.borrow().clone();
        let old_token = mint(&old_signer);
        let old_kid = decode_header(&old_token).unwrap().kid.unwrap();
        assert!(
            verifies(&handles.jwks_rx.borrow(), &old_token),
            "a token signed with live Transit material verifies against the generated JWKS"
        );

        // Rotate at the source (the real Transit rotate call), then adopt it.
        provider.rotate().await.expect("Transit rotate");
        let t0 = now_secs();
        manager.refresh(t0).await.expect("refresh after live rotate");

        let new_token = mint(&handles.signer_rx.borrow().clone());
        let new_kid = decode_header(&new_token).unwrap().kid.unwrap();
        assert_ne!(new_kid, old_kid, "rotation cut the signer over to a new Transit version");
        let published = published_kids(&handles.jwks_rx.borrow());
        assert!(published.contains(&old_kid) && published.contains(&new_kid), "both keys published during overlap");
        assert!(verifies(&handles.jwks_rx.borrow(), &old_token), "the OLD Transit key still verifies in overlap");
        assert!(verifies(&handles.jwks_rx.borrow(), &new_token), "the NEW Transit key verifies");

        // After the overlap window the old key is retired and drops from the JWKS.
        manager.refresh(t0 + OVERLAP).await.expect("refresh past overlap");
        let retired = published_kids(&handles.jwks_rx.borrow());
        assert!(!retired.contains(&old_kid), "the old key is retired after ttl+skew");
        assert!(retired.contains(&new_kid), "the active key stays published");
    }
}
