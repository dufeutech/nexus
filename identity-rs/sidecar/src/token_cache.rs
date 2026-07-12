//! In-process reuse cache for the signed `x-identity-contract` (hot-path-rps-optimization).
//!
//! WHY (design.md): on a cache-hit request the ES256 signature is the dominant per-request
//! CPU op. Two requests that resolve to an *identical* contract are cryptographically
//! interchangeable within a short window, so we sign once and reuse the token — turning
//! signing from once-per-request into once-per-(principal × window).
//!
//! Build-vs-adopt (decide gate): the tier is `moka` **in-process** — never Redis. The cost
//! avoided is a LOCAL sign (~tens of µs); a network cache round-trip would cost more than
//! re-signing, and sharing signed contracts through a store widens the credential blast
//! radius. `moka` is already the repo's adopted in-process cache.
//!
//! Safety invariants this module upholds (identity-contract-signing ADDED delta):
//!   - **Expiry-safe.** A cached token is reused only while its remaining validity clears a
//!     safety floor; otherwise it is re-minted. Reuse never serves an expired/near-expired
//!     contract even though `exp` is fixed at mint time.
//!   - **Rotation-safe (no flush race).** The active signer's `kid` is PART of the cache
//!     key. After a rotation cut-over the current signer's `kid` differs, so a post-rotation
//!     lookup misses and re-mints with the new key — a token signed by a superseded key is
//!     never served after cut-over, with no cross-thread flush window to get wrong.
//!   - **Freshness.** The key is the full set of contract-determining facts, so any fact
//!     change (membership/role/plan/suspension/entitlements) yields a different key and a
//!     fresh mint; staleness is bounded by the short reuse TTL (≤ the existing freshness
//!     envelope).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use moka::sync::Cache;

use identity_core::SignError;

use crate::signer::{MintInput, Signer};
use crate::state::METRICS;

/// The identity facts that fully determine a signed contract, EXCEPT the per-mint fields
/// (`jti`/`iat`/`exp`). Two requests with an equal key mint byte-identical claims, so one
/// signature serves both. List-valued claims are folded to a `u64` hash to bound key size;
/// they come from the same resolved `Profile`, so their order — and thus the hash — is
/// stable across a principal's requests. `kid` scopes every entry to the signing key that
/// produced it (rotation-safety, see module docs). `aud` is included, so a token is never
/// reused across destination boxes.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    kid: String,
    sub: String,
    aud: String,
    principal_kind: String,
    on_behalf_of: Option<String>,
    workspace_id: String,
    member_type: Option<String>,
    role: Option<String>,
    plan: Option<String>,
    suspended: Option<bool>,
    roles_hash: u64,
    permissions_hash: u64,
    entitlements_hash: u64,
}

impl CacheKey {
    fn build(kid: &str, input: &MintInput<'_>) -> Self {
        Self {
            kid: kid.to_owned(),
            sub: input.sub.to_owned(),
            aud: input.aud.to_owned(),
            principal_kind: input.principal_kind.to_owned(),
            on_behalf_of: input.on_behalf_of.map(str::to_owned),
            workspace_id: input.workspace_id.to_owned(),
            member_type: input.member_type.map(str::to_owned),
            role: input.role.map(str::to_owned),
            plan: input.plan.map(str::to_owned),
            suspended: input.suspended,
            roles_hash: hash_list(input.roles),
            permissions_hash: hash_list(input.permissions),
            // Option matters: `None` (profile unresolved) and `Some(&[])` (resolved, empty)
            // are DIFFERENT contracts — the discriminant is folded into the hash.
            entitlements_hash: hash_opt_list(input.entitlements),
        }
    }
}

fn hash_list(items: &[String]) -> u64 {
    let mut hasher = DefaultHasher::new();
    items.hash(&mut hasher);
    hasher.finish()
}

fn hash_opt_list(items: Option<&[String]>) -> u64 {
    let mut hasher = DefaultHasher::new();
    match items {
        None => 0_u8.hash(&mut hasher),
        Some(list) => {
            1_u8.hash(&mut hasher);
            list.hash(&mut hasher);
        }
    }
    hasher.finish()
}

/// A reused token plus the `exp` (epoch secs) it was minted with, so the expiry-safe floor
/// is enforced without re-parsing the compact JWT on every hit.
#[derive(Clone)]
struct CachedToken {
    token: String,
    exp: u64,
}

/// The reuse cache. Cheap to `Clone` (shares one `moka` inner), so it lives directly in
/// `AppState`. `None` in `AppState` means the cache is disabled (sign-per-request).
#[derive(Clone)]
pub(crate) struct ContractTokenCache {
    cache: Cache<CacheKey, CachedToken>,
    /// A cached token is reused only while `exp > now + min_remaining_secs`. Guarantees an
    /// expiry-safe reuse even if the reuse TTL is ever set close to the contract TTL.
    min_remaining_secs: u64,
}

impl ContractTokenCache {
    /// Build a cache with a bounded capacity and a reuse window (`time_to_live`). The
    /// window MUST be ≪ the contract TTL; `min_remaining_secs` is the extra expiry floor.
    pub(crate) fn new(max_capacity: u64, reuse_window: Duration, min_remaining_secs: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(reuse_window)
                .build(),
            min_remaining_secs,
        }
    }

    /// Return a reusable signed contract for `input`, minting (and caching) one on a miss or
    /// when the cached token is too close to expiry. `now` is injected (epoch secs) for
    /// testability and to decouple the expiry check from `moka`'s wall-clock TTL.
    ///
    /// # Errors
    /// Propagates [`SignError`] from a mint on a miss (the caller treats it as fail-closed:
    /// no token stamped → the box rejects the request).
    pub(crate) fn get_or_mint(
        &self,
        signer: &Signer,
        input: &MintInput<'_>,
        now: u64,
    ) -> Result<String, SignError> {
        let key = CacheKey::build(signer.kid(), input);
        if let Some(entry) = self.cache.get(&key)
            && entry.exp > now.saturating_add(self.min_remaining_secs)
        {
            METRICS.contract_cache_hits.add(1, &[]);
            return Ok(entry.token);
        }
        // Miss, or a hit too close to expiry: mint a fresh token and (re)cache it.
        let token = signer.mint(input)?;
        let exp = input.now.saturating_add(signer.ttl_secs());
        self.cache.insert(key, CachedToken { token: token.clone(), exp });
        METRICS.contract_cache_mints.add(1, &[]);
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "tests unwrap on fixtures known to be valid"
    )]
    use super::*;

    const TEST_PEM: &str = include_str!("testdata/test-ec-p256.pem");
    const ISSUER: &str = "https://identity.nexus";

    fn signer_with_kid(kid: &str) -> Signer {
        Signer::from_pem(TEST_PEM.as_bytes(), kid.to_owned(), ISSUER.to_owned(), "v1".to_owned(), 60)
            .unwrap()
    }

    /// A full mint input for `sub`, plan `plan`; all other facts fixed.
    fn input<'a>(sub: &'a str, plan: Option<&'a str>, now: u64) -> MintInput<'a> {
        MintInput {
            sub,
            aud: "evenout",
            principal_kind: "user",
            on_behalf_of: None,
            workspace_id: "ws-1",
            member_type: Some("staff"),
            role: Some("admin"),
            roles: &[],
            permissions: &[],
            plan,
            entitlements: None,
            suspended: None,
            now,
        }
    }

    fn cache() -> ContractTokenCache {
        // Reuse window far larger than the test's simulated elapsed time, so `moka` never
        // evicts mid-test; the expiry check is driven by the injected `now` instead.
        ContractTokenCache::new(1000, Duration::from_mins(5), 5)
    }

    #[test]
    fn identical_facts_reuse_one_signed_token() {
        // The core win: two requests with identical facts get the SAME token. A fresh mint
        // would carry a different per-request `jti`, so equal tokens prove reuse (a skipped
        // signature), not two independent signs.
        let signer = signer_with_kid("k1");
        let cache = cache();
        let first = cache.get_or_mint(&signer, &input("user-1", None, 1000), 1000).unwrap();
        let second = cache.get_or_mint(&signer, &input("user-1", None, 1001), 1001).unwrap();
        assert_eq!(first, second, "identical facts within the window reuse one signed token");
    }

    #[test]
    fn a_changed_fact_mints_a_fresh_token() {
        // A fact change (here: the plan) yields a different key → a fresh mint, so a stale
        // contract carrying the old facts is never served.
        let signer = signer_with_kid("k1");
        let cache = cache();
        let free = cache.get_or_mint(&signer, &input("user-1", None, 1000), 1000).unwrap();
        let pro = cache.get_or_mint(&signer, &input("user-1", Some("pro"), 1000), 1000).unwrap();
        assert_ne!(free, pro, "a changed fact must mint a new contract, not reuse the old one");
    }

    #[test]
    fn different_subjects_do_not_share_a_token() {
        let signer = signer_with_kid("k1");
        let cache = cache();
        let a = cache.get_or_mint(&signer, &input("user-1", None, 1000), 1000).unwrap();
        let b = cache.get_or_mint(&signer, &input("user-2", None, 1000), 1000).unwrap();
        assert_ne!(a, b, "distinct principals must never share a contract");
    }

    #[test]
    fn a_token_near_expiry_is_re_minted_not_served() {
        // Expiry-safe reuse: minted at now=1000 (exp=1060). A later request at now=1058 has
        // only 2s remaining (< the 5s floor), so the cache re-mints rather than serve a
        // contract about to expire. The fresh token differs (new iat/jti).
        let signer = signer_with_kid("k1");
        let cache = cache();
        let fresh = cache.get_or_mint(&signer, &input("user-1", None, 1000), 1000).unwrap();
        let near_expiry = cache.get_or_mint(&signer, &input("user-1", None, 1058), 1058).unwrap();
        assert_ne!(fresh, near_expiry, "a token within the expiry floor must be re-minted");
    }

    #[test]
    fn a_rotated_signing_key_is_never_reused_across_the_cut_over() {
        // Rotation-safety without a flush race: the same facts signed under a new kid produce
        // a different key, so the post-rotation request mints with the new key instead of
        // reusing the superseded-key token. The two tokens differ (different kid + signature).
        let cache = cache();
        let before = cache.get_or_mint(&signer_with_kid("k1"), &input("user-1", None, 1000), 1000).unwrap();
        let after = cache.get_or_mint(&signer_with_kid("k2"), &input("user-1", None, 1000), 1000).unwrap();
        assert_ne!(before, after, "a token signed by a superseded key must not be reused after rotation");
    }
}
