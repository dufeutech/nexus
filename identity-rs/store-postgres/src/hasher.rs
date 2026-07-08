//! HMAC-SHA256 secret hasher — the adopted adapter behind `identity_core::SecretHasher`
//! (`customer-api-keys`, `/opsx:decide`). This is a CRYPTO adapter, not a DB one; it
//! lives in this shared adapter crate because BOTH the sidecar (verify/lookup a presented
//! secret) and authz-admin (hash a freshly-minted secret at issuance) need it, and both
//! already depend on this crate — core must stay crypto-free (design.md).
//!
//! Why a keyed HMAC and not a password hash (argon2/bcrypt): a PAT secret is a
//! **high-entropy random token**, so the offline-brute-force threat a password hash
//! defends against does not apply, and verification runs on the sidecar's per-request hot
//! path where argon2's deliberate CPU cost would hurt. HMAC-SHA256 is microseconds and,
//! being **deterministic**, lets the sidecar resolve a key with a single indexed lookup
//! by the hash — a per-row salt would forbid that. The server-side **pepper** (an HMAC
//! key from a secret, never in the DB) means a stolen database alone cannot brute-force
//! secrets. "Not hand-rolled": HMAC/SHA-256 are audited RustCrypto crates and the
//! post-lookup equality is `subtle`'s constant-time compare.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use identity_core::SecretHasher;

type HmacSha256 = Hmac<Sha256>;

/// A warm HMAC-SHA256 hasher keyed by a server-held pepper. Cheap to clone/share; holds
/// no per-secret state.
#[derive(Clone)]
pub struct HmacSecretHasher {
    pepper: Vec<u8>,
}

impl fmt::Debug for HmacSecretHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the pepper — it is a secret.
        f.debug_struct("HmacSecretHasher").finish_non_exhaustive()
    }
}

impl HmacSecretHasher {
    /// Build a hasher keyed by `pepper` (a server-held secret, e.g. `APIKEY_HMAC_PEPPER`).
    #[must_use]
    pub fn new(pepper: impl Into<Vec<u8>>) -> Self {
        Self { pepper: pepper.into() }
    }
}

impl SecretHasher for HmacSecretHasher {
    fn hash(&self, secret: &str) -> String {
        // HMAC accepts a key of ANY length, so `new_from_slice` is infallible for Hmac —
        // the RustCrypto docs guarantee it (the `InvalidLength` error is only ever
        // returned by fixed-key-size algorithms). expect documents that invariant.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.pepper)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(secret.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn verify(&self, secret: &str, stored: &str) -> bool {
        // Constant-time over the hex hashes: no early exit that could leak how much of a
        // rejected secret matched. (Length may differ, which is not secret.)
        self.hash(secret).as_bytes().ct_eq(stored.as_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic_and_hex_encoded() {
        let h = HmacSecretHasher::new(b"pepper".to_vec());
        let a = h.hash("nexus_pat_secret");
        let b = h.hash("nexus_pat_secret");
        assert_eq!(a, b, "the same secret must hash to the same value (indexable lookup)");
        // HMAC-SHA256 -> 32 bytes -> 64 hex chars, all lowercase hex.
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()), "hash must be hex");
    }

    #[test]
    fn different_secrets_and_peppers_diverge() {
        let h = HmacSecretHasher::new(b"pepper-1".to_vec());
        assert_ne!(h.hash("secret-a"), h.hash("secret-b"), "distinct secrets diverge");
        // The pepper is part of the key: the SAME secret under a different pepper is a
        // different hash, so a stolen DB without the pepper can't be replayed elsewhere.
        let other = HmacSecretHasher::new(b"pepper-2".to_vec());
        assert_ne!(h.hash("secret-a"), other.hash("secret-a"), "the pepper keys the hash");
    }

    #[test]
    fn verify_accepts_a_match_and_rejects_a_mismatch() {
        // Task 2.2: reject-on-mismatch + constant-time verify.
        let h = HmacSecretHasher::new(b"pepper".to_vec());
        let stored = h.hash("right-secret");
        assert!(h.verify("right-secret", &stored), "the minting secret must verify");
        assert!(!h.verify("wrong-secret", &stored), "a different secret must be rejected");
        assert!(!h.verify("right-secret", "deadbeef"), "a wrong stored hash must be rejected");
    }
}
