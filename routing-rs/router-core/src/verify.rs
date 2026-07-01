//! Domain ownership proof (RFC C4 / N2b) — the abstract proof port plus the pure
//! helpers that derive the challenge name and match a published proof against a
//! minted token. The concrete name-resolution mechanism is an adapter (rules §2,
//! §5); core only states the capability and the deterministic matching rule.

use async_trait::async_trait;
use subtle::ConstantTimeEq;

use crate::store::BoxError;

/// The label under which a tenant publishes the ownership-proof record. A
/// *subdomain* label so it coexists with an apex alias record (RFC C4). Pure and
/// deterministic — the same domain always yields the same challenge name.
#[must_use]
pub fn challenge_name(domain: &str) -> String {
    format!("_nexus-challenge.{domain}")
}

/// Whether any published proof record carries the expected token. Pure, total,
/// deterministic: trims surrounding whitespace, requires an exact value match —
/// no substring or prefix acceptance (RFC C4: the proof must be the token).
/// The per-record comparison is constant-time in the token bytes (defense in
/// depth — the token is a server-minted secret, even though it is compared
/// against attacker-published DNS).
#[must_use]
pub fn token_matches(records: &[String], token: &str) -> bool {
    !token.is_empty() && records.iter().any(|r| ct_eq(r.trim(), token))
}

/// Constant-time byte-equality, backed by the vetted `subtle` crate
/// (`ConstantTimeEq`) rather than a hand-rolled loop. Length is not secret here
/// (token lengths are fixed and known), so `subtle`'s early length-mismatch
/// return is fine; the byte comparison itself carries no data-dependent branch.
/// Shared by the ownership-proof match and the control-plane admin-token check
/// (both compare a server-minted secret).
#[must_use]
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Resolve the ownership-proof records published at a name (RFC C4). Implemented
/// by an adapter against a concrete naming system.
///
/// Contract: an empty vector means "looked up, found no proof" (the domain stays
/// pending — not an error). An `Err` means a *transient* resolution failure; the
/// caller MUST keep the domain pending and retry later, never treat it as a
/// disproof. Fail-closed: the absence of a match never verifies a domain.
#[async_trait]
pub trait OwnershipProof: Send + Sync {
    async fn txt_records(&self, name: &str) -> Result<Vec<String>, BoxError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_name_is_a_subdomain_label() {
        assert_eq!(challenge_name("acme.example"), "_nexus-challenge.acme.example");
    }

    #[test]
    fn matches_exact_token_only() {
        let recs = vec!["  tok123  ".to_owned(), "other".to_owned()];
        assert!(token_matches(&recs, "tok123")); // trimmed exact match
        assert!(!token_matches(&recs, "tok")); // no prefix acceptance
        assert!(!token_matches(&recs, "")); // empty token never matches
        assert!(!token_matches(&[], "tok123")); // no records -> no match
    }
}
