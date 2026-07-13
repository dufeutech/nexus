//! The caller-supplied idempotency-key contract for provisioning creates
//! (provisioning-idempotency). The key is OPAQUE to nexus: the caller encodes
//! its flow semantics in the value (e.g. a broker keying signup provisioning by
//! subject) and nexus derives no policy from it — it is only the replay guard
//! the store's unique constraint enforces. This module owns the one validation
//! bound both admin handlers share (rules §5: a single source of truth, next to
//! the concept that owns it).

use std::fmt;

/// Longest accepted key, in bytes. A deliberately boring bound: generous enough
/// for any namespaced caller scheme (`signup:<sub>`), small enough to index.
pub const IDEMPOTENCY_KEY_MAX_BYTES: usize = 128;

/// Why a caller-supplied idempotency key was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidKey {
    /// Present but empty — an empty replay guard guards nothing.
    Empty,
    /// Longer than [`IDEMPOTENCY_KEY_MAX_BYTES`].
    TooLong,
    /// Contains bytes outside visible ASCII — keys appear in logs/errors and
    /// must be safe to print and compare byte-for-byte.
    NotVisibleAscii,
}

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty"),
            Self::TooLong => write!(f, "longer than {IDEMPOTENCY_KEY_MAX_BYTES} bytes"),
            Self::NotVisibleAscii => write!(f, "not visible ASCII"),
        }
    }
}

/// Validate a caller-supplied idempotency key: non-empty, bounded, visible
/// ASCII (0x21–0x7E). Absence of a key is valid by definition (replay
/// protection is opt-in) — this checks only a key that was supplied.
pub fn validate_key(key: &str) -> Result<(), InvalidKey> {
    if key.is_empty() {
        return Err(InvalidKey::Empty);
    }
    if key.len() > IDEMPOTENCY_KEY_MAX_BYTES {
        return Err(InvalidKey::TooLong);
    }
    if !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(InvalidKey::NotVisibleAscii);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_key, InvalidKey, IDEMPOTENCY_KEY_MAX_BYTES};

    #[test]
    fn accepts_a_namespaced_caller_key() {
        assert_eq!(validate_key("signup:auth0|68f1c2"), Ok(()), "the canonical broker shape");
    }

    #[test]
    fn rejects_empty_and_oversized_and_unprintable() {
        assert_eq!(validate_key(""), Err(InvalidKey::Empty), "empty guards nothing");
        assert_eq!(
            validate_key(&"k".repeat(IDEMPOTENCY_KEY_MAX_BYTES.saturating_add(1))),
            Err(InvalidKey::TooLong),
            "over the documented bound"
        );
        assert_eq!(
            validate_key("has space"),
            Err(InvalidKey::NotVisibleAscii),
            "space is not visible ASCII"
        );
        assert_eq!(
            validate_key("ctrl\nchar"),
            Err(InvalidKey::NotVisibleAscii),
            "control characters are rejected"
        );
    }

    #[test]
    fn the_bound_itself_is_accepted() {
        assert_eq!(
            validate_key(&"k".repeat(IDEMPOTENCY_KEY_MAX_BYTES)),
            Ok(()),
            "exactly the bound is valid"
        );
    }
}
