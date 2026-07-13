//! Server-minted resource identifiers (workspace-tenancy: system-minted, typed
//! ids). Nexus mints every workspace/account id itself — callers never supply
//! them. An id is `<prefix><uuidv7>`: time-ordered and globally
//! collision-resistant (RFC 9562 UUIDv7), with a typed prefix so an id's kind
//! and origin are evident from the string alone in logs, errors, and downstream
//! systems (the prefix is the structural collision guard other systems inherit).
//! The generator crate is confined to this module — every other layer sees only
//! the mint functions and the prefix constants below.

use uuid::Uuid;

/// Typed prefix carried by every workspace id.
pub const WORKSPACE_ID_PREFIX: &str = "ws_";

/// Typed prefix carried by every account id.
pub const ACCOUNT_ID_PREFIX: &str = "acct_";

/// Mint a fresh workspace id (`ws_<uuidv7>`).
#[must_use]
pub fn mint_workspace_id() -> String {
    mint(WORKSPACE_ID_PREFIX)
}

/// Mint a fresh account id (`acct_<uuidv7>`).
#[must_use]
pub fn mint_account_id() -> String {
    mint(ACCOUNT_ID_PREFIX)
}

/// `Uuid::now_v7()` guarantees in-process monotonic ordering (uuid ≥ 1.9 keeps a
/// counter behind a static context), so successive mints sort by creation time
/// even within one millisecond.
fn mint(prefix: &str) -> String {
    let generated = Uuid::now_v7();
    format!("{prefix}{generated}")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{mint_account_id, mint_workspace_id, ACCOUNT_ID_PREFIX, WORKSPACE_ID_PREFIX};

    #[test]
    fn minted_ids_carry_their_typed_prefix() {
        assert!(
            mint_workspace_id().starts_with(WORKSPACE_ID_PREFIX),
            "workspace ids must be self-describing"
        );
        assert!(
            mint_account_id().starts_with(ACCOUNT_ID_PREFIX),
            "account ids must be self-describing"
        );
    }

    #[test]
    fn id_kinds_are_distinguishable_from_the_value_alone() {
        // The spec scenario: prefix alone identifies the resource kind.
        assert!(!mint_workspace_id().starts_with(ACCOUNT_ID_PREFIX), "kinds must not overlap");
        assert!(!mint_account_id().starts_with(WORKSPACE_ID_PREFIX), "kinds must not overlap");
    }

    #[test]
    fn successive_mints_are_unique() {
        let minted: BTreeSet<String> = (0..1000).map(|_| mint_workspace_id()).collect();
        assert_eq!(minted.len(), 1000, "every mint must be distinct");
    }

    #[test]
    fn successive_mints_are_time_ordered() {
        // UUIDv7's hyphenated form sorts lexicographically by creation instant,
        // and now_v7()'s counter keeps sub-millisecond mints monotonic too.
        let earlier = mint_workspace_id();
        let later = mint_workspace_id();
        assert!(earlier < later, "v7 ids must sort by mint order: {earlier} !< {later}");
    }
}
