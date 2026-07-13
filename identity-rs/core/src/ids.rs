//! Server-minted typed identifiers for the identity plane's OWN records.
//!
//! Deliberately narrow: nexus never mints ACTOR identity here — subjects
//! (`sub`) come from the IdP and api-key ids are random handles
//! (`api_keys::generate_credential`). The only typed, time-ordered id this
//! plane mints is the admin audit EVENT id, following the platform convention
//! (`ws_`/`acct_`/`aev_` + UUIDv7, docs/tenancy-and-identity.md): the prefix
//! makes the kind evident from the string alone, and UUIDv7's lexicographic
//! order IS event-time order. Twin of `router_core::ids` — the convention, not
//! a shared crate, is the contract (admin-action-audit D3). The generator
//! crate is confined to this module.

use uuid::Uuid;

/// Typed prefix carried by every admin audit event id (admin-action-audit D3).
pub const AUDIT_EVENT_ID_PREFIX: &str = "aev_";

/// Mint a fresh admin audit event id (`aev_<uuidv7>`): self-describing in logs
/// and exports, and lexicographically time-ordered so the ledger's id order IS
/// its event order. `Uuid::now_v7()` guarantees in-process monotonic ordering
/// (uuid ≥ 1.9 keeps a counter behind a static context), so successive mints
/// sort by creation time even within one millisecond.
#[must_use]
pub fn mint_audit_event_id() -> String {
    let generated = Uuid::now_v7();
    format!("{AUDIT_EVENT_ID_PREFIX}{generated}")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{mint_audit_event_id, AUDIT_EVENT_ID_PREFIX};

    #[test]
    fn minted_ids_carry_their_typed_prefix() {
        assert!(
            mint_audit_event_id().starts_with(AUDIT_EVENT_ID_PREFIX),
            "audit event ids must be self-describing"
        );
    }

    #[test]
    fn successive_mints_are_unique_and_time_ordered() {
        let minted: BTreeSet<String> = (0..1000).map(|_| mint_audit_event_id()).collect();
        assert_eq!(minted.len(), 1000, "every mint must be distinct");
        let earlier = mint_audit_event_id();
        let later = mint_audit_event_id();
        assert!(earlier < later, "aev_ ids must sort by mint order: {earlier} !< {later}");
    }
}
