//! identity-core — the language-agnostic identity domain, shared by the sidecar
//! (reads), the sync-worker (event writes), and the reconciler (authoritative
//! writes). Holding the Profile shape and the version/ordering guard in ONE
//! place is the invariant the rest of the system depends on (rules §2, §5).

pub mod membership;
pub mod profile;
pub mod reconcile;
pub mod store;
pub mod sync;

pub use membership::{
    Membership, MemberType, MembershipResolver, ResolvedMembership, SourceMembershipReader,
};
pub use profile::Profile;
