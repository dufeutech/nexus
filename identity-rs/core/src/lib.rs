//! identity-core — the language-agnostic identity domain, shared by the sidecar
//! (reads), the membership-sync worker (membership projection writes), and the
//! authz-admin surface (authorization authoring writes). Holding the Profile shape
//! and the authorization ports in ONE place is the invariant the rest of the system
//! depends on (rules §2, §5).
//!
//! The OIDC provider answers "who am I" (authentication + basic profile); nexus
//! answers "what may I do here" (authorization). Authorization is nexus-authored
//! behind the [`AuthzResolver`] / [`AuthzAuthoring`] ports — never sourced from the
//! provider (`nexus-native-authorization` spec).

pub mod api_key;
pub mod authz;
pub mod contract;
pub mod membership;
pub mod platform;
pub mod principal;
pub mod profile;
pub mod projection;
pub mod store;
pub mod telemetry;

pub use api_key::{
    ApiKeyCandidate, ApiKeyReader, ApiKeyScope, ScopeIntersectionResolver, SecretHasher,
};
pub use authz::{AuthzAuthoring, AuthzFacts, AuthzResolver};
pub use contract::{ContractClaims, ContractSigner, SignError};
pub use membership::{
    Membership, MemberType, MembershipResolver, ResolvedMembership, SourceMembershipReader,
};
pub use platform::{PlatformService, PlatformServiceReader};
pub use principal::{Authority, PlatformScope, Principal, PrincipalKind};
pub use profile::Profile;
pub use projection::{backstop_pass, sync_subject, BackstopStats};
