//! The normalized Principal (`principal-model` capability) — the single, uniform
//! identity shape every authenticator produces and every authorizer consumes.
//!
//! WHAT, not HOW: authentication varies by trust boundary (human OIDC, core-service
//! infra trust, later API keys), but it ALWAYS yields one [`Principal`]; authorization
//! then operates on the principal alone, blind to how the caller authenticated
//! (`principal-model` spec). The credential-verification mechanisms live behind the
//! edge (`jwt_authn`) and the sidecar's authenticator chain — none of them appear here.
//!
//! Two orthogonal axes meet in a principal and MUST NOT be conflated (ADR-2):
//!   - [`PrincipalKind`] — WHAT authenticated (user / api key / service). An authN output.
//!   - [`crate::MemberType`] — a role-family WITHIN a workspace (staff / customer). An
//!     authz fact. A `service` is a kind, never a member type.
//!
//! A principal carries exactly one [`Authority`], selected by kind: a workspace-scoped
//! principal (user, api key, tenant service) resolves to [`Authority::Workspace`] from
//! live membership rows; a core platform service resolves to [`Authority::Platform`]
//! from the live platform registry (ADR-3). A verified credential that resolves to NO
//! authority is rejected — never admitted open (`principal-model` spec, fail-closed).

use serde::{Deserialize, Serialize};

use crate::membership::ResolvedMembership;

/// What authenticated — the principal kind, orthogonal to [`crate::MemberType`]
/// (ADR-2). Emitted as the `principal_kind` contract claim so a box can authorize on
/// kind (e.g. admit a service as a writer while gating a human by role). Wire values
/// are lowercase and stable.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    /// A human end-user (ZITADEL OIDC).
    User,
    /// A customer automation credential — a Personal Access Token. Defined now;
    /// wired by the `customer-api-keys` change (ADR-8), which resolves it to a
    /// [`Authority::Workspace`] bounded by the key's scopes.
    ApiKey,
    /// A core platform service authenticated by infrastructure-level trust (a K8s
    /// projected ServiceAccount token in prod; a dev-issuer stub in compose). Resolves
    /// to [`Authority::Platform`].
    Service,
}

impl PrincipalKind {
    /// The stable wire value carried in the `principal_kind` contract claim / header.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ApiKey => "apikey",
            Self::Service => "service",
        }
    }
}

/// A core platform service's platform-level authority: a **named-permission set**,
/// least-privilege (ADR-3), NOT a boolean god-mode. The service may perform only the
/// operations its permissions admit, even though those permissions apply across
/// workspaces. Resolved live from the platform registry so a revoke/permission change
/// takes effect within seconds (`platform-service-authz` spec).
///
/// The acting workspace is deliberately NOT part of the scope — a platform service
/// still acts on ONE workspace per request, taken from the trusted routing context
/// (`x-workspace-id`), never from the scope or the service itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlatformScope {
    /// The named permissions this service holds, e.g. `events:write`. Least-privilege:
    /// an operation whose permission is absent is refused even for a registered,
    /// authenticated service.
    pub permissions: Vec<String>,
}

impl PlatformScope {
    /// Construct a scope from a permission set.
    #[must_use]
    pub const fn new(permissions: Vec<String>) -> Self {
        Self { permissions }
    }

    /// Whether this scope admits `permission` (exact match). The least-privilege
    /// check a box maps its write door onto.
    #[must_use]
    pub fn allows(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }
}

/// The single authoritative authority a principal carries, selected by kind (ADR-3/4).
/// Resolution branches on the kind and produces exactly one of these; the mint guard
/// admits a principal only when it has one (`nexus-native-authorization` spec).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority {
    /// Workspace-scoped authority from a live membership row (user / api key / tenant
    /// service). Bounded to the workspace the membership names; never widened to
    /// platform scope.
    Workspace(ResolvedMembership),
    /// Platform-level authority from the live registry (core service). Cross-workspace,
    /// a least-privilege permission set — NOT membership rows.
    Platform(PlatformScope),
}

/// The normalized principal: one uniform shape produced by every authenticator and
/// consumed by every authorizer (`principal-model` spec). Its kind, subject, and
/// on-behalf-of are system-authored from the verified credential and nexus's own
/// resolution — NEVER caller-asserted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// What authenticated.
    pub kind: PrincipalKind,
    /// The subject identifying this principal: `sub` for a user, key-id for an api
    /// key, service-id for a service.
    pub subject: String,
    /// The subject this principal acts on behalf of, when it acts for someone else —
    /// an api key carries the creating user here for audit (populated by
    /// `customer-api-keys`; `None` for user/service).
    pub on_behalf_of: Option<String>,
    /// The resolved authority. Construction of a principal means an authority
    /// resolved; a credential that resolves to none is rejected before a principal is
    /// built (fail-closed).
    pub authority: Authority,
}

impl Principal {
    /// A human-user principal with a resolved workspace authority.
    #[must_use]
    pub const fn user(subject: String, membership: ResolvedMembership) -> Self {
        Self {
            kind: PrincipalKind::User,
            subject,
            on_behalf_of: None,
            authority: Authority::Workspace(membership),
        }
    }

    /// A core-service principal with a resolved platform authority.
    #[must_use]
    pub const fn service(subject: String, scope: PlatformScope) -> Self {
        Self {
            kind: PrincipalKind::Service,
            subject,
            on_behalf_of: None,
            authority: Authority::Platform(scope),
        }
    }

    /// An api-key principal with a resolved workspace authority and the creating user
    /// recorded for audit. Defined for the seam; wired by `customer-api-keys`.
    #[must_use]
    pub const fn api_key(
        subject: String,
        on_behalf_of: String,
        membership: ResolvedMembership,
    ) -> Self {
        Self {
            kind: PrincipalKind::ApiKey,
            subject,
            on_behalf_of: Some(on_behalf_of),
            authority: Authority::Workspace(membership),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, reason = "test assertions legitimately panic on the impossible branch")]
    use super::*;
    use crate::membership::MemberType;

    fn membership(ws: &str) -> ResolvedMembership {
        ResolvedMembership {
            workspace_id: ws.to_owned(),
            member_type: MemberType::Staff,
            role: "admin".to_owned(),
        }
    }

    #[test]
    fn kind_wire_values_are_stable() {
        assert_eq!(PrincipalKind::User.as_str(), "user");
        assert_eq!(PrincipalKind::ApiKey.as_str(), "apikey");
        assert_eq!(PrincipalKind::Service.as_str(), "service");
    }

    #[test]
    fn user_principal_carries_a_workspace_authority() {
        // Task 1.4: a user constructs with the Workspace authority variant and no
        // on-behalf-of.
        let p = Principal::user("u1".to_owned(), membership("ws-1"));
        assert_eq!(p.kind, PrincipalKind::User);
        assert_eq!(p.subject, "u1");
        assert!(p.on_behalf_of.is_none());
        match p.authority {
            Authority::Workspace(m) => assert_eq!(m.workspace_id, "ws-1"),
            Authority::Platform(_) => panic!("user must resolve to a Workspace authority"),
        }
    }

    #[test]
    fn service_principal_carries_a_platform_authority() {
        // Task 1.4: a service constructs with the Platform authority variant — a
        // least-privilege permission set, no membership.
        let p = Principal::service(
            "svc-events".to_owned(),
            PlatformScope::new(vec!["events:write".to_owned()]),
        );
        assert_eq!(p.kind, PrincipalKind::Service);
        assert_eq!(p.subject, "svc-events");
        assert!(p.on_behalf_of.is_none());
        match p.authority {
            Authority::Platform(scope) => {
                assert!(scope.allows("events:write"));
                assert!(!scope.allows("events:delete"), "least-privilege: only named perms");
            }
            Authority::Workspace(_) => panic!("service must resolve to a Platform authority"),
        }
    }

    #[test]
    fn api_key_principal_records_the_creating_user() {
        // Task 1.4: the apikey kind is defined now (wired later) and carries the
        // on-behalf-of subject for audit, over a Workspace authority.
        let p = Principal::api_key("key-7".to_owned(), "u1".to_owned(), membership("ws-9"));
        assert_eq!(p.kind, PrincipalKind::ApiKey);
        assert_eq!(p.subject, "key-7");
        assert_eq!(p.on_behalf_of.as_deref(), Some("u1"));
        assert!(matches!(p.authority, Authority::Workspace(_)));
    }

    #[test]
    fn principal_kind_is_orthogonal_to_member_type() {
        // ADR-2 / task 1.3: kind and member_type are different axes. A staff member
        // and a customer are both `user` kind; a service is `service` kind and holds
        // NO member type at all.
        let staff = Principal::user(
            "u1".to_owned(),
            ResolvedMembership {
                workspace_id: "ws".to_owned(),
                member_type: MemberType::Staff,
                role: "admin".to_owned(),
            },
        );
        let customer = Principal::user(
            "u2".to_owned(),
            ResolvedMembership {
                workspace_id: "ws".to_owned(),
                member_type: MemberType::Customer,
                role: "buyer".to_owned(),
            },
        );
        assert_eq!(staff.kind, PrincipalKind::User);
        assert_eq!(customer.kind, PrincipalKind::User);
        let service = Principal::service("svc".to_owned(), PlatformScope::default());
        assert_eq!(service.kind, PrincipalKind::Service);
        // The service's authority carries no member_type — it is a Platform authority.
        assert!(matches!(service.authority, Authority::Platform(_)));
    }
}
