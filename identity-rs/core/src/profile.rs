//! The canonical Profile — the single definition shared by the sidecar (reads),
//! the membership-sync worker (membership projection writes), and the authz-admin
//! surface (authorization authoring writes). Field identifiers are normalized lower
//! `snake_case` (RFC §3.8); mapping from the provider's casing happens at the
//! boundary.
//!
//! Authorization fields (`roles`, `entitlements`, `is_suspended`) are
//! **nexus-authored and authoritative** — never sourced from the token or the OIDC
//! provider (`nexus-native-authorization` spec). In Model 1 the Profile is the
//! nexus-native authorization store; the [`crate::AuthzResolver`] /
//! [`crate::AuthzAuthoring`] ports read/write them so a future engine is an adapter
//! swap.

use serde::{Deserialize, Serialize};

use crate::membership::{Membership, ResolvedMembership};

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct Profile {
    #[serde(default)]
    pub sub: String,
    /// The subject's home organization, denormalized for display/context only.
    /// **Informational — NEVER an authorization input**: it does not influence
    /// [`Profile::resolve_membership`] or the emitted acting scope (the `x-user-org`
    /// authz signal was retired). See `identity-workspace-authz` spec.
    #[serde(default)]
    pub home_org: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub preferred_language: Option<String>,
    /// Nexus-authored global roles (spec R1). Authored ONLY via [`crate::AuthzAuthoring`];
    /// never from the token or the provider.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Nexus-authored global entitlements (spec R1).
    #[serde(default)]
    pub entitlements: Vec<String>,
    /// Whether nexus has suspended the subject (spec R1). Revocation-sensitive: the
    /// sidecar sources it live so a suspension denies within seconds (spec R3).
    #[serde(default)]
    pub is_suspended: bool,
    /// The user's typed workspace memberships (staff|customer + role),
    /// denormalized here so the identity plane resolves the acting workspace in a
    /// single `sub`-keyed lookup. A user belongs to few workspaces, so this stays
    /// small. This is the v1 backing for the `MembershipResolver` port.
    #[serde(default)]
    pub memberships: Vec<Membership>,
    /// Monotonic per-key version derived from the authoritative change marker
    /// (RFC §3.3). A write with an older version MUST NOT overwrite a newer one.
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub updated_at: Option<String>,
}

impl Profile {
    /// Resolve this subject's authorized membership of `workspace_id`, if any —
    /// the v1 (denormalized) resolution the [`crate::MembershipResolver`] port
    /// delegates to. **Fail-closed:** `None` means "not an authorized member" of
    /// that workspace. First matching membership wins (one row per workspace).
    #[must_use]
    pub fn resolve_membership(&self, workspace_id: &str) -> Option<ResolvedMembership> {
        self.memberships
            .iter()
            .find(|m| m.workspace_id == workspace_id)
            .map(|m| ResolvedMembership {
                workspace_id: m.workspace_id.clone(),
                member_type: m.member_type,
                role: m.role.clone(),
            })
    }

    /// Return this profile with its membership projection replaced by the
    /// source-of-record `memberships`, preserving every other field. This is the
    /// single convergence point for the projection: both the real-time consumer and
    /// the reconcile backstop call it, so an identity-attribute write never clobbers
    /// memberships and a membership write never touches identity fields.
    #[must_use]
    pub fn with_memberships(mut self, memberships: Vec<Membership>) -> Self {
        self.memberships = memberships;
        self
    }

    /// Return this profile with its nexus-authored authorization facts (roles,
    /// entitlements, suspension) replaced, preserving every other field. The
    /// no-clobber convergence point for the authz-authoring writer, mirroring
    /// [`Profile::with_memberships`]: an authorization write never touches memberships
    /// or display identity, and a membership/identity write never touches authz. So
    /// the three writers (authz authoring + membership projection + identity display)
    /// converge on the same document without clobbering each other.
    #[must_use]
    pub fn with_authz(
        mut self,
        roles: Vec<String>,
        entitlements: Vec<String>,
        is_suspended: bool,
    ) -> Self {
        self.roles = roles;
        self.entitlements = entitlements;
        self.is_suspended = is_suspended;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::MemberType;

    fn member(ws: &str, t: MemberType, role: &str) -> Membership {
        Membership {
            workspace_id: ws.to_owned(),
            member_type: t,
            role: role.to_owned(),
            entitlements: Vec::new(),
        }
    }

    #[test]
    fn resolves_the_matching_workspace_membership() {
        let p = Profile {
            sub: "u1".into(),
            memberships: vec![
                member("ws-a", MemberType::Staff, "admin"),
                member("ws-b", MemberType::Customer, "pro"),
            ],
            ..Default::default()
        };
        let a = p.resolve_membership("ws-a").expect("member of ws-a");
        assert_eq!(a.member_type, MemberType::Staff);
        assert_eq!(a.role, "admin");
        // Same subject, different capacity per workspace (typed, workspace-scoped).
        let b = p.resolve_membership("ws-b").expect("member of ws-b");
        assert_eq!(b.member_type, MemberType::Customer);
        assert_eq!(b.role, "pro");
    }

    #[test]
    fn non_member_resolves_to_none_fail_closed() {
        let p = Profile {
            sub: "u1".into(),
            memberships: vec![member("ws-a", MemberType::Staff, "admin")],
            ..Default::default()
        };
        assert!(p.resolve_membership("ws-unknown").is_none());
        // A profile with no memberships is a member of nothing.
        assert!(Profile::default().resolve_membership("ws-a").is_none());
    }

    #[test]
    fn member_type_wire_values_are_stable() {
        assert_eq!(MemberType::Staff.as_str(), "staff");
        assert_eq!(MemberType::Customer.as_str(), "customer");
    }

    #[test]
    fn home_org_never_affects_resolution() {
        // home_org is informational: it must not grant a workspace, and must not
        // change the scope resolved from an actual membership.
        let non_member = Profile {
            sub: "u1".into(),
            home_org: Some("org-home".into()),
            ..Default::default()
        };
        assert!(non_member.resolve_membership("org-home").is_none());
        assert!(non_member.resolve_membership("ws-a").is_none());

        let member = Profile {
            sub: "u1".into(),
            home_org: Some("org-home".into()),
            memberships: vec![member("ws-a", MemberType::Customer, "pro")],
            ..Default::default()
        };
        let r = member.resolve_membership("ws-a").expect("member of ws-a");
        assert_eq!(r.member_type, MemberType::Customer);
        assert_eq!(r.role, "pro");
    }

    #[test]
    fn with_memberships_replaces_only_memberships() {
        let base = Profile {
            sub: "u1".into(),
            home_org: Some("org-home".into()),
            username: Some("alice".into()),
            roles: vec!["admin".into()],
            memberships: vec![member("ws-old", MemberType::Staff, "owner")],
            version: 7,
            ..Default::default()
        };
        let merged = base
            .clone()
            .with_memberships(vec![member("ws-a", MemberType::Customer, "pro")]);
        // Memberships swapped to the source-of-record set...
        assert_eq!(merged.memberships.len(), 1);
        assert_eq!(merged.memberships[0].workspace_id, "ws-a");
        // ...every other field preserved unchanged.
        assert_eq!(merged.home_org, base.home_org);
        assert_eq!(merged.username, base.username);
        assert_eq!(merged.roles, base.roles);
        assert_eq!(merged.version, base.version);
    }

    #[test]
    fn with_authz_replaces_only_authz_facts() {
        let base = Profile {
            sub: "u1".into(),
            home_org: Some("org-home".into()),
            username: Some("alice".into()),
            roles: vec!["old-role".into()],
            entitlements: vec!["old-ent".into()],
            is_suspended: false,
            memberships: vec![member("ws-a", MemberType::Staff, "owner")],
            version: 7,
            ..Default::default()
        };
        let merged = base.clone().with_authz(
            vec!["admin".into()],
            vec!["pro".into()],
            true,
        );
        // Authz facts swapped to the newly authored set...
        assert_eq!(merged.roles, vec!["admin".to_owned()]);
        assert_eq!(merged.entitlements, vec!["pro".to_owned()]);
        assert!(merged.is_suspended);
        // ...memberships + display identity + version preserved (no clobber).
        assert_eq!(merged.memberships, base.memberships);
        assert_eq!(merged.home_org, base.home_org);
        assert_eq!(merged.username, base.username);
        assert_eq!(merged.version, base.version);
    }

    #[test]
    fn with_memberships_empty_clears_membership_projection() {
        // Revoke-all: an empty source-of-record set removes every membership.
        let p = Profile {
            sub: "u1".into(),
            memberships: vec![member("ws-a", MemberType::Staff, "admin")],
            ..Default::default()
        }
        .with_memberships(Vec::new());
        assert!(p.memberships.is_empty());
        assert!(p.resolve_membership("ws-a").is_none());
    }
}
