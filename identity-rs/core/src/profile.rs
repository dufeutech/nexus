//! The canonical Profile — the single definition shared by the sidecar (reads),
//! the sync-worker (writes from change events), and the reconciler (writes from
//! the authoritative list). Field identifiers are normalized lower `snake_case`
//! (RFC §3.8); mapping from the provider's casing happens at the boundary.

use serde::{Deserialize, Serialize};

use crate::membership::{Membership, ResolvedMembership};

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct Profile {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub org_id: Option<String>,
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
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub entitlements: Vec<String>,
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
}
