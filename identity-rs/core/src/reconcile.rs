//! Authoritative-user → Profile mapping and drift comparison (RFC C8).
//! Pure functions; the reconciler does the listing and the KV writes.

use serde_json::Value;

use crate::profile::Profile;

fn str_field(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_owned)
}

/// Build the desired Profile from an authoritative user record (provider v2
/// shape) plus its resolved role set. `version`/`updated_at` are not
/// authoritative here (they come from the change feed), so they are left at
/// defaults and excluded from `differs`.
pub fn build_profile_from_user(user: &Value, mut roles: Vec<String>) -> Profile {
    let null = Value::Null;
    let human = user.get("human").unwrap_or(&null);
    let profile = human.get("profile").unwrap_or(&null);
    let det = user.get("details").unwrap_or(&null);
    roles.sort();
    Profile {
        sub: str_field(user, "userId").unwrap_or_default(),
        org_id: str_field(det, "resourceOwner"),
        username: str_field(user, "username"),
        email: human
            .get("email")
            .and_then(|e| e.get("email"))
            .and_then(|x| x.as_str())
            .map(String::from),
        given_name: str_field(profile, "givenName"),
        family_name: str_field(profile, "familyName"),
        display_name: str_field(profile, "displayName"),
        preferred_language: str_field(profile, "preferredLanguage"),
        is_suspended: str_field(user, "state").as_deref() == Some("USER_STATE_INACTIVE"),
        roles,
        entitlements: Vec::new(),
        // Memberships are nexus-native (not from the IdP), so the reconciler never
        // authors them — left empty here and excluded from `differs`. TODO(apply):
        // when membership CRUD populates them, the reconcile/sync WRITE path must
        // PRESERVE existing memberships (read-merge-write, or store them outside the
        // identity doc) so an identity-field update does not clobber them.
        memberships: Vec::new(),
        version: 0,
        updated_at: str_field(det, "changeDate"),
    }
}

/// True if the desired Profile differs from what is stored on the fields the
/// reconciler is authoritative for (identity attributes + roles). Excludes
/// `version`, `updated_at`, and `entitlements` (not reconciler-owned).
#[must_use]
pub fn differs(desired: &Profile, stored: Option<&Profile>) -> bool {
    let Some(s) = stored else {
        return true;
    };
    if desired.sub != s.sub
        || desired.org_id != s.org_id
        || desired.username != s.username
        || desired.email != s.email
        || desired.given_name != s.given_name
        || desired.family_name != s.family_name
        || desired.display_name != s.display_name
        || desired.preferred_language != s.preferred_language
        || desired.is_suspended != s.is_suspended
    {
        return true;
    }
    let mut a = desired.roles.clone();
    let mut b = s.roles.clone();
    a.sort();
    b.sort();
    a != b
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builds_from_v2_user_shape() {
        let u = json!({
            "userId": "u1", "username": "alice", "state": "USER_STATE_INACTIVE",
            "human": {"email": {"email": "a@x.io"}, "profile": {"givenName": "Al", "familyName": "Ice"}},
            "details": {"resourceOwner": "org1", "changeDate": "2026-01-01T00:00:00Z"}
        });
        let p = build_profile_from_user(&u, vec!["viewer".into(), "admin".into()]);
        assert_eq!(p.sub, "u1");
        assert_eq!(p.email.as_deref(), Some("a@x.io"));
        assert!(p.is_suspended);
        assert_eq!(p.roles, vec!["admin".to_owned(), "viewer".to_owned()]); // sorted
    }

    #[test]
    fn differs_detects_role_and_field_drift() {
        let desired = build_profile_from_user(&json!({"userId": "u1", "username": "alice"}), vec!["admin".into()]);
        assert!(differs(&desired, None));
        let mut stored = desired.clone();
        assert!(!differs(&desired, Some(&stored)));
        stored.roles = vec![];
        assert!(differs(&desired, Some(&stored)));
        stored.roles = desired.roles.clone();
        stored.username = Some("bob".into());
        assert!(differs(&desired, Some(&stored)));
    }
}
