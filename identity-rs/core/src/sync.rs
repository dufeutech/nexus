//! Change-event → Profile mapping and the version/ordering guard (RFC C7, §3.4).
//!
//! Pure functions: no I/O. The caller fetches the existing Profile and persists
//! the result, so this logic is identical and testable regardless of transport.

use serde_json::Value;

use crate::profile::Profile;

/// Provider (camelCase) → normalized (`snake_case`) field names (RFC §3.8).
pub const FIELD_MAP: &[(&str, &str)] = &[
    ("userName", "username"),
    ("firstName", "given_name"),
    ("lastName", "family_name"),
    ("displayName", "display_name"),
    ("email", "email"),
    ("preferredLanguage", "preferred_language"),
];

fn str_field(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_owned)
}

/// A user-relevant change with the subject already resolved (RFC §3.4: the
/// subject is resolved from the event contents, not assumed to be the notifying
/// aggregate — a grant event carries the user id in its payload).
#[derive(Debug)]
pub struct UserEvent<'a> {
    pub sub: String,
    pub event_type: String,
    pub org: Option<String>,
    /// Globally-ordered change marker (creation timestamp) — the cross-source
    /// version guard (RFC §3.4); per-aggregate `sequence` is NOT comparable.
    pub ts: String,
    pub sequence: i64,
    pub is_grant: bool,
    pub payload: &'a Value,
}

#[derive(Debug)]
pub enum Classify<'a> {
    /// Not a user-relevant event; ignore.
    Ignore,
    /// User event but no resolvable subject.
    NoSubject,
    Event(UserEvent<'a>),
}

/// Decide whether an event concerns a user and resolve its subject.
#[must_use]
pub fn classify(event: &Value) -> Classify<'_> {
    let et = str_field(event, "event_type").unwrap_or_default();
    let agg_type = str_field(event, "aggregateType").unwrap_or_default();
    if agg_type != "user" && !et.starts_with("user.") {
        return Classify::Ignore;
    }
    let payload = event.get("event_payload").unwrap_or(&Value::Null);
    let is_grant = et.contains("grant");
    let sub = if is_grant {
        payload
            .get("userID")
            .or_else(|| payload.get("userId"))
            .or_else(|| payload.get("user_id"))
            .and_then(|x| x.as_str())
            .map(str::to_owned)
    } else {
        str_field(event, "aggregateID")
    };
    let subject = match sub {
        Some(s) if !s.is_empty() => s,
        _ => return Classify::NoSubject,
    };
    let sequence = match event.get("sequence") {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    };
    Classify::Event(UserEvent {
        sub: subject,
        org: str_field(event, "resourceOwner"),
        ts: str_field(event, "created_at").unwrap_or_default(),
        sequence,
        is_grant,
        event_type: et,
        payload,
    })
}

#[derive(Debug)]
pub enum Apply {
    /// The stored Profile is newer than this event; drop it.
    SkipStale,
    /// Remove the subject's Profile (user-level removal only).
    Delete,
    /// Create/update the Profile.
    Upsert(Box<Profile>),
}

fn set_field(p: &mut Profile, target: &str, val: &str) {
    let v = Some(val.to_owned());
    match target {
        "username" => p.username = v,
        "given_name" => p.given_name = v,
        "family_name" => p.family_name = v,
        "display_name" => p.display_name = v,
        "email" => p.email = v,
        "preferred_language" => p.preferred_language = v,
        _ => {}
    }
}

/// Apply a classified event to the existing Profile under the version guard.
///
/// NOTE (behavior fix vs. the prior Python worker): a *grant* removal clears
/// roles rather than deleting the whole Profile. Only a user-level removal/
/// deletion deletes the subject. The old code's `"removed" in et` delete check
/// fired first for `user.grant.removed`, nuking the entire identity — corrected
/// here now that the logic lives in one place.
#[must_use]
pub fn apply(existing: Option<Profile>, ev: &UserEvent<'_>) -> Apply {
    let removed_or_deleted =
        ev.event_type.contains("removed") || ev.event_type.contains("deleted");
    if removed_or_deleted && !ev.is_grant {
        return Apply::Delete;
    }

    // Version guard: a newer stored value is never overwritten by an older event
    // (globally-ordered timestamp, RFC §3.4).
    if let Some(e) = &existing {
        if e.updated_at.as_deref().unwrap_or("") > ev.ts.as_str() {
            return Apply::SkipStale;
        }
    }

    let mut prof = existing.unwrap_or_default();
    if ev.event_type.contains("deactivated") {
        prof.is_suspended = true;
    } else if ev.event_type.contains("reactivated") {
        prof.is_suspended = false;
    } else if ev.is_grant {
        if removed_or_deleted {
            prof.roles = Vec::new();
        } else if let Some(Value::Array(arr)) = ev
            .payload
            .get("roleKeys")
            .or_else(|| ev.payload.get("roles"))
        {
            let roles: Vec<String> =
                arr.iter().filter_map(|x| x.as_str().map(String::from)).collect();
            if !roles.is_empty() {
                prof.roles = roles;
            }
        }
    } else if let Value::Object(map) = ev.payload {
        for (k, target) in FIELD_MAP {
            if let Some(val) = map.get(*k).and_then(|x| x.as_str()) {
                set_field(&mut prof, target, val);
            }
        }
    }

    prof.sub.clone_from(&ev.sub);
    prof.org_id.clone_from(&ev.org);
    // `home_org` mirrors the IdP resource owner like `org_id` (informational, not an
    // authz input). Starting from `existing`, memberships are carried through untouched.
    prof.home_org.clone_from(&ev.org);
    prof.version = ev.sequence;
    prof.updated_at = Some(ev.ts.clone());
    Apply::Upsert(Box::new(prof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(et: &str, agg_id: &str, ts: &str, payload: &Value) -> Value {
        json!({
            "event_type": et, "aggregateType": "user", "aggregateID": agg_id,
            "resourceOwner": "org1", "created_at": ts, "sequence": 5,
            "event_payload": payload.clone()
        })
    }

    fn subj(c: Classify<'_>) -> UserEvent<'_> {
        match c {
            Classify::Event(e) => e,
            Classify::Ignore | Classify::NoSubject => unreachable!("expected Event"),
        }
    }

    #[test]
    fn maps_human_fields_to_snake_case() {
        let e = ev("user.human.added", "u1", "2026-01-01T00:00:00Z",
            &json!({"userName": "alice", "firstName": "Al", "lastName": "Ice"}));
        match apply(None, &subj(classify(&e))) {
            Apply::Upsert(p) => {
                assert_eq!(p.sub, "u1");
                assert_eq!(p.username.as_deref(), Some("alice"));
                assert_eq!(p.given_name.as_deref(), Some("Al"));
                assert_eq!(p.family_name.as_deref(), Some("Ice"));
                assert_eq!(p.org_id.as_deref(), Some("org1"));
            }
            Apply::SkipStale | Apply::Delete => unreachable!("expected upsert"),
        }
    }

    #[test]
    fn version_guard_drops_older_event() {
        let existing = Profile { updated_at: Some("2026-06-01T00:00:00Z".into()), ..Default::default() };
        let e = ev("user.human.updated", "u1", "2026-01-01T00:00:00Z", &json!({"userName": "stale"}));
        assert!(matches!(apply(Some(existing), &subj(classify(&e))), Apply::SkipStale));
    }

    #[test]
    fn deactivate_then_reactivate_flips_suspended() {
        let e = ev("user.deactivated", "u1", "2026-02-01T00:00:00Z", &json!({}));
        let Apply::Upsert(p) = apply(None, &subj(classify(&e))) else {
            unreachable!("expected upsert")
        };
        assert!(p.is_suspended);
        let e2 = ev("user.reactivated", "u1", "2026-03-01T00:00:00Z", &json!({}));
        let Apply::Upsert(p2) = apply(Some(*p), &subj(classify(&e2))) else {
            unreachable!("expected upsert")
        };
        assert!(!p2.is_suspended);
    }

    #[test]
    fn grant_removed_clears_roles_not_deletes_user() {
        // Grant event: subject is in the payload, not the aggregate id.
        let e = json!({
            "event_type": "user.grant.removed", "aggregateType": "usergrant",
            "aggregateID": "grant99", "resourceOwner": "org1",
            "created_at": "2026-04-01T00:00:00Z", "sequence": 9,
            "event_payload": {"userID": "u1", "roleKeys": ["admin"]}
        });
        let c = classify(&e);
        let ue = subj(c);
        assert_eq!(ue.sub, "u1");
        let existing = Profile { sub: "u1".into(), roles: vec!["admin".into()], ..Default::default() };
        match apply(Some(existing), &ue) {
            Apply::Upsert(p) => assert!(p.roles.is_empty(), "roles cleared, user kept"),
            Apply::SkipStale | Apply::Delete => {
                unreachable!("grant removal must not delete the user")
            }
        }
    }

    #[test]
    fn non_user_event_ignored() {
        let e = json!({"event_type": "org.added", "aggregateType": "org"});
        assert!(matches!(classify(&e), Classify::Ignore));
    }
}
