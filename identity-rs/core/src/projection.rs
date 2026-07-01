//! Membership projection — the pure orchestration that keeps `Profile.memberships`
//! in sync with the routing source of record. Composed over two ports
//! ([`SourceMembershipReader`] reads the source of record; [`ProfileStore`] holds
//! the projection), so it is fully testable with in-memory fakes and reused by both
//! the real-time consumer and the periodic backstop. The `membership-sync` binary
//! is the thin adapter that wires LISTEN + metrics around these functions.

use std::collections::HashSet;

use crate::membership::SourceMembershipReader;
use crate::store::{BoxError, ProfileStore};
use crate::Profile;

/// Re-derive one subject's memberships from the source of record and
/// read-merge-write them into its Profile, preserving every other field. Returns
/// `true` if a profile was written, `false` if there was nothing to project (no
/// existing profile and no memberships — so we don't create an empty row).
pub async fn sync_subject(
    reader: &dyn SourceMembershipReader,
    store: &dyn ProfileStore,
    sub: &str,
) -> Result<bool, BoxError> {
    let memberships = reader.memberships_for(sub).await?;
    let existing = store.get(sub).await?;
    if existing.is_none() && memberships.is_empty() {
        return Ok(false);
    }
    let profile = existing
        .unwrap_or_else(|| Profile { sub: sub.to_owned(), ..Default::default() })
        .with_memberships(memberships);
    store.put(&profile).await?;
    Ok(true)
}

/// Outcome of a backstop pass (for logging/metrics in the adapter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackstopStats {
    /// Subjects considered this pass (the convergence set).
    pub subjects: usize,
    /// Subjects whose projection was written.
    pub written: usize,
}

/// Converge EVERY subject that either holds a source-of-record membership
/// (backfill / missed grant) or still carries a projected membership (heal a missed
/// revoke, including revoke-to-zero where the subject left the source set). A single
/// subject's failure is surfaced to the caller only if the enumeration reads fail;
/// per-subject write errors abort the pass so the caller can retry/log.
pub async fn backstop_pass(
    reader: &dyn SourceMembershipReader,
    store: &dyn ProfileStore,
) -> Result<BackstopStats, BoxError> {
    let mut subjects: HashSet<String> =
        reader.all_member_subjects().await?.into_iter().collect();
    for p in store.scan_all().await? {
        if !p.memberships.is_empty() {
            subjects.insert(p.sub);
        }
    }
    let total = subjects.len();
    let mut written = 0_usize;
    for sub in subjects {
        if sync_subject(reader, store, &sub).await? {
            written += 1;
        }
    }
    Ok(BackstopStats { subjects: total, written })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use futures::stream;

    use super::*;
    use crate::membership::{MemberType, Membership};
    use crate::store::{ChangeEvent, ChangeFeed, WatchToken};

    fn member(ws: &str, role: &str) -> Membership {
        Membership {
            workspace_id: ws.to_owned(),
            member_type: MemberType::Staff,
            role: role.to_owned(),
            entitlements: Vec::new(),
        }
    }

    /// In-memory source of record: `sub -> memberships`.
    #[derive(Default)]
    struct FakeReader {
        rows: Mutex<HashMap<String, Vec<Membership>>>,
    }
    impl FakeReader {
        fn set(&self, sub: &str, m: Vec<Membership>) {
            self.rows.lock().unwrap().insert(sub.to_owned(), m);
        }
        fn remove(&self, sub: &str) {
            self.rows.lock().unwrap().remove(sub);
        }
    }
    #[async_trait]
    impl SourceMembershipReader for FakeReader {
        async fn memberships_for(&self, sub: &str) -> Result<Vec<Membership>, BoxError> {
            Ok(self.rows.lock().unwrap().get(sub).cloned().unwrap_or_default())
        }
        async fn all_member_subjects(&self) -> Result<Vec<String>, BoxError> {
            Ok(self.rows.lock().unwrap().keys().cloned().collect())
        }
    }

    /// In-memory profile store; counts puts so we can assert writes happened.
    #[derive(Default)]
    struct FakeStore {
        profiles: Mutex<HashMap<String, Profile>>,
    }
    #[async_trait]
    impl ProfileStore for FakeStore {
        async fn get(&self, sub: &str) -> Result<Option<Profile>, BoxError> {
            Ok(self.profiles.lock().unwrap().get(sub).cloned())
        }
        async fn put(&self, profile: &Profile) -> Result<(), BoxError> {
            self.profiles
                .lock()
                .unwrap()
                .insert(profile.sub.clone(), profile.clone());
            Ok(())
        }
        async fn delete(&self, sub: &str) -> Result<(), BoxError> {
            self.profiles.lock().unwrap().remove(sub);
            Ok(())
        }
        async fn scan_all(&self) -> Result<Vec<Profile>, BoxError> {
            Ok(self.profiles.lock().unwrap().values().cloned().collect())
        }
        async fn watch(&self, _after: Option<WatchToken>) -> Result<ChangeFeed, BoxError> {
            let empty: Vec<Result<ChangeEvent, BoxError>> = vec![];
            Ok(Box::pin(stream::iter(empty)))
        }
    }

    #[tokio::test]
    async fn grant_is_reflected_and_preserves_identity_fields() {
        let reader = FakeReader::default();
        let store = FakeStore::default();
        // An identity-synced profile already exists (from ZITADEL) with no memberships.
        store
            .put(&Profile { sub: "u1".into(), username: Some("alice".into()), ..Default::default() })
            .await
            .unwrap();
        reader.set("u1", vec![member("ws-a", "admin")]);

        assert!(sync_subject(&reader, &store, "u1").await.unwrap());
        let p = store.get("u1").await.unwrap().unwrap();
        assert_eq!(p.username.as_deref(), Some("alice")); // identity field preserved
        assert_eq!(p.resolve_membership("ws-a").unwrap().role, "admin");
    }

    #[tokio::test]
    async fn revoke_to_zero_clears_projection() {
        let reader = FakeReader::default();
        let store = FakeStore::default();
        store
            .put(&Profile {
                sub: "u1".into(),
                memberships: vec![member("ws-a", "admin")],
                ..Default::default()
            })
            .await
            .unwrap();
        reader.set("u1", vec![]); // all revoked at the source of record

        assert!(sync_subject(&reader, &store, "u1").await.unwrap());
        assert!(store.get("u1").await.unwrap().unwrap().resolve_membership("ws-a").is_none());
    }

    #[tokio::test]
    async fn no_profile_no_memberships_writes_nothing() {
        let reader = FakeReader::default();
        let store = FakeStore::default();
        assert!(!sync_subject(&reader, &store, "ghost").await.unwrap());
        assert!(store.get("ghost").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn backstop_backfills_and_heals_missed_revoke() {
        let reader = FakeReader::default();
        let store = FakeStore::default();
        // Source has a grant for u1 with no projected profile yet (backfill case)...
        reader.set("u1", vec![member("ws-a", "admin")]);
        // ...and u2 still carries a stale projection while the source has nothing
        // for it (a missed revoke-to-zero — u2 is NOT in all_member_subjects).
        store
            .put(&Profile {
                sub: "u2".into(),
                memberships: vec![member("ws-b", "owner")],
                ..Default::default()
            })
            .await
            .unwrap();
        reader.remove("u2");

        let stats = backstop_pass(&reader, &store).await.unwrap();
        assert_eq!(stats.subjects, 2); // u1 (source) ∪ u2 (stale projection)
        // u1 backfilled...
        assert_eq!(store.get("u1").await.unwrap().unwrap().resolve_membership("ws-a").unwrap().role, "admin");
        // ...u2 healed to non-member.
        assert!(store.get("u2").await.unwrap().unwrap().resolve_membership("ws-b").is_none());
    }
}
