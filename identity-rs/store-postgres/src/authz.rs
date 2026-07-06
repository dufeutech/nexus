//! Nexus-native authorization adapter (Model 1) — implements the core
//! [`AuthzResolver`] (read) and [`AuthzAuthoring`] (write) ports over the identity
//! plane's OWN Postgres store, so global authorization facts (roles, entitlements,
//! suspension) live on the subject's [`Profile`] alongside its membership projection.
//!
//! Authoring is **read-merge-write** through [`Profile::with_authz`]: it re-reads the
//! current document, replaces only the authz facts, and writes it back — preserving
//! memberships and display identity (the no-clobber convergence the three identity
//! writers share). Every write goes through [`PgProfileStore::put`], which bumps the
//! row `seq` and emits the `LISTEN/NOTIFY` change signal, so a grant/revoke/suspend
//! reaches the sidecar over the existing feed within seconds (spec R3 — instant
//! revocation, no new token).
//!
//! When an engine (OpenFGA/Cedar) is adopted it becomes the source of record and this
//! adapter is replaced behind the same two ports, without touching enforcement
//! (design D-authz / spec R5).

use async_trait::async_trait;
use sqlx::Row;

use identity_core::authz::{AuthzAuthoring, AuthzFacts, AuthzResolver};
use identity_core::store::{BoxError, ProfileStore};
use identity_core::Profile;

use crate::PgProfileStore;

impl PgProfileStore {
    /// Read-merge-write the subject's authorization facts: load the current Profile
    /// (or a fresh one keyed by `sub` — authoring creates the row), let `mutate`
    /// adjust the authz facts, and write it back preserving every other field. The
    /// `put` bumps `seq` + NOTIFYs, so the change propagates over the feed.
    async fn author_authz<F>(&self, sub: &str, mutate: F) -> Result<(), BoxError>
    where
        F: FnOnce(&mut Vec<String>, &mut Vec<String>, &mut bool) + Send,
    {
        let base = self
            .get(sub)
            .await?
            .unwrap_or_else(|| Profile { sub: sub.to_owned(), ..Default::default() });
        let mut roles = base.roles.clone();
        let mut entitlements = base.entitlements.clone();
        let mut is_suspended = base.is_suspended;
        mutate(&mut roles, &mut entitlements, &mut is_suspended);
        let updated = base.with_authz(roles, entitlements, is_suspended);
        self.put(&updated).await
    }
}

#[async_trait]
impl AuthzResolver for PgProfileStore {
    async fn facts(&self, sub: &str) -> Result<AuthzFacts, BoxError> {
        // Absent profile → deny-by-default zero value (spec R2), never an error.
        Ok(self.get(sub).await?.as_ref().map(AuthzFacts::from).unwrap_or_default())
    }

    // The question helpers are spelled out (not left to the trait default) so the
    // `missing_trait_methods` lint is satisfied; each resolves the facts once.
    async fn has_role(&self, sub: &str, role: &str) -> Result<bool, BoxError> {
        Ok(self.facts(sub).await?.has_role(role))
    }

    async fn is_suspended(&self, sub: &str) -> Result<bool, BoxError> {
        Ok(self.facts(sub).await?.is_suspended)
    }
}

#[async_trait]
impl AuthzAuthoring for PgProfileStore {
    async fn assign_role(&self, sub: &str, role: &str) -> Result<(), BoxError> {
        self.author_authz(sub, |roles, _ent, _susp| {
            if !roles.iter().any(|r| r == role) {
                roles.push(role.to_owned());
            }
        })
        .await
    }

    async fn revoke_role(&self, sub: &str, role: &str) -> Result<(), BoxError> {
        self.author_authz(sub, |roles, _ent, _susp| roles.retain(|r| r != role))
            .await
    }

    async fn grant_entitlement(&self, sub: &str, entitlement: &str) -> Result<(), BoxError> {
        self.author_authz(sub, |_roles, ent, _susp| {
            if !ent.iter().any(|e| e == entitlement) {
                ent.push(entitlement.to_owned());
            }
        })
        .await
    }

    async fn revoke_entitlement(&self, sub: &str, entitlement: &str) -> Result<(), BoxError> {
        self.author_authz(sub, |_roles, ent, _susp| ent.retain(|e| e != entitlement))
            .await
    }

    async fn suspend(&self, sub: &str) -> Result<(), BoxError> {
        self.author_authz(sub, |_roles, _ent, susp| *susp = true).await
    }

    async fn reactivate(&self, sub: &str) -> Result<(), BoxError> {
        self.author_authz(sub, |_roles, _ent, susp| *susp = false).await
    }

    async fn any_subject_has_role(&self, role: &str) -> Result<bool, BoxError> {
        // `jsonb_exists(doc->'roles', $1)` matches the role as an array element of the
        // stored `roles` array (avoids the `?` jsonb operator, which fouls the bind
        // parser). Tombstoned rows are excluded — a suspended admin still counts, a
        // deleted one does not.
        let row = sqlx::query(
            "SELECT EXISTS ( \
                 SELECT 1 FROM identity.profiles \
                 WHERE deleted = false AND jsonb_exists(doc->'roles', $1) \
             ) AS present",
        )
        .bind(role)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.get::<bool, _>("present"))
    }
}
