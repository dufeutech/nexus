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
use serde_json::{json, Value};
use sqlx::Row;

use identity_core::audit::{
    AuditCtx, ACTION_BOOTSTRAP_GRANT, ACTION_ENTITLEMENT_GRANT, ACTION_ENTITLEMENT_REVOKE,
    ACTION_ROLE_ASSIGN, ACTION_ROLE_REVOKE, ACTION_SUBJECT_REACTIVATE, ACTION_SUBJECT_SUSPEND,
    ACTOR_BOOTSTRAP, OUTCOME_OK,
};
use identity_core::authz::{AuthzAuthoring, AuthzFacts, AuthzResolver};
use identity_core::store::{BoxError, ProfileStore};
use identity_core::Profile;

use crate::admin_audit::NewAuditEvent;
use crate::PgProfileStore;

/// The audit half of one authoring write (admin-action-audit): which action the
/// event records, its secret-free detail, and the transport facts.
struct AuthoringAudit<'a> {
    action: &'static str,
    detail: Value,
    actx: &'a AuditCtx,
}

impl PgProfileStore {
    /// Read-merge-write the subject's authorization facts: load the current Profile
    /// (or a fresh one keyed by `sub` — authoring creates the row), let `mutate`
    /// adjust the authz facts, and write it back preserving every other field. The
    /// write bumps `seq` + NOTIFYs, so the change propagates over the feed — and
    /// records the authoring's audit event IN THE SAME TRANSACTION
    /// (admin-action-audit: an unrecorded authoring mutation does not commit).
    async fn author_authz<F>(&self, sub: &str, mutate: F, audit: AuthoringAudit<'_>) -> Result<(), BoxError>
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
        let event = NewAuditEvent {
            action: audit.action,
            target_kind: "subject",
            target_id: sub,
            outcome: OUTCOME_OK,
            detail: audit.detail,
            idempotency_key: None,
        };
        self.put_with_event(&updated, Some((&event, audit.actx))).await
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
    async fn assign_role(&self, sub: &str, role: &str, actx: &AuditCtx) -> Result<(), BoxError> {
        self.author_authz(
            sub,
            |roles, _ent, _susp| {
                if !roles.iter().any(|r| r == role) {
                    roles.push(role.to_owned());
                }
            },
            AuthoringAudit { action: ACTION_ROLE_ASSIGN, detail: json!({ "role": role }), actx },
        )
        .await
    }

    async fn revoke_role(&self, sub: &str, role: &str, actx: &AuditCtx) -> Result<(), BoxError> {
        self.author_authz(
            sub,
            |roles, _ent, _susp| roles.retain(|r| r != role),
            AuthoringAudit { action: ACTION_ROLE_REVOKE, detail: json!({ "role": role }), actx },
        )
        .await
    }

    async fn grant_entitlement(
        &self,
        sub: &str,
        entitlement: &str,
        actx: &AuditCtx,
    ) -> Result<(), BoxError> {
        self.author_authz(
            sub,
            |_roles, ent, _susp| {
                if !ent.iter().any(|e| e == entitlement) {
                    ent.push(entitlement.to_owned());
                }
            },
            AuthoringAudit {
                action: ACTION_ENTITLEMENT_GRANT,
                detail: json!({ "entitlement": entitlement }),
                actx,
            },
        )
        .await
    }

    async fn revoke_entitlement(
        &self,
        sub: &str,
        entitlement: &str,
        actx: &AuditCtx,
    ) -> Result<(), BoxError> {
        self.author_authz(
            sub,
            |_roles, ent, _susp| ent.retain(|e| e != entitlement),
            AuthoringAudit {
                action: ACTION_ENTITLEMENT_REVOKE,
                detail: json!({ "entitlement": entitlement }),
                actx,
            },
        )
        .await
    }

    async fn suspend(&self, sub: &str, actx: &AuditCtx) -> Result<(), BoxError> {
        self.author_authz(
            sub,
            |_roles, _ent, susp| *susp = true,
            AuthoringAudit { action: ACTION_SUBJECT_SUSPEND, detail: json!({}), actx },
        )
        .await
    }

    async fn reactivate(&self, sub: &str, actx: &AuditCtx) -> Result<(), BoxError> {
        self.author_authz(
            sub,
            |_roles, _ent, susp| *susp = false,
            AuthoringAudit { action: ACTION_SUBJECT_REACTIVATE, detail: json!({}), actx },
        )
        .await
    }

    async fn bootstrap_grant(&self, sub: &str, role: &str) -> Result<(), BoxError> {
        // The break-glass startup grant (design D8): same read-merge-write as a
        // role assign, but recorded as `bootstrap.grant` with the reserved
        // bootstrap actor — in the same transaction as the grant itself.
        let actx = AuditCtx::system(ACTOR_BOOTSTRAP);
        self.author_authz(
            sub,
            |roles, _ent, _susp| {
                if !roles.iter().any(|r| r == role) {
                    roles.push(role.to_owned());
                }
            },
            AuthoringAudit {
                action: ACTION_BOOTSTRAP_GRANT,
                detail: json!({ "role": role }),
                actx: &actx,
            },
        )
        .await
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
