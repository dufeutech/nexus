//! Nexus-native authorization — the identity plane is the AUTHORITATIVE source of a
//! subject's global authorization facts (roles, entitlements, suspension). The OIDC
//! provider answers "who am I" (authentication + basic profile); nexus answers "what
//! may I do here" (authorization). No authorization fact ever originates from the
//! token or the provider (`nexus-native-authorization` spec, R1).
//!
//! Two ports keep the backend swappable (spec R5): [`AuthzResolver`] (read, on the
//! request path) and [`AuthzAuthoring`] (write, the administrative surface). Both are
//! shaped in DOMAIN language — assign/revoke/suspend and authorization *questions*,
//! never a storage-column read — so the current nexus-native Postgres adapter and a
//! future policy/ReBAC engine (OpenFGA/Cedar) are the same seam, an adapter swap
//! rather than a rewrite (design D-authz).

use async_trait::async_trait;

use crate::audit::AuditCtx;
use crate::profile::Profile;
use crate::store::BoxError;

/// A subject's effective global authorization facts, resolved live from the
/// authoritative store. The [`Default`] (zero) value is **deny-by-default** (spec
/// R2): no roles, no entitlements, not suspended — exactly how a subject nexus holds
/// no facts about is treated (authenticated but unprivileged).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthzFacts {
    /// Coarse global roles nexus has authored for the subject.
    pub roles: Vec<String>,
    /// Global entitlements nexus has authored for the subject.
    pub entitlements: Vec<String>,
    /// Whether nexus has suspended the subject. Absent fact ⇒ `false` (not
    /// suspended is the safe default; spec R2).
    pub is_suspended: bool,
}

impl AuthzFacts {
    /// Does the subject hold `role`? Deny-by-default: the zero value holds nothing.
    #[must_use]
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Does the subject hold `entitlement`?
    #[must_use]
    pub fn has_entitlement(&self, entitlement: &str) -> bool {
        self.entitlements.iter().any(|e| e == entitlement)
    }
}

impl From<&Profile> for AuthzFacts {
    /// The nexus-native (Model 1) projection: a subject's authorization facts live on
    /// its [`Profile`] in the identity store. A future engine-backed adapter builds
    /// `AuthzFacts` from the engine instead, behind the same [`AuthzResolver`] port.
    fn from(p: &Profile) -> Self {
        Self {
            roles: p.roles.clone(),
            entitlements: p.entitlements.clone(),
            is_suspended: p.is_suspended,
        }
    }
}

/// Resolve a subject's effective authorization facts on the request path (spec R3:
/// resolved live, revocation within seconds). **Deny-by-default:** a subject the
/// backend holds no facts about resolves to [`AuthzFacts::default`], never an error —
/// `Err` is a transient resolution failure the caller must treat as "cannot decide"
/// (fail-closed), never as a grant.
///
/// Shaped around authorization *questions* (the default-method helpers) so a future
/// decision engine slots in as an adapter without changing enforcement (design
/// discipline 3). Today's coarse edge gate still reads the full [`AuthzFacts`] to
/// inject `x-user-*` headers; the question helpers are the forward-compatible shape.
#[async_trait]
pub trait AuthzResolver: Send + Sync {
    /// The subject's effective facts. Absent subject ⇒ deny-by-default zero value.
    async fn facts(&self, sub: &str) -> Result<AuthzFacts, BoxError>;

    /// Does the subject hold `role`? (Authorization question — deny-by-default.)
    async fn has_role(&self, sub: &str, role: &str) -> Result<bool, BoxError> {
        Ok(self.facts(sub).await?.has_role(role))
    }

    /// Is the subject suspended? Absent fact ⇒ `false` (safe default).
    async fn is_suspended(&self, sub: &str) -> Result<bool, BoxError> {
        Ok(self.facts(sub).await?.is_suspended)
    }
}

/// The administrative authoring surface — the SINGLE source of record for
/// authorization facts (spec R4). Facts are created/changed/revoked ONLY here; no
/// token, event, or provider action may author them. Domain-language and
/// storage-agnostic: an adapter maps these to its backend (Model 1 writes the
/// identity Profile; a future engine writes the engine).
///
/// Every mutating method carries an [`AuditCtx`] (admin-action-audit): the
/// adapter records one audit event atomically with the write — an unrecorded
/// authoring mutation does not commit (fail-closed, design D1/D2).
#[async_trait]
pub trait AuthzAuthoring: Send + Sync {
    /// Assign a global role to the subject (idempotent — assigning an already-held
    /// role is a no-op). Creates the subject's record if absent.
    async fn assign_role(&self, sub: &str, role: &str, actx: &AuditCtx) -> Result<(), BoxError>;

    /// Revoke a global role (idempotent — revoking an unheld role is a no-op).
    async fn revoke_role(&self, sub: &str, role: &str, actx: &AuditCtx) -> Result<(), BoxError>;

    /// Grant a global entitlement (idempotent).
    async fn grant_entitlement(
        &self,
        sub: &str,
        entitlement: &str,
        actx: &AuditCtx,
    ) -> Result<(), BoxError>;

    /// Revoke a global entitlement (idempotent).
    async fn revoke_entitlement(
        &self,
        sub: &str,
        entitlement: &str,
        actx: &AuditCtx,
    ) -> Result<(), BoxError>;

    /// Suspend the subject — subsequent requests are denied within seconds (spec R3),
    /// no re-authentication. Creates the subject's record if absent.
    async fn suspend(&self, sub: &str, actx: &AuditCtx) -> Result<(), BoxError>;

    /// Reactivate a suspended subject.
    async fn reactivate(&self, sub: &str, actx: &AuditCtx) -> Result<(), BoxError>;

    /// Whether ANY subject currently holds `role` — the bootstrap gate (spec R4): the
    /// first administrator is seeded only when no administrator exists yet.
    async fn any_subject_has_role(&self, role: &str) -> Result<bool, BoxError>;

    /// The break-glass startup grant (spec R4 + admin-action-audit D8): assign
    /// the initial admin role, recording a `bootstrap.grant` event attributed to
    /// the bootstrap mechanism in the same transaction as the grant. The caller
    /// (the startup gate) fires this ONLY when no administrator exists yet — a
    /// no-op startup writes nothing.
    async fn bootstrap_grant(&self, sub: &str, role: &str) -> Result<(), BoxError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_value_is_deny_by_default() {
        let facts = AuthzFacts::default();
        assert!(facts.roles.is_empty());
        assert!(facts.entitlements.is_empty());
        assert!(!facts.is_suspended);
        assert!(!facts.has_role("admin"));
        assert!(!facts.has_entitlement("pro"));
    }

    #[test]
    fn facts_project_from_profile() {
        let p = Profile {
            sub: "u1".into(),
            roles: vec!["admin".into()],
            entitlements: vec!["pro".into()],
            is_suspended: true,
            ..Default::default()
        };
        let facts = AuthzFacts::from(&p);
        assert!(facts.has_role("admin"));
        assert!(!facts.has_role("viewer"));
        assert!(facts.has_entitlement("pro"));
        assert!(facts.is_suspended);
    }
}
