//! Customer API keys — the Personal Access Token (PAT) domain (`customer-api-keys`).
//!
//! WHAT, not HOW: this module owns the language-agnostic *behavior* of a PAT — its
//! scope vocabulary, the effective-authority intersection, and the [`SecretHasher`]
//! port — and NOTHING about how a secret is hashed, stored, or presented. The HMAC
//! adapter, the Postgres reader, and the `x-api-key` extractor all live behind ports
//! in the adapters/sidecar (rules §2), so core never imports a crypto crate or a DB
//! type.
//!
//! An api-key principal is the third [`crate::PrincipalKind`]: it authenticates as a
//! key but acts **on behalf of** its creating human, bounded by the key's scopes. Its
//! effective authority is the creator's **live** workspace membership **intersected**
//! with the key's scopes — nexus-resolved, revocation-consistent, and fail-closed, so a
//! key can never exceed its creator and follows the creator's revocation
//! (`customer-api-keys` / `nexus-native-authorization` specs).

use async_trait::async_trait;

use crate::membership::ResolvedMembership;
use crate::principal::Principal;
use crate::store::BoxError;

/// A key's **scope vocabulary**: the set of workspace ids the key may act in (data, not
/// code — sourced from the stored key row). Least-privilege and fail-closed: a workspace
/// the set does not name is never admitted, and an EMPTY set admits nothing (a key with
/// no scope resolves to no authority). Issuance requires at least one scope.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiKeyScope {
    /// The workspace ids this key is scoped to. An operation on a workspace absent from
    /// this list is refused even for the creator's own memberships (the narrowing half
    /// of the intersection).
    workspaces: Vec<String>,
}

impl ApiKeyScope {
    /// Construct a scope from a set of workspace ids.
    #[must_use]
    pub const fn new(workspaces: Vec<String>) -> Self {
        Self { workspaces }
    }

    /// Whether this scope admits acting in `workspace_id` (exact match). An empty scope
    /// admits nothing (fail-closed least-privilege).
    #[must_use]
    pub fn admits(&self, workspace_id: &str) -> bool {
        self.workspaces.iter().any(|w| w == workspace_id)
    }

    /// Whether the scope names no workspace — an unusable key that resolves to no
    /// authority. Issuance rejects this.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.workspaces.is_empty()
    }
}

/// A **verified but not-yet-authorized** api-key candidate — what the authenticator
/// produces from a presented secret AFTER the secret verifies against a live
/// (`active`, unexpired) stored key, and BEFORE authority resolution. Its subject is the
/// key id; `creator_sub` is the human it acts on behalf of. Carrying no authority yet,
/// it must pass the [`ScopeIntersectionResolver`] to become a [`Principal`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKeyCandidate {
    /// The stable, public key id (audit / management handle) — NOT the secret.
    pub key_id: String,
    /// The creating user's subject; recorded as the principal's `on_behalf_of`.
    pub creator_sub: String,
    /// The key's scopes.
    pub scope: ApiKeyScope,
}

/// Composes a key's scopes with the **creator's live membership** to produce the
/// effective authority — `Authority::Workspace(membership ∩ scopes)`
/// (`customer-api-keys` correctness concern). Pure core logic: the caller supplies the
/// creator's already-resolved membership of the acting workspace (from the live Profile,
/// the same source the human path uses), and this decides admission. Empty intersection
/// ⇒ `None` ⇒ fail closed (no principal, no contract, rejected).
#[derive(Clone, Copy, Debug, Default)]
pub struct ScopeIntersectionResolver;

impl ScopeIntersectionResolver {
    /// Resolve an api-key principal for `workspace_id`, or `None` (fail closed) when the
    /// intersection is empty. Admits IFF **both** the key's scope names `workspace_id`
    /// AND the creator holds a live membership of exactly that workspace. The resolved
    /// authority is the creator's membership verbatim — never widened past either input,
    /// so a key can only ever be a subset of its creator and follows the creator's
    /// revocation (an absent `creator_membership` withdraws the key within seconds).
    #[must_use]
    pub fn resolve(
        candidate: &ApiKeyCandidate,
        workspace_id: &str,
        creator_membership: Option<ResolvedMembership>,
    ) -> Option<Principal> {
        if !candidate.scope.admits(workspace_id) {
            return None;
        }
        // The membership must be for exactly the acting workspace — never a different
        // one the creator happens to hold (defense-in-depth against a mismatched
        // resolve).
        let membership = creator_membership.filter(|m| m.workspace_id == workspace_id)?;
        Some(Principal::api_key(
            candidate.key_id.clone(),
            candidate.creator_sub.clone(),
            membership,
        ))
    }
}

/// Read a presented key's **hash** back to a live key candidate — the source of record
/// for a PAT's identity + scopes. Implemented by a read-only adapter over the
/// `identity.api_keys` store (mirroring [`crate::SourceMembershipReader`]); consulted by
/// the sidecar authenticator on the request path.
///
/// **Fail-closed by contract:** an adapter MUST surface ONLY an `active`, unexpired key,
/// so a revoked/expired/unknown key resolves to `Ok(None)` — no candidate, no authority,
/// rejected. `Ok(None)` is "no such live key" (NOT an error); an `Err` is a transient
/// resolution failure the caller treats as "cannot decide" (fail closed), never as a
/// disproof. Resolving live on each call is what makes revocation/expiry take effect on
/// the very next request.
#[async_trait]
pub trait ApiKeyReader: Send + Sync {
    /// Resolve the deterministic hash of a presented secret (see [`SecretHasher::hash`])
    /// to its live key candidate, or `Ok(None)` when no active, unexpired key has that
    /// hash.
    async fn lookup(&self, key_hash: &str) -> Result<Option<ApiKeyCandidate>, BoxError>;
}

/// The secret-hashing port (`customer-api-keys` security concern). Key secrets are
/// stored and verified ONLY as hashes; the concrete construction (a keyed HMAC over an
/// adopted crate) lives entirely behind this port in an adapter, so core holds no crypto
/// and a hasher swap never touches it. The hash is **deterministic** (keyed, not salted)
/// so a presented secret resolves with a single indexed lookup by [`Self::hash`].
pub trait SecretHasher: Send + Sync {
    /// The stable, hex-encoded hash of `secret` — the value persisted at issuance and
    /// the lookup key at resolve time. MUST be deterministic for a given key/secret.
    fn hash(&self, secret: &str) -> String;

    /// Constant-time check that `secret` hashes to `stored` — reject-on-mismatch, no
    /// early exit that could leak how much matched. Used for a post-lookup
    /// defense-in-depth re-verify (the DB equality is the primary match).
    fn verify(&self, secret: &str, stored: &str) -> bool;
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

    fn candidate(scopes: &[&str]) -> ApiKeyCandidate {
        ApiKeyCandidate {
            key_id: "pak-1".to_owned(),
            creator_sub: "u-creator".to_owned(),
            scope: ApiKeyScope::new(scopes.iter().map(|s| (*s).to_owned()).collect()),
        }
    }

    #[test]
    fn intersection_admits_a_scoped_workspace_the_creator_is_a_member_of() {
        // Task 3.3 (subset): scope names ws-1 AND the creator is a live member of ws-1
        // -> a resolved apikey principal acting on ws-1, on behalf of the creator.
        let c = candidate(&["ws-1", "ws-2"]);
        let p = ScopeIntersectionResolver::resolve(&c, "ws-1", Some(membership("ws-1")))
            .expect("scope ∩ membership must admit");
        assert_eq!(p.kind, crate::PrincipalKind::ApiKey);
        assert_eq!(p.subject, "pak-1");
        assert_eq!(p.on_behalf_of.as_deref(), Some("u-creator"));
        match p.authority {
            crate::Authority::Workspace(m) => assert_eq!(m.workspace_id, "ws-1"),
            crate::Authority::Platform(_) => panic!("an api key resolves to a Workspace authority"),
        }
    }

    #[test]
    fn scope_narrows_but_never_widens() {
        // Task 3.3 (never widens): the creator is a member of ws-2, but the key's scope
        // does not name ws-2 -> no authority, even though the creator could act there.
        let c = candidate(&["ws-1"]);
        assert!(
            ScopeIntersectionResolver::resolve(&c, "ws-2", Some(membership("ws-2"))).is_none(),
            "a workspace outside the key's scope must never be admitted, even for a member",
        );
    }

    #[test]
    fn creator_revocation_cascades_to_the_key() {
        // Task 3.3 (revocation cascade): the scope still names ws-1, but the creator no
        // longer holds a live membership there (None) -> the key's authority is withdrawn.
        let c = candidate(&["ws-1"]);
        assert!(
            ScopeIntersectionResolver::resolve(&c, "ws-1", None).is_none(),
            "losing the creator's membership must withdraw the key (fail closed)",
        );
    }

    #[test]
    fn no_intersection_fails_closed() {
        // Task 3.3 (no-intersection rejection): scope admits nothing at all (empty).
        let empty = ApiKeyCandidate {
            key_id: "pak-1".to_owned(),
            creator_sub: "u-creator".to_owned(),
            scope: ApiKeyScope::default(),
        };
        assert!(empty.scope.is_empty());
        assert!(ScopeIntersectionResolver::resolve(&empty, "ws-1", Some(membership("ws-1"))).is_none());
    }

    #[test]
    fn a_mismatched_membership_workspace_is_not_admitted() {
        // Defense-in-depth: even if a membership for a DIFFERENT workspace is supplied,
        // it must not authorize the acting workspace.
        let c = candidate(&["ws-1"]);
        assert!(
            ScopeIntersectionResolver::resolve(&c, "ws-1", Some(membership("ws-other"))).is_none(),
            "a membership for another workspace must not admit the acting one",
        );
    }
}
