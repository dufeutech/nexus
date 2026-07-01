//! Read-only adapter over the ROUTING plane's `routing.memberships` table — the
//! membership source of record (written by the routing control plane). The
//! identity plane PROJECTS this into `Profile.memberships`; it never writes it, so
//! this adapter is `SELECT`-only and holds its own pool to a least-privilege
//! routing connection (a separate database in production — see design D4/D5).

use std::time::Duration;

use async_trait::async_trait;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{PgPool, Row};

use identity_core::membership::{MemberType, Membership, SourceMembershipReader};
use identity_core::store::BoxError;

/// Reads active memberships for the projection out of `routing.memberships`.
pub struct PgSourceMembershipReader {
    pool: PgPool,
}

impl PgSourceMembershipReader {
    /// Open a read-only pool to the routing database. Mirrors the identity store's
    /// pooler-safe settings (no statement cache, server-side statement timeout).
    pub async fn connect(url: &str) -> Result<Self, BoxError> {
        let opts = url
            .parse::<PgConnectOptions>()?
            .statement_cache_capacity(0)
            .options([("statement_timeout", "5000")]);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;
        Ok(Self { pool })
    }
}

/// Map the routing wire string to the typed member kind. An unrecognized value is
/// dropped (fail-closed): a row we can't classify never becomes an acting scope.
fn map_member_type(s: &str) -> Option<MemberType> {
    match s {
        "staff" => Some(MemberType::Staff),
        "customer" => Some(MemberType::Customer),
        _ => None,
    }
}

#[async_trait]
impl SourceMembershipReader for PgSourceMembershipReader {
    async fn memberships_for(&self, sub: &str) -> Result<Vec<Membership>, BoxError> {
        // Only ACTIVE rows are projected — a suspended/inactive membership must not
        // grant the acting scope (`Profile::resolve_membership` is fail-closed on
        // presence, so exclusion here is the enforcement point).
        let rows = sqlx::query(
            "SELECT workspace_id, member_type, role \
             FROM routing.memberships WHERE user_sub = $1 AND status = 'active'",
        )
        .bind(sub)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let workspace_id: String = r.try_get("workspace_id")?;
            let member_type: String = r.try_get("member_type")?;
            let role: String = r.try_get("role")?;
            if let Some(member_type) = map_member_type(&member_type) {
                out.push(Membership {
                    workspace_id,
                    member_type,
                    role,
                    // Routing memberships carry no per-membership entitlements today.
                    entitlements: Vec::new(),
                });
            }
        }
        Ok(out)
    }

    async fn all_member_subjects(&self) -> Result<Vec<String>, BoxError> {
        let rows = sqlx::query(
            "SELECT DISTINCT user_sub FROM routing.memberships WHERE status = 'active'",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| r.try_get::<String, _>("user_sub").map_err(Into::into))
            .collect()
    }
}
