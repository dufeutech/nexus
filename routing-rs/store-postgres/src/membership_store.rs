use async_trait::async_trait;
use sqlx::Row;

use router_core::store::{BoxError, Membership, MembershipStore};

use crate::PgRoutingStore;

#[async_trait]
impl MembershipStore for PgRoutingStore {
    async fn upsert_membership(&self, m: &Membership) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.memberships \
                 (user_sub, workspace_id, member_type, role, status, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now()) \
             ON CONFLICT (user_sub, workspace_id) DO UPDATE SET \
                 member_type = EXCLUDED.member_type, role = EXCLUDED.role, \
                 status = EXCLUDED.status, updated_at = now()",
        )
        .bind(&m.user_sub)
        .bind(&m.workspace_id)
        .bind(&m.member_type)
        .bind(&m.role)
        .bind(&m.status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_membership(
        &self,
        user_sub: &str,
        workspace_id: &str,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "DELETE FROM routing.memberships WHERE user_sub = $1 AND workspace_id = $2",
        )
        .bind(user_sub)
        .bind(workspace_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn memberships_for_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<Vec<Membership>, BoxError> {
        let rows = sqlx::query(
            "SELECT user_sub, workspace_id, member_type, role, status \
             FROM routing.memberships WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Membership {
                user_sub: r.get("user_sub"),
                workspace_id: r.get("workspace_id"),
                member_type: r.get("member_type"),
                role: r.get("role"),
                status: r.get("status"),
            })
            .collect())
    }
}
