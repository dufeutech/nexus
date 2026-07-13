use async_trait::async_trait;
use serde_json::json;
use sqlx::Row;

use router_core::audit::{
    AuditCtx, ACTION_MEMBERSHIP_REVOKE, ACTION_MEMBERSHIP_UPSERT, OUTCOME_OK,
};
use router_core::store::{BoxError, Membership, MembershipStore};

use crate::admin_audit::{record, NewAuditEvent};
use crate::PgRoutingStore;

#[async_trait]
impl MembershipStore for PgRoutingStore {
    async fn upsert_membership(&self, m: &Membership, actx: &AuditCtx) -> Result<(), BoxError> {
        // Upsert + audit event in ONE transaction (admin-action-audit): an
        // unrecorded grant does not commit.
        let mut tx = self.pool.begin().await?;
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
        .execute(&mut *tx)
        .await?;
        record(
            &mut *tx,
            actx,
            &NewAuditEvent {
                action: ACTION_MEMBERSHIP_UPSERT,
                target_kind: "workspace",
                target_id: &m.workspace_id,
                outcome: OUTCOME_OK,
                detail: json!({
                    "user_sub": m.user_sub,
                    "member_type": m.member_type,
                    "role": m.role,
                    "status": m.status,
                }),
                idempotency_key: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn delete_membership(
        &self,
        user_sub: &str,
        workspace_id: &str,
        actx: &AuditCtx,
    ) -> Result<(), BoxError> {
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "DELETE FROM routing.memberships WHERE user_sub = $1 AND workspace_id = $2",
        )
        .bind(user_sub)
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
        // Idempotent: a no-op revoke mutates nothing and records nothing.
        if res.rows_affected() > 0 {
            record(
                &mut *tx,
                actx,
                &NewAuditEvent {
                    action: ACTION_MEMBERSHIP_REVOKE,
                    target_kind: "workspace",
                    target_id: workspace_id,
                    outcome: OUTCOME_OK,
                    detail: json!({ "user_sub": user_sub }),
                    idempotency_key: None,
                },
            )
            .await?;
        }
        tx.commit().await?;
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
