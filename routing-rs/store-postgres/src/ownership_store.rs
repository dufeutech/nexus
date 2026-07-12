use async_trait::async_trait;
use sqlx::Row;

use router_core::store::{Account, AccountMember, BoxError, OwnershipStore};

use crate::PgRoutingStore;

#[async_trait]
impl OwnershipStore for PgRoutingStore {
    async fn create_account(
        &self,
        account_id: &str,
        name: &str,
        payer_ref: Option<&str>,
    ) -> Result<bool, BoxError> {
        // Idempotent provision (ON CONFLICT DO NOTHING): a repeat signup for an
        // already-provisioned account is a no-op and never clobbers its name/payer.
        let res = sqlx::query(
            "INSERT INTO routing.accounts (account_id, name, payer_ref, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (account_id) DO NOTHING",
        )
        .bind(account_id)
        .bind(name)
        .bind(payer_ref)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn get_account(&self, account_id: &str) -> Result<Option<Account>, BoxError> {
        let row = sqlx::query(
            "SELECT account_id, name, payer_ref, updated_at::text AS updated_at \
             FROM routing.accounts WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Account {
            account_id: r.get("account_id"),
            name: r.get("name"),
            payer_ref: r.get::<Option<String>, _>("payer_ref"),
            updated_at: r.get::<Option<String>, _>("updated_at"),
        }))
    }

    async fn add_account_member(
        &self,
        account_id: &str,
        user_sub: &str,
        role: &str,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.account_members (account_id, user_sub, role, updated_at) \
             VALUES ($1, $2, $3, now()) \
             ON CONFLICT (account_id, user_sub) DO UPDATE SET \
                 role = EXCLUDED.role, updated_at = now()",
        )
        .bind(account_id)
        .bind(user_sub)
        .bind(role)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn account_members(&self, account_id: &str) -> Result<Vec<AccountMember>, BoxError> {
        let rows = sqlx::query(
            "SELECT account_id, user_sub, role FROM routing.account_members WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AccountMember {
                account_id: r.get("account_id"),
                user_sub: r.get("user_sub"),
                role: r.get("role"),
            })
            .collect())
    }

    async fn set_workspace_account(
        &self,
        workspace_id: &str,
        account_id: &str,
    ) -> Result<bool, BoxError> {
        // Create-time ownership assignment: repoint ONLY `account_id`, no staff
        // reset (a brand-new workspace has none). An ownership CHANGE goes through
        // `transfer_workspace`, which also resets staff atomically.
        let res = sqlx::query(
            "UPDATE routing.workspaces SET account_id = $2, updated_at = now() \
             WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .bind(account_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn transfer_workspace(
        &self,
        workspace_id: &str,
        account_id: &str,
    ) -> Result<Option<u64>, BoxError> {
        // One transaction: repoint ownership AND reset staff together, so a crash
        // between the two can never leave the previous owner's staff with access.
        // Customer memberships (member_type <> 'staff') are deliberately left, and
        // domains/data ride through on the unchanged workspace_id.
        let mut tx = self.pool.begin().await?;
        let moved = sqlx::query(
            "UPDATE routing.workspaces SET account_id = $2, updated_at = now() \
             WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
        if moved.rows_affected() == 0 {
            // Unknown workspace — nothing to transfer; roll back so no partial state.
            tx.rollback().await?;
            return Ok(None);
        }
        let cleared = sqlx::query(
            "DELETE FROM routing.memberships WHERE workspace_id = $1 AND member_type = 'staff'",
        )
        .bind(workspace_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(cleared.rows_affected()))
    }
}
