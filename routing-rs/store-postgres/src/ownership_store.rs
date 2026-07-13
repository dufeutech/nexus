use async_trait::async_trait;
use serde_json::json;
use sqlx::Row;

use router_core::audit::{
    AuditCtx, ACTION_ACCOUNT_PROVISION, ACTION_WORKSPACE_TRANSFER, OUTCOME_OK, OUTCOME_REPLAY,
};
use router_core::store::{Account, AccountMember, BoxError, CreateOutcome, NewAccount, OwnershipStore};

use crate::admin_audit::{record, NewAuditEvent};
use crate::PgRoutingStore;

#[async_trait]
impl OwnershipStore for PgRoutingStore {
    async fn provision_account(
        &self,
        account: &NewAccount<'_>,
        actx: &AuditCtx,
    ) -> Result<CreateOutcome, BoxError> {
        // ONE transaction: the insert-only account create, the owner-membership
        // assert, and the audit event commit together (admin-action-audit: an
        // unrecorded provision does not commit).
        //
        // Insert-only, replay-safe in ONE round trip (server-minted-ids D2): on an
        // idempotency-key conflict the no-op DO UPDATE (the key with itself) locks
        // the existing row so RETURNING yields its ORIGINAL id — no
        // read-after-conflict gap for two same-key racers, and the existing
        // name/payer are never clobbered. `xmax = 0` distinguishes a fresh insert
        // from that replay. A NULL key never conflicts (UNIQUE treats NULLs as
        // distinct), so a keyless create always inserts.
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(
            "INSERT INTO routing.accounts (account_id, name, payer_ref, idempotency_key, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (idempotency_key) DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key \
             RETURNING account_id, (xmax = 0) AS created",
        )
        .bind(account.account_id)
        .bind(account.name)
        .bind(account.payer_ref)
        .bind(account.idempotency_key)
        .fetch_one(&mut *tx)
        .await?;
        let outcome = CreateOutcome { id: row.get("account_id"), created: row.get("created") };
        // Assert the owner membership on create AND on replay (a keyed replay
        // re-asserts, never widens — same row, same role).
        sqlx::query(
            "INSERT INTO routing.account_members (account_id, user_sub, role, updated_at) \
             VALUES ($1, $2, 'owner', now()) \
             ON CONFLICT (account_id, user_sub) DO UPDATE SET \
                 role = EXCLUDED.role, updated_at = now()",
        )
        .bind(&outcome.id)
        .bind(account.owner_sub)
        .execute(&mut *tx)
        .await?;
        record(
            &mut *tx,
            actx,
            &NewAuditEvent {
                action: ACTION_ACCOUNT_PROVISION,
                target_kind: "account",
                target_id: &outcome.id,
                outcome: if outcome.created { OUTCOME_OK } else { OUTCOME_REPLAY },
                detail: json!({ "owner_sub": account.owner_sub, "name": account.name }),
                idempotency_key: account.idempotency_key,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(outcome)
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

    async fn transfer_workspace(
        &self,
        workspace_id: &str,
        account_id: &str,
        actx: &AuditCtx,
    ) -> Result<Option<u64>, BoxError> {
        // One transaction: repoint ownership, reset staff, AND record the audit
        // event together, so a crash between the steps can never leave the
        // previous owner's staff with access — or a committed transfer without
        // its ledger entry. Customer memberships (member_type <> 'staff') are
        // deliberately left, and domains/data ride through on the unchanged
        // workspace_id.
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
        record(
            &mut *tx,
            actx,
            &NewAuditEvent {
                action: ACTION_WORKSPACE_TRANSFER,
                target_kind: "workspace",
                target_id: workspace_id,
                outcome: OUTCOME_OK,
                detail: json!({
                    "account_id": account_id,
                    "staff_removed": cleared.rows_affected(),
                }),
                idempotency_key: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(Some(cleared.rows_affected()))
    }
}
