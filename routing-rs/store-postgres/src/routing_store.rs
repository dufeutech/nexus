use async_trait::async_trait;
use sqlx::Row;

use router_core::auth::{AuthPolicy, PathRule, RouteAuth};
use router_core::domain::{Pool, WorkspaceConfig};
use router_core::store::{BoxError, DomainRecord, RoutingStore};

use crate::PgRoutingStore;

#[async_trait]
impl RoutingStore for PgRoutingStore {
    async fn lookup_domain(
        &self,
        domain: &str,
        wildcard: bool,
    ) -> Result<Option<String>, BoxError> {
        // Point read on the `domain` primary key. `verified = true` enforces
        // RFC C16: an unverified domain MUST NOT resolve on protected routes.
        let row = sqlx::query(
            "SELECT workspace_id FROM routing.domains \
             WHERE domain = $1 AND is_wildcard = $2 AND verified = true",
        )
        .bind(domain)
        .bind(wildcard)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.get::<String, _>("workspace_id")))
    }

    async fn get_workspace(&self, workspace_id: &str) -> Result<Option<WorkspaceConfig>, BoxError> {
        let row = sqlx::query(
            "SELECT workspace_id, plan, target_pool, features, updated_at::text AS updated_at \
             FROM routing.workspaces WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(r) = row else { return Ok(None) };
        // The read path trusts the stored selector: the control plane validated it
        // against the data-driven allow-list (PoolSet) at write time, so re-checking
        // here would only couple the store to that config. If a pool is later
        // removed from the allow-list, the edge route table's default cluster is the
        // backstop (an unknown x-route-pool falls through to `application`).
        let target: String = r.get("target_pool");
        Ok(Some(WorkspaceConfig {
            workspace_id: r.get("workspace_id"),
            plan: r.get("plan"),
            target_pool: Pool::new(target),
            features: r.get::<Vec<String>, _>("features"),
            updated_at: r.get::<Option<String>, _>("updated_at"),
        }))
    }

    async fn upsert_workspace(&self, cfg: &WorkspaceConfig) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.workspaces (workspace_id, plan, target_pool, features, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (workspace_id) DO UPDATE SET \
                 plan = EXCLUDED.plan, target_pool = EXCLUDED.target_pool, \
                 features = EXCLUDED.features, updated_at = now()",
        )
        .bind(&cfg.workspace_id)
        .bind(&cfg.plan)
        .bind(cfg.target_pool.as_str())
        .bind(&cfg.features)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_domain(
        &self,
        domain: &str,
        workspace_id: &str,
        wildcard: bool,
        verified: bool,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.domains (domain, workspace_id, is_wildcard, verified, updated_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (domain, is_wildcard) DO UPDATE SET \
                 workspace_id = EXCLUDED.workspace_id, \
                 verified = EXCLUDED.verified, updated_at = now()",
        )
        .bind(domain)
        .bind(workspace_id)
        .bind(wildcard)
        .bind(verified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn create_pending_domain(
        &self,
        domain: &str,
        workspace_id: &str,
    ) -> Result<bool, BoxError> {
        // INSERT ... ON CONFLICT DO NOTHING never reassigns an existing row's
        // workspace_id, so two workspaces racing the same new domain can't steal it:
        // the loser's insert is a no-op (rows_affected == 0) and the caller resolves
        // it as `domain_taken`. Exact (non-wildcard), unverified by construction.
        let res = sqlx::query(
            "INSERT INTO routing.domains (domain, workspace_id, is_wildcard, verified, updated_at) \
             VALUES ($1, $2, false, false, now()) \
             ON CONFLICT (domain, is_wildcard) DO NOTHING",
        )
        .bind(domain)
        .bind(workspace_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn set_domain_verified(&self, domain: &str, verified: bool) -> Result<(), BoxError> {
        sqlx::query(
            "UPDATE routing.domains SET verified = $2, updated_at = now() \
             WHERE domain = $1 AND is_wildcard = false",
        )
        .bind(domain)
        .bind(verified)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_domain(&self, domain: &str, wildcard: bool) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.domains WHERE domain = $1 AND is_wildcard = $2")
            .bind(domain)
            .bind(wildcard)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn domains_for_workspace(&self, workspace_id: &str) -> Result<Vec<String>, BoxError> {
        let rows = sqlx::query("SELECT domain FROM routing.domains WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("domain")).collect())
    }

    async fn get_domain(
        &self,
        domain: &str,
        wildcard: bool,
    ) -> Result<Option<DomainRecord>, BoxError> {
        let row = sqlx::query(
            "SELECT workspace_id, is_wildcard, verified FROM routing.domains \
             WHERE domain = $1 AND is_wildcard = $2",
        )
        .bind(domain)
        .bind(wildcard)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| DomainRecord {
            workspace_id: r.get("workspace_id"),
            wildcard: r.get("is_wildcard"),
            verified: r.get("verified"),
        }))
    }

    async fn count_domains_for_workspace(&self, workspace_id: &str) -> Result<u32, BoxError> {
        // verified + pending: every row the workspace holds (RFC C3/I6).
        let row = sqlx::query("SELECT count(*) AS n FROM routing.domains WHERE workspace_id = $1")
            .bind(workspace_id)
            .fetch_one(&self.pool)
            .await?;
        let n: i64 = row.get("n");
        Ok(n.max(0) as u32)
    }

    async fn pending_domains(&self) -> Result<Vec<String>, BoxError> {
        let rows = sqlx::query("SELECT domain FROM routing.domains WHERE verified = false")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("domain")).collect())
    }

    async fn expire_pending_domains(&self, ttl_secs: i64) -> Result<Vec<String>, BoxError> {
        // `updated_at` for a pending row is its declare time (an idempotent
        // re-declare touches only the challenge, not this row). The challenge
        // cascades away with the domain.
        let rows = sqlx::query(
            "DELETE FROM routing.domains \
             WHERE verified = false AND updated_at < now() - make_interval(secs => $1) \
             RETURNING domain",
        )
        .bind(ttl_secs as f64)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.get::<String, _>("domain")).collect())
    }

    async fn get_auth_policy(&self, workspace_id: &str) -> Result<AuthPolicy, BoxError> {
        // Point read of the workspace's rule set. No rows -> the default (pass-
        // through) falls out of an empty `AuthPolicy`, so a workspace with no policy
        // is public.
        let rows = sqlx::query(
            "SELECT path_prefix, auth_required, requires_role, requires_entitlement, min_aal, account_scoped \
             FROM routing.auth_routes WHERE workspace_id = $1",
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await?;
        let rules = rows
            .into_iter()
            .map(|r| PathRule {
                prefix: r.get::<String, _>("path_prefix"),
                auth: RouteAuth {
                    required: r.get::<bool, _>("auth_required"),
                    requires_role: r.get::<Option<String>, _>("requires_role"),
                    requires_entitlement: r.get::<Option<String>, _>("requires_entitlement"),
                    min_aal: r
                        .get::<Option<i16>, _>("min_aal")
                        .and_then(|v| u8::try_from(v).ok()),
                    account_scoped: r.get::<bool, _>("account_scoped"),
                },
            })
            .collect();
        Ok(AuthPolicy::new(rules))
    }

    async fn upsert_auth_route(
        &self,
        workspace_id: &str,
        prefix: &str,
        auth: &RouteAuth,
    ) -> Result<(), BoxError> {
        sqlx::query(
            "INSERT INTO routing.auth_routes \
                 (workspace_id, path_prefix, auth_required, requires_role, requires_entitlement, min_aal, account_scoped, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, now()) \
             ON CONFLICT (workspace_id, path_prefix) DO UPDATE SET \
                 auth_required = EXCLUDED.auth_required, \
                 requires_role = EXCLUDED.requires_role, \
                 requires_entitlement = EXCLUDED.requires_entitlement, \
                 min_aal = EXCLUDED.min_aal, \
                 account_scoped = EXCLUDED.account_scoped, \
                 updated_at = now()",
        )
        .bind(workspace_id)
        .bind(prefix)
        .bind(auth.required)
        .bind(auth.requires_role.as_deref())
        .bind(auth.requires_entitlement.as_deref())
        .bind(auth.min_aal.map(i16::from))
        .bind(auth.account_scoped)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_auth_route(&self, workspace_id: &str, prefix: &str) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.auth_routes WHERE workspace_id = $1 AND path_prefix = $2")
            .bind(workspace_id)
            .bind(prefix)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
