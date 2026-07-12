use async_trait::async_trait;
use sqlx::Row;

use router_core::store::{BoxError, Challenge, ChallengeStore};

use crate::PgRoutingStore;

#[async_trait]
impl ChallengeStore for PgRoutingStore {
    async fn mint_or_get_challenge(
        &self,
        domain: &str,
        workspace_id: &str,
        ttl_secs: i64,
    ) -> Result<Challenge, BoxError> {
        // Mint a fresh ownership-proof token: 256 bits from the OS CSPRNG (ring's
        // `SystemRandom`), hex-encoded (DNS-safe charset, so it drops straight into
        // a TXT record). Minted here in security-aware Rust rather than via SQL
        // `gen_random_uuid()` so the token's entropy does not depend on the
        // database build's RNG configuration.
        fn mint_challenge_token() -> Result<String, BoxError> {
            use ring::rand::{SecureRandom, SystemRandom};
            let mut bytes = [0_u8; 32];
            SystemRandom::new()
                .fill(&mut bytes)
                .map_err(|_| "csprng failure")?;
            Ok(hex::encode(bytes))
        }
        // Idempotent (RFC C3): insert a fresh token if absent; on conflict, keep
        // the existing token while it is live and re-issue only once expired
        // (RFC C4: re-issuable). RETURNING reflects the resulting row, so a
        // re-issue returns `expired = false`. The freshly minted $4 is used only
        // when inserting or re-issuing an expired row; a live row keeps its token.
        // is_wildcard is fixed false: a challenge always proves the EXACT declared
        // domain (the only thing self-service declares), so it keys to the
        // (domain, false) row the declare flow created just before this call.
        let token = mint_challenge_token()?;
        let row = sqlx::query(
            "INSERT INTO routing.domain_challenges (domain, is_wildcard, workspace_id, token, expires_at, updated_at) \
             VALUES ($1, false, $2, $4, now() + make_interval(secs => $3), now()) \
             ON CONFLICT (domain, is_wildcard) DO UPDATE SET \
                 token = CASE WHEN routing.domain_challenges.expires_at < now() \
                              THEN $4 \
                              ELSE routing.domain_challenges.token END, \
                 expires_at = CASE WHEN routing.domain_challenges.expires_at < now() \
                              THEN now() + make_interval(secs => $3) \
                              ELSE routing.domain_challenges.expires_at END, \
                 workspace_id = EXCLUDED.workspace_id, \
                 updated_at = now() \
             RETURNING domain, token, (expires_at < now()) AS expired",
        )
        .bind(domain)
        .bind(workspace_id)
        .bind(ttl_secs as f64)
        .bind(&token)
        .fetch_one(&self.pool)
        .await?;
        Ok(Challenge {
            domain: row.get("domain"),
            token: row.get("token"),
            expired: row.get("expired"),
        })
    }

    async fn get_challenge(&self, domain: &str) -> Result<Option<Challenge>, BoxError> {
        let row = sqlx::query(
            "SELECT domain, token, (expires_at < now()) AS expired \
             FROM routing.domain_challenges WHERE domain = $1 AND is_wildcard = false",
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| Challenge {
            domain: r.get("domain"),
            token: r.get("token"),
            expired: r.get("expired"),
        }))
    }

    async fn delete_challenge(&self, domain: &str) -> Result<(), BoxError> {
        sqlx::query("DELETE FROM routing.domain_challenges WHERE domain = $1 AND is_wildcard = false")
            .bind(domain)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
