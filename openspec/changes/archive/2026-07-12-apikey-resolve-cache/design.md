# Design — apikey-resolve-cache

> HOW for this change. Adds an optional caching layer *beneath* the `customer-api-keys`
> resolve path without altering its behavior contract. The build-vs-adopt call is recorded
> below and should be confirmed with `/opsx:decide` before `/opsx:apply`.

## Context

The api-key authenticator resolves each request with a fresh, fail-closed SELECT: `ApiKeyAuth::resolve` (`identity-rs/sidecar/src/state.rs`) hashes the presented secret and calls `PgApiKeyReader::lookup` (`identity-rs/store-postgres/src/api_keys.rs`) — `WHERE key_hash=$1 AND status='active' AND unexpired` against a SELECT-only pool. `customer-api-keys` deliberately chose *no resident cache* so revocation/expiry take effect on the next request, and it recorded why the service-registry's resident-whole-set pattern was rejected for keys: **keys are a large, per-request-miss-loaded set, not a small enumerable one.**

That reasoning rejects caching the *keyspace*. It does not reject caching the *working set*. An app on an api-key hammers **one** row thousands of times per second; the profile cache (`AppState::resolve`) and the contract cache (`ContractTokenCache`, `token_cache.rs`) already collapse the downstream repeat cost, leaving this SELECT as the only per-request DB hit on the machine hot path. The set of keys *actively presenting traffic at any instant* is tiny even though the total keyspace is unbounded — so a **bounded** cache of recently-resolved keys captures nearly all the benefit while staying memory-bounded.

Two pieces of the mechanism already exist and are load-bearing here:
- The `api_keys` table ships an `api_key_changes` NOTIFY trigger (`store-postgres/migrations/0002_api_keys.sql`) that **nothing currently LISTENs on** — shipped explicitly as a "future opt-in cache/audit-tap" hook (`api_keys.rs`).
- The sidecar already runs feed-listener tasks in this exact shape: `watch_store` (profiles) and `watch_platform_services` (`serve.rs`), each backed by a `PgListener` + `timeout(poll)` self-heal fallback (`platform_services.rs::watch_active`).

## Goals / Non-Goals

**Goals:**
- Collapse "one app, one key, N requests" from N identical resolve SELECTs into ~1 per cache lifetime, relieving the tiny RO pool — **opt-in, default OFF**, byte-for-byte status quo when disabled.
- Preserve every `customer-api-keys` guarantee when enabled: positive-only + fail-closed, expiry always enforced, revocation/rotation effective **within seconds** via targeted invalidation, with self-heal if a signal is dropped.
- Keep `core` DB- and cache-agnostic: the cache is a sidecar adapter behind the existing `ApiKeyReader` port.

**Non-Goals:**
- **Negative caching / credential-stuffing shield** — a hit-only cache does nothing for a flood of *invalid* keys; that is a distinct concern (rate-limit / source-shaped) with opposite pressures. Explicitly out of scope; named so it is not smuggled in.
- Caching the platform **service-token** path — already a resident map warmed by its own feed; unaffected.
- Any change to the HMAC/pepper construction, the `key_hash` scheme, issuance, or the `customer-api-keys` spec.

## Decisions

**Core vs adapters, dependency direction (inward-only):**
- **Core** (`identity-rs/core`) is untouched: the `ApiKeyReader` port already expresses "hash → candidate resolution." The cache is a **decorator** implementing the same port and wrapping `PgApiKeyReader`. Core never learns a cache exists.
- **Adapters** (sidecar): (1) a `CachingApiKeyReader` decorator holding the bounded cache, keyed by `key_hash` → resolved `ApiKeyCandidate`; (2) a **feed-listener task** consuming `api_key_changes` and evicting the affected key's entry; (3) config parsing + metrics. Composition wiring lives in the sidecar `build_api_key_auth` / startup path (`bootstrap.rs` / `main.rs`), matching how `build_signer` / `watch_store` are wired today.

### Decision: cache/eviction store — Adopt `moka` in-process

- **Status**: approved
- **Why**: Sits on the ext_proc fail-closed hot path in front of every request; an in-process read is ~nanoseconds and cannot fail-open on a network blip, whereas a Redis hop (~0.5 ms) adds a network dependency to the availability floor. `moka` (0.12.x, dual MIT/Apache-2.0, actively maintained) gives bounded working-set eviction (TinyLFU/LRU), TTL, and targeted `invalidate(key)` for free — and is already the in-tree house pattern via `ContractTokenCache` (`token_cache.rs`, `moka::sync::Cache`), which explicitly rejected Redis for the same reason.
- **Considered**: L1 moka + L2 Redis (MS Identity Web's two-tier) — adds cross-sidecar sharing a per-pod working set doesn't need, plus a network failure mode; overkill. Hand-rolled bounded LRU (Build) — re-solves a concurrency/eviction problem already shipped in-tree.
- **Isolation**: a `CachingApiKeyReader` decorator implementing the existing `ApiKeyReader` port and wrapping `PgApiKeyReader`; `core` never learns a cache exists.
- **Enterprise validation**: In-process L1 is the credible hot-path tier for fail-closed auth — MS Identity Web ships L1-in-front-of-L2 so auth survives an L2 outage; Kong caches credentials in-process per node and uses the cluster only for invalidation, not lookups.

### Decision: change-feed consumption — Reuse in-tree `PgListener` + `timeout(poll)`, with poll/TTL authoritative

- **Status**: approved
- **Why**: The self-heal fallback (periodic poll + TTL ceiling) is the **correctness guarantee**; the `api_key_changes` NOTIFY is only the fast path for prompt eviction. Reuses the exact in-tree shape (`watch_active` / `watch_platform_services`: `PgListener` + `timeout(poll)`), so no new infra or failure mode. On each notification it evicts **only** the affected entry (`cache.invalidate(key_hash)`) — unlike `watch_platform_services`, which reloads the whole (small, enumerable) active set; keys are an unbounded set and are never enumerated.
- **Considered**: Poll/TTL only, drop NOTIFY — dodges NOTIFY risk but bounds revocation propagation by the poll interval; weaker on "within seconds" unless the poll is tight. External broker (Kafka/Redis pub-sub) with replay — more robust at very high write volume but disproportionate infra for a per-sidecar cache now.
- **Isolation**: a feed-listener task wired in the sidecar startup/watch path (`bootstrap.rs` / `serve.rs`), constructed only when the cache is enabled.
- **LISTEN/NOTIFY scale guardrails** (from research — recall.ai NOTIFY-lock outages, pgdog): `NOTIFY` takes a global commit-serializing lock and has an 8000-byte payload limit, and each `LISTEN` pins a dedicated non-pooled connection. Therefore: keep the payload **tiny — key identifier only, never the row**; run the listener on a **dedicated connection that bypasses the transaction pooler**; and never trust delivery — the TTL/poll self-heal remains authoritative. The NOTIFY payload must carry enough to address the cache key (`key_id` and/or `key_hash`); if only `key_id`, either widen the payload in the existing migration or fall back to the TTL ceiling for that entry — see Open Questions.

**Fail-closed & expiry discipline (conforms to `customer-api-keys` + `identity-revocation-integrity`):**
- Cache stores **only** a positive resolution of a currently-valid key. Misses, invalid keys, and rejections are never stored (no negative cache).
- Each cached entry carries the key's `expires_at`; a hit whose entry is past expiry is treated as a miss → live resolve → reject. TTL is the staleness ceiling, independent of and never exceeding the guarantees above.
- On revocation via feed → targeted eviction (within seconds). On dropped signal → TTL/poll self-heal (bounded seconds). Both strictly satisfy the spec's "within seconds."

**Configuration (single source of truth, opt-in, mirrors `CONTRACT_CACHE_*`):**
- `APIKEY_RESOLVE_CACHE_ENABLED` (default **false**), `APIKEY_RESOLVE_CACHE_TTL_SECONDS`, `APIKEY_RESOLVE_CACHE_MAX_CAPACITY`, `APIKEY_RESOLVE_CACHE_POLL_SECONDS` (self-heal fallback). Parsed in the sidecar config path next to the contract-cache knobs; documented in `deploy/README.md`, compose, and Helm values. Disabled ⇒ the decorator and listener are never constructed (zero behavioral or code-path change).

**Metrics:** `sidecar_apikey_resolve_cache_hits` / `_misses` / `_evictions`, registered alongside `sidecar_contract_cache_hits` / `_mints` (`state.rs`).

**Data-is-not-code:** no new DDL; reuses the shipped `api_key_changes` trigger. If the NOTIFY payload must be widened to include `key_hash`, that edit lives in the existing `.sql` migration, never inlined.

## Risks / Trade-offs

- **[A cached entry outlives a revocation if BOTH the feed and the poll fail]** → Mitigation: TTL is a hard ceiling on entry age regardless of signals; choose TTL to match the `customer-api-keys` "within seconds" bar (small, e.g. single-digit seconds), so even total-signal-loss staleness is bounded by TTL. Default-off means the stronger next-request guarantee is the default.
- **[NOTIFY payload lacks `key_hash`, so targeted eviction can't find the entry]** → Mitigation (Open Question): extend the payload in the existing migration, or key the cache so the notified identifier can address it; absent that, the TTL ceiling still bounds staleness (correctness preserved, just less prompt for that window).
- **[Enabling weakens the current "revocation on the very next request" to "within seconds"]** → This is a deliberate, operator-chosen trade (throughput for a bounded staleness window) and is *exactly* what `customer-api-keys` already permits ("within seconds"). Default-off keeps the stronger guarantee unless explicitly opted into.
- **[Cache key is the secret hash — a sensitive value in memory]** → It is the same `key_hash` already held transiently during every resolve and stored in the DB; no new secret exposure. Never log the key or hash.
- **[Working-set assumption fails under high-cardinality churn (many distinct keys, each once)]** → Then hit-rate is low and the cache mostly misses to the live path — degrades to status quo plus small overhead, never to incorrectness. Capacity bound caps the memory cost of that case.

## Migration Plan

1. Land the `CachingApiKeyReader` decorator + bounded cache + config parsing + metrics, all gated behind `APIKEY_RESOLVE_CACHE_ENABLED=false`. No behavior change while off.
2. Land the `api_key_changes` listener task (targeted eviction) + poll self-heal, constructed only when the cache is enabled. Widen the NOTIFY payload in-migration if Open Questions resolves that way.
3. Verify (cache OFF): behavior identical to today — fresh resolve per request, revoke effective next request.
4. Verify (cache ON): repeat requests hit cache (metrics), DB resolve count drops; revoke → rejected within seconds; rotate → old secret rejected within seconds; expired cached key rejected; dropped-signal (skip NOTIFY) → self-heals within TTL.
5. Roll out disabled; enable per-environment as an operational decision once verified.

**Rollback:** set `APIKEY_RESOLVE_CACHE_ENABLED=false` — instant return to the live-resolve path, no data migration to undo (cache is in-process, table/trigger were already present).

## Open Questions — RESOLVED (apply)

- **NOTIFY payload = `key_id` only** (confirmed against `0002_api_keys.sql` / `PgApiKeyStore::init_schema`: `pg_notify('api_key_changes', COALESCE(NEW.key_id, OLD.key_id))`). The cache is keyed by `key_hash`, so a `key_id`-only signal cannot address an entry directly. **Resolution: do NOT widen the payload.** The decorator keeps an in-process `key_id → key_hash` reverse index (bounded + TTL'd alongside the entry map), so a `key_id` signal targets exactly one `key_hash` entry — satisfying "only the affected key is invalidated" without a migration change and without ever putting the sensitive hash on the NOTIFY wire. Task 4.4 (widen payload) is therefore **not needed**.
- **TTL default = 5 seconds** (`APIKEY_RESOLVE_CACHE_TTL_SECONDS`), matching the contract-cache TTL and the `customer-api-keys` "within seconds" bar. It is the staleness ceiling: even under total signal loss (feed + a wedged listener), a cached entry is re-resolved live within 5s.

## Implementation refinements (recorded at apply)

- **`ApiKeyCandidate` gains one intrinsic field `expires_at: Option<i64>`** (epoch secs; `None` = no expiry). The reader already filters on expiry in SQL but did not surface the value; the cache needs it to enforce the key's own expiry on a hit (spec: "Cached key past expiry is rejected"). This is a scalar property of a resolved key, **not** a cache type — `core` stays cache-agnostic (no `moka`/cache symbol crosses the port). The live path ignores it (the DB `expires_at > now()` filter remains the enforcement).
- **Self-heal is authoritative** (per `/opsx:decide`): the change feed yields `Ok(Some(key_id))` to evict, `Ok(None)` as a poll heartbeat; the moka TTL — not NOTIFY delivery — is the correctness ceiling. The listener uses a fresh `PgListener` session connection (bypass the txn pooler) and a tiny `key_id`-only payload, per the LISTEN/NOTIFY scale guardrails.
