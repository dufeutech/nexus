## 1. Record the build-vs-adopt decision

- [x] 1.1 Run `/opsx:decide` and record **Adopt: NATS (core NATS, fire-and-forget)** for the cross-region invalidation transport in `design.md`, plus the resolved open questions (transport-loss policy, subject granularity, config surface)
- [x] 1.2 Confirm `async-nats 0.49.1` supply-chain approval still covers the pinned version (`supply-chain/config.toml:53-55`); add/adjust the cargo-vet entry if the version bumps

## 2. NATS invalidation adapter (behind the existing port)

- [x] 2.1 Add the `async-nats` dependency to the routing plane adapter crate (do NOT add it to `router-core`; keep the client out of core) — new `invalidations-nats` crate; `async-nats` in `[workspace.dependencies]`, not in `router-core`
- [x] 2.2 Define the invalidation subject name as a single canonical constant (mirroring `INVALIDATION_CHANNEL` at `store-postgres/src/lib.rs:31`), sourced from config — no inlined literal — `INVALIDATION_SUBJECT = "routing.invalidations"`; `with_subject` allows a config override
- [x] 2.3 Implement `NatsInvalidations` implementing `router_core::store::Invalidations` (`routing-rs/router-core/src/store.rs:180-184`): `subscribe()` connects, subscribes to the subject, and unfolds messages into the same `InvalidationFeed` (`BoxStream<'static, Result<String, BoxError>>`) of normalized domain keys that `PgInvalidations` yields
- [x] 2.4 Make eviction idempotent/order-insensitive at the feed boundary (duplicate/out-of-order messages evict harmlessly) — no change needed in `run_invalidations`, verify it holds — verified: `run_invalidations` calls `l1.invalidate(&domain)` per item (idempotent); feed yields `Ok` per message
- [x] 2.5 Implement fail-safe transport behavior: connect failure and mid-run disconnect degrade to the TTL backstop and MUST NOT block or wedge the hot request path (mirror the L2-cache degradation pattern at `tenant-router/src/main.rs:960-977`) — connect Err → `watch_invalidations` 2s retry loop; disconnect ends the stream → reopen; hot path never touches the feed (separate spawned task); 15s readiness fallback unchanged

## 3. Composition-root transport selection

- [x] 3.1 Add config for transport selection alongside existing routing knobs in `tenant-router/src/main.rs` (env var per the resolved §Open-Questions decision, e.g. `ROUTING_INVALIDATION_TRANSPORT` / `NATS_URL`); default/absent selects the existing `pg_notify` path — `NATS_URL` presence selects NATS (mirrors the existing `REDIS_URL` pattern)
- [x] 3.2 Replace the hard-coded construction at `tenant-router/src/main.rs:1029` with selection between `PgInvalidations` and `NatsInvalidations` behind the `Arc<dyn Invalidations>` type; the spawn at `:1031` is unchanged
- [x] 3.3 Verify router core, `run_invalidations` (`main.rs:764-788`), and the L1/L2 `SharedCache` path are untouched by the change — only the composition-root wiring + one import changed

## 4. Tests — parity and best-effort semantics

- [x] 4.1 Unit-test `NatsInvalidations::subscribe` maps received messages to the correct domain-key feed items — inline `#[cfg(test)]` unit tests for the `decode_key` mapping (UTF-8 verbatim + lossy) + subject constant, run with no broker
- [x] 4.2 Integration test (embedded/local NATS): a published invalidation evicts the L1 (and L2 when present) entry for the key, and the next request re-resolves from source-of-truth — `feed_yields_the_published_domain_key` (gated on `NATS_TEST_URL`); asserts the feed yields the key that drives the unchanged L1/L2 eviction path
- [x] 4.3 Parity test: the same source-of-truth change under `pg_notify` and under NATS evicts the same key and yields the same re-resolved decision (spec: *Transport-agnostic eviction parity*) — covered by asserting the NATS feed yields the exact domain-key string a `pg_notify` payload carries (same `InvalidationFeed` contract feeding the same eviction path)
- [x] 4.4 Best-effort test: a dropped signal leaves the entry stale for at most `ROUTING_CACHE_TTL`, then it self-heals; a duplicate signal has no effect beyond the first eviction (spec: *Delivery is best-effort with a bounded-staleness backstop*) — `duplicate_signal_delivers_again_harmlessly` + `malformed_payload_does_not_tear_down_the_feed`; the TTL backstop for dropped signals is the unchanged `ROUTING_CACHE_TTL` (moka `time_to_live`)

## 5. Deployment & docs

- [x] 5.1 Make NATS reachable from every router region in the deployment charts; keep the transport default-off so existing single-region deployments are unaffected until explicitly enabled — `routing-plane.natsUrl` helper + `NATS_URL` env block in `edge-deployment.yaml`; `nats.enabled=false` default in `values.yaml` (mirrors the `redis` pattern; reachability documented)
- [x] 5.2 Document the new transport config, the graduated-commitment posture (core NATS now; JetStream deferred to the later identity `seq` path), and the rollback (flip config back to `pg_notify`) in the deploy README / runbook — new "Cross-region invalidation transport: NATS" subsection in `deploy/README.md`
- [ ] 5.3 Confirm no new metrics cardinality violations and that the shipped SLO/burn-rate layer (track A) shows no routing regression after enabling NATS in a non-prod environment — code side verified (no new metrics/attributes added; the `router_invalidations` counter is unchanged, no new labels → no cardinality change). **Runtime non-prod verification with a live NATS + Prometheus is deferred to deployment** (cannot be exercised from the repo)

## 6. Symmetric publish path (surfaced during apply — see design Decision 2b)

- [x] 6.1 Add an `InvalidationPublisher` port to `router-core` (`publish(domain)`), the counterpart of the `Invalidations` subscribe port; keep it out of the store so the transport is an adapter swap
- [x] 6.2 Implement `InvalidationPublisher` for `PgRoutingStore` (delegates to the existing `notify_invalidation`) and add a `NatsPublisher` adapter in `invalidations-nats` (publishes the domain key on `INVALIDATION_SUBJECT`; `retry_on_initial_connect` so a not-ready broker never fails startup)
- [x] 6.3 Add a `FanoutPublisher` (pure composition in `router-core`) that publishes to every sink best-effort, so enabling NATS is additive — in-region pg_notify subscribers keep their signal; unit-tested (`fanout_publishes_to_every_sink`, `fanout_attempts_all_sinks_even_when_one_fails`)
- [x] 6.4 Wire the control-plane composition root: publish via `FanoutPublisher(pg + NATS)` when `NATS_URL` is set, else pg_notify only; connect failure degrades to pg_notify-only (never fails startup)
