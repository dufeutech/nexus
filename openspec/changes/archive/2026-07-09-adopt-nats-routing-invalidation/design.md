## Context

The `tenant-router` plane caches routing decisions (moka L1, optional Redis L2) and evicts
them on demand. Eviction is driven by a single port, `router_core::store::Invalidations`
(`routing-rs/router-core/src/store.rs:180-184`), whose one method
`async fn subscribe() -> Result<InvalidationFeed, BoxError>` yields a
`BoxStream<'static, Result<String, BoxError>>` of normalized domain keys. The feed drives
`run_invalidations` (`tenant-router/src/main.rs:764-788`), which calls `state.l1.invalidate`
and, if present, `l2.invalidate` per key.

The only adapter today is `PgInvalidations` (`routing-rs/store-postgres/src/lib.rs:900-926`),
which opens a `PgListener` and `LISTEN`s on the `routing_invalidations` channel. It is
hard-constructed at the composition root (`tenant-router/src/main.rs:1029`) and spawned at
`:1031` — there is no transport-selection switch; the `Arc<dyn Invalidations>` type is already
the abstraction, only the concrete constructor is fixed.

The constraint that forces this change: **Postgres `LISTEN/NOTIFY` is delivered only within a
single Postgres server** — physical replicas do not forward `NOTIFY`. Any router instance
running against a replica, a failover target, or a second region stops receiving invalidations
and serves stale routes until `ROUTING_CACHE_TTL` (default 600s, `main.rs:946`, applied as the
moka `time_to_live` at `:984`) expires the entry. This is the first, thinnest, reversible
blocker on the recorded track-D direction (failure-survival → CNPG; signals → a cross-region
transport). The port's own doc comment (`store.rs:177-179`) anticipates exactly this: it is
"kept distinct from the store so a different transport (a message bus, a poll) is an adapter
swap, never a core change."

## Goals / Non-Goals

**Goals:**
- Deliver routing invalidations across a region edge, not just within one Postgres server.
- Implement the new transport as a second adapter behind the existing `Invalidations` port —
  router core, `run_invalidations`, and the L1/L2 `SharedCache` remain untouched.
- Keep the existing `pg_notify` path as the default; the new transport is opt-in and reversible
  by configuration alone.
- Preserve best-effort semantics with the TTL backstop as the correctness floor (fire-and-forget
  is sufficient; the routing plane has no per-second revocation requirement — documented at
  `store-postgres/src/lib.rs:11-13`, `main.rs:774-776`, `deploy/README.md:591`).

**Non-Goals:**
- The identity-plane `identity_changes` / `seq` revocation path. It is bespoke, durable, and
  security-timed; it needs a port introduced first and durable (replayable) delivery. Sequenced
  later.
- The `routing_membership_changes` channel — consumed by the separate `membership-sync` service,
  not this port.
- CNPG deployment and edge↔box mTLS — the other two pieces of the B-gate+D program, proposed
  separately.
- Durable / replay-from-cursor delivery, cross-region stream mirroring, and promoting Redis to a
  bus. Out of scope; this slice is fire-and-forget only.

## Decisions

### Decision: Cross-region invalidation transport — Adopt core NATS (fire-and-forget)

- **Status**: approved
- **Why**: Interest-based gateway/supercluster fan-out is a 1:1 fit for broadcast-to-every-router across regions, at a ~20MB/10–50MB footprint; at-most-once is safe because `ROUTING_CACHE_TTL` is the correctness floor, and `async-nats 0.49.1` is already cargo-vet-approved. Self-writing a cross-region transport is the defect this gate prevents.
- **Considered**: *Redis pub/sub as bus* — no native cross-region (needs app-level forwarding) and promotes an optional value cache to a load-bearing bus (new personality); *Extend pg_notify (bridge/poll)* — hand-rolls a transport and leaves `NOTIFY`'s single-server scope (replicas don't forward NOTIFY) unsolved; *JetStream* — durable/RAFT infra the routing path doesn't need, reserved for the later identity `seq` path (graduated commitment).
- **Isolation**: a `NatsInvalidations` adapter behind the unchanged `router_core::store::Invalidations` port; the concrete NATS client stays in the routing-plane adapter crate, selected at the composition root with `pg_notify` as the reversible default.

The narrative below is the supporting rationale for the block above.

### Decision 1 — Adopt a message transport for cross-region delivery (critical concern)

The reliability-critical concern is **cross-region invalidation delivery**. Per CLAUDE.md
(Rent > Adopt > Extend > Fork > Build), self-writing a distribution transport is a defect when a
mature option exists. **Recommendation: Adopt NATS (core NATS, fire-and-forget subjects)** for
this slice, behind the existing port.

Rationale (recorded via `/opsx:decide`, 2026-07-09 — see the approved block above):
- Native fan-out pub/sub matches broadcast-to-every-router semantics; cross-region fan-out
  (gateways/superclusters) is first-class.
- The user intends to run NATS as a platform component regardless (recorded in
  `platform-ha-and-hardening/EXPLORATION.md §4`), which collapses the "no new service" argument
  that previously favored reusing Redis — and Redis is not a bus today (it is an optional value
  cache; using it as a bus would be a new personality and promote it optional → load-bearing).
- `async-nats 0.49.1` is already cargo-vet-approved (`supply-chain/config.toml:53-55`,
  `safe-to-deploy`), so adoption clears the supply-chain gate — though it is not yet a wired code
  dependency in any `Cargo.toml`/`Cargo.lock`.

Alternatives considered:
- **Extend pg_notify via replica bridge / poll:** keeps one dependency but hand-builds a
  cross-region transport (the defect the hierarchy warns against) and fights `NOTIFY`'s
  single-server scope. Rejected.
- **Redis pub/sub or Streams as the bus:** a new usage mode plus promoting an optional cache to
  load-bearing; the only advantage (no new service) is void once NATS runs anyway. Rejected.
- **Core NATS vs JetStream for this slice:** JetStream (durable, RAFT, file storage) is real infra
  the routing path does not need — the TTL backstop already tolerates drops. Adopt **core NATS**
  now; reserve JetStream for the later identity `seq` path. This keeps NATS a *graduated*
  commitment and avoids the YAGNI trap flagged in the exploration.

### Decision 2 — Subscribe adapter behind the unchanged `Invalidations` port

Add a `NatsInvalidations` adapter (crate `invalidations-nats`) implementing
`Invalidations::subscribe`, converting received messages into the same `InvalidationFeed`
(`BoxStream` of domain-key strings) that `PgInvalidations` produces. The feed contract is the
seam; downstream (`run_invalidations` → L1/L2 eviction, lazy re-resolution) is identical for both
adapters. Dependency direction stays inward: the concrete NATS client is confined to the adapter
crate; router core depends only on the port.

### Decision 2b — Symmetric publish path (`InvalidationPublisher` port + fan-out)

**Surfaced during apply (2026-07-09), recorded via `AskUserQuestion`.** A subscribe adapter alone
is inert: nothing publishes to the NATS subject (the control plane only ran
`pg_notify('routing_invalidations', …)`), so enabling `NATS_URL` on a router would deliver *zero*
invalidations and silently degrade freshness to the TTL — a regression, not a win. The subscribe
and publish halves must ship together.

Introduce a **new `InvalidationPublisher` port** in `router-core` (`publish(domain)`), the
counterpart of `Invalidations` — kept out of the store so the transport is an adapter swap. Two
adapters implement it: `PgRoutingStore` (delegates to its existing `notify_invalidation`) and
`NatsPublisher` (in `invalidations-nats`). The control plane publishes through a **`FanoutPublisher`**
(pure composition in `router-core`, no external dep) that, when NATS is enabled, publishes to
**pg_notify AND NATS**. This keeps enabling the transport **additive**: in-region subscribers still
on pg_notify never lose the signal while cross-region subscribers get it over NATS. Fan-out is
best-effort — every sink is attempted even if one fails; the last error is logged (the write already
committed, TTL heals). A NATS connect failure degrades the control plane to pg_notify-only, never
failing startup (`NatsPublisher::connect` uses `retry_on_initial_connect`).

### Decision 3 — Transport selected at the composition roots, pg_notify default

Selection is by configuration via **`NATS_URL`** (presence-based, mirroring the existing `REDIS_URL`
pattern) at two composition roots — `tenant-router/src/main.rs` (subscribe) and
`control-plane/src/main.rs` (publish). Absence selects the existing `pg_notify` path at both, so no
deployment is forced to change and rollback is unsetting the env var. Connection details (NATS URL,
subject) are config injected at runtime — not inlined literals — and the subject name has one
canonical definition (`invalidations_nats::INVALIDATION_SUBJECT = "routing.invalidations"`),
mirroring how `INVALIDATION_CHANNEL` is defined once today (`store-postgres/src/lib.rs:31`).

## Risks / Trade-offs

- **New runtime component to operate** → priced as a graduated commitment: core NATS only,
  fire-and-forget; JetStream deferred. Charts/deployment must make NATS reachable from every
  router region before the transport is switched on; until then the default `pg_notify` path is
  unaffected.
- **At-most-once delivery drops a signal** → acceptable and by design: the `ROUTING_CACHE_TTL`
  backstop bounds worst-case staleness, and the routing plane has no per-second revocation
  requirement. The identity revocation path (which does) is explicitly out of scope.
- **NATS unavailable at startup / mid-run** → fails safe like the L2 cache. Subscriber: a connect
  error makes `watch_invalidations` retry every 2s; a disconnect ends the stream and reopens; the
  hot resolve path never touches the feed (separate task) and the 15s readiness fallback still fires.
  Publisher: `NatsPublisher::connect` uses `retry_on_initial_connect` (never fails control-plane
  startup) and the fan-out degrades to pg_notify-only on a connect error. Either way, staleness is
  bounded by the TTL — never a hot-path outage.
- **Reversibility** → because the change is a config-selected adapter behind an unchanged port,
  rollback is flipping the config back to `pg_notify`; no schema or core change to unwind.
- **Ordering/duplicates** → eviction is idempotent and order-insensitive (evict-then-lazy-resolve),
  so pub/sub's weaker ordering guarantees are safe.

## Migration Plan

1. Land the subscribe adapter (`NatsInvalidations`) **and** the publish path (`InvalidationPublisher`
   + `FanoutPublisher` + `NatsPublisher`) with `pg_notify` as default at both composition roots — no
   behavioral change for existing single-region deployments.
2. Stand up NATS reachable across router regions; set `NATS_URL` on the control plane first (it
   fans out to pg_notify AND NATS, so nothing is lost), then on routers. Verify parity (same key
   evicted, same re-resolution) against the `pg_notify` baseline in a non-prod environment.
3. Roll out per-environment via config; the SLO/burn-rate layer already shipped (track A) is the
   instrument for confirming no regression.
4. Rollback = unset `NATS_URL` (control plane falls back to pg_notify-only; routers back to the
   pg_notify feed). No schema or core change to unwind.

## Open Questions (resolved at apply)

1. **Transport-loss policy** → *resolved:* degrade to the TTL backstop silently (matching L2 cache
   degradation); the hot path never blocks on the bus. See Risks above.
2. **Subject granularity** → *resolved:* one broadcast subject (`routing.invalidations`), matching
   today's single-channel model; interest-based gateway routing already skips regions with no
   subscribers, so per-tenant subjects buy nothing yet.
3. **Config surface** → *resolved:* presence of `NATS_URL` selects NATS at both composition roots
   (mirrors the existing `REDIS_URL` pattern); absence keeps pg_notify.
4. **Publisher gap** → *resolved:* the symmetric publish path (Decision 2b) ships in this change; a
   subscribe-only slice would have been a freshness regression when enabled.
