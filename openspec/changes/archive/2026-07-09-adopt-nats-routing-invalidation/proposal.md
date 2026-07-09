## Why

Routing-cache invalidation today rides Postgres `LISTEN/NOTIFY`, which is delivered
**only within a single Postgres server** — physical replicas do not forward `NOTIFY`. The
moment a router instance runs against a different region (a read replica, an async failover
target, or a second write region), it stops receiving invalidations and serves stale routing
decisions until the 600s cache TTL expires. This is the first — and thinnest, most reversible —
blocker on the recorded multi-region/HA direction (track **D**: failure-survival → CNPG, signals
→ a cross-region transport). Doing it now delivers a cross-region freshness win even before full
multi-region lands, and does so behind an already-existing port with no change to router core.

## What Changes

- Introduce a **cross-region-capable routing-invalidation transport** as an alternative to the
  intra-server `pg_notify` feed, selected by configuration. The default (existing) behavior is
  preserved; the new transport is opt-in and fully reversible via config.
- Preserve **observable parity**: an invalidation carried by the router's `Invalidations` port
  (today the `routing_invalidations` channel) still results in the corresponding L1/L2 cache
  eviction; only the delivery path changes. (The `routing_membership_changes` channel is consumed by
  a separate `membership-sync` service, not this port, and is out of scope here.)
- Keep delivery **best-effort with the existing TTL backstop** as the correctness floor: a dropped
  signal degrades to bounded staleness (≤ the routing cache TTL), never to incorrectness — matching
  the current fire-and-forget semantics.
- Add the **symmetric publish path**: a new `InvalidationPublisher` port (the counterpart of the
  existing subscribe-side `Invalidations` port) with pg_notify and NATS adapters, so the control
  plane publishes cross-region. When NATS is enabled the control plane **fans out to pg_notify AND
  NATS**, so enabling the new transport is purely additive — in-region pg_notify subscribers never
  lose the signal. Without a publisher, a NATS subscriber would receive nothing and silently degrade
  to TTL-only, so the two halves ship together.
- The subscribe-side `Invalidations` port is **unchanged**; a new adapter implements it. Redis stays
  exactly as-is (an optional L2 value cache, not a bus).
- Scope is the **routing plane only.** The identity-plane `seq`/revocation path (bespoke, durable,
  security-timed) is explicitly **out of scope** and sequenced later.

## Capabilities

### New Capabilities
- `routing-invalidation-propagation`: The observable contract for how a change to routing
  source-of-truth reaches every router instance's cache — delivery reach (including across a region
  edge, not just within one Postgres server), best-effort semantics with a bounded-staleness TTL
  backstop, and transport-agnostic parity of the resulting cache eviction. Names the
  **reliability-critical transport** concern whose concrete tool is deferred to `/opsx:decide`.

### Modified Capabilities
<!-- None. The current pg_notify invalidation behavior is not specified in any existing capability;
     this change introduces the first behavioral contract for it rather than modifying one. Router
     resolution specs (domain-host-resolution, workspace-tenancy) are unaffected. -->

## Impact

- **Code:** a new `NatsInvalidations` adapter implementing the existing
  `router_core::store::Invalidations` (subscribe) port, plus a new `InvalidationPublisher` (publish)
  port in `router-core` with pg_notify + NATS adapters and a `FanoutPublisher` composition; config
  selection at both composition roots (`tenant-router` subscribes, `control-plane` publishes). The
  resolution logic and the moka L1 / Redis L2 `SharedCache` are untouched.
- **Dependencies:** adds a message-transport client crate (critical-concern, tool chosen in
  `/opsx:decide`). Introduces a new platform runtime component to operate — priced as a graduated
  commitment (fire-and-forget first; durability only if/when the identity path later needs it).
- **Config/Ops:** a new transport-selection setting alongside the existing routing knobs; the current
  `pg_notify` path remains the default so no deployment is forced to adopt it. New component must be
  reachable from every router region.
- **Out of scope / unaffected:** identity-plane `identity_changes` transport, CNPG deployment, and
  edge↔box mTLS — the other two pieces of the B-gate+D program, each proposed separately.
