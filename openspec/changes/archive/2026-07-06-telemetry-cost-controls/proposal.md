# Proposal: telemetry-cost-controls

## Why

The telemetry stack is now complete and correct (edge-rooted tracing, the box
telemetry contract, first-party compliance) — but every store runs the **lab
default: local disk** with fixed retention, and nothing bounds what a single
producer can cost. Two independent bill problems follow: the **baseline** (volume ×
retention × an expensive storage tier) and the **worst case** (one box adds an
unbounded label or a chatty log and the metrics series / log volume — and the bill —
explode overnight). Both are solved by mature, standardized configuration of the
stack we already run; neither needs anything hand-built. This change graduates the
stores to the production cost posture the earlier designs explicitly deferred
("local-disk now / object-storage-later, a config change here only") and puts a
fail-safe cost ceiling at the single egress we already own.

## What Changes

- **Baseline cost — object storage + retention tiering.** The three stores move off
  local disk onto an object-storage tier (the architecture Loki/Tempo were built
  for; ~10–20× cheaper per GB and horizontally scalable), each with an explicit,
  per-signal retention policy sized to that signal's purpose (traces are a
  short-lived debugging signal; logs an investigation trail; metrics the cheapest by
  volume). Retention becomes a stated, owned value, not an implicit default.
- **Worst-case cost — a cost ceiling enforced at the single egress.** The collection
  layer (the one telemetry egress every producer already knows) gains guards that
  bound what any producer can cost regardless of its behavior: high-cardinality
  label control, log-volume/noise control, and per-signal limits — so a misbehaving
  box degrades *its own* telemetry fidelity rather than the whole bill. Enforcement
  lives in one place; producers are unchanged.
- **Sampling economics stay simple — keep head sampling, do NOT add tail sampling.**
  The edge's head-sampling decision remains the cost ceiling (it saves generation +
  transport + collector + storage — everything). Tail sampling is explicitly ruled
  out here: it saves only storage (which object storage already makes cheap), costs
  ingest + a stateful contrib collector, and collides with the shipped "head decision
  is the ceiling, the collector may only subtract" invariant. Recorded so the
  tempting-but-wrong optimization is a documented non-goal, not a gap.
- **The lab stays runnable on a clean checkout.** The object-storage tier must have a
  zero-dependency local mode (an in-tree object-storage emulator or filesystem-object
  shim) so `docker compose up` needs no cloud account; production points the same
  config at real object storage via env.
- **Docs:** deploy README observability guidance gains the cost model (storage tier,
  retention table, the egress cost-ceiling knobs); the box telemetry contract notes
  that cardinality/volume are bounded at the collector.
- **Out of scope (successor changes, recorded in design):** long-term metric
  retention / downsampling via Mimir or Thanos (metrics are the cheapest signal; defer
  until real history need); SLO targets + burn-rate alerting on the RED baseline;
  tail/error-biased trace retention.

## Capabilities

### New Capabilities

- `telemetry-cost-controls`: the cost guarantees of the telemetry stack — each signal
  stored on a cheap, scalable tier with an explicit retention bound, and a fail-safe
  cost ceiling enforced at the single egress so no single producer can blow up the
  bill. Critical concerns for the build-vs-adopt gate (tool choice deferred to
  `/opsx:decide`): **object-storage backend + its local-dev emulation** (a
  reliability- and cost-sensitive adopt, never hand-built), **cardinality/label
  control mechanism at the collection layer**, and **log-volume/noise control
  mechanism** — all standard collection-layer configuration, none a build candidate.

### Modified Capabilities

<!-- none at the requirement level: box-telemetry-contract already states single-
     egress + fail-open + PII hygiene; this change adds cost bounds as a new
     capability rather than changing the emission contract. The retention values and
     store backends are HOW (design/config), not a change to any spec's WHAT. -->

## Impact

- **Monitoring stack config** (`monitoring/{tempo,loki,prometheus,otel-collector}`):
  store backends repoint to object storage (env-driven endpoint/bucket/creds); the
  collector config gains cost-ceiling processors. No producer changes.
- **Lab compose + deploy compose + helm:** an object-storage emulator service in the
  lab; object-storage endpoint/credentials as env in deploy/helm (external, like every
  other stateful dependency). Retention values become configurable.
- **Boxes / first-party services:** unchanged — they still emit to the one endpoint;
  cardinality/volume bounding happens downstream of them at the collector.
- **Docs:** `deploy/README.md`, `nexus-upstream-requirements.md` (contract note).
- **No behavior change for tenants or request handling;** telemetry stays fail-open,
  and the cost ceiling degrades telemetry fidelity under abuse, never request paths.
