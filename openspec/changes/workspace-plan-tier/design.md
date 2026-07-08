# Design — workspace-plan-tier

## Context

Plan tier is **not new state** — it already ships as a nexus-owned, vendor-free fact on the
routing plane. The prior `nexus-owned-workspace-tenancy` change established the model
(*"plan lives on the workspace, the payer on the account"*) and it is live in code:

- `routing.workspaces.plan text NOT NULL DEFAULT 'free'` (`routing-rs/store-postgres/src/lib.rs:155-160`),
  written by the control-plane workspace UPSERT (`plan = EXCLUDED.plan`, `lib.rs:412`).
- `router-core::PlanLimits` — a **config-driven** (never compiled-in) plan→limits table
  (`router-core/src/domain.rs:37`), already consumed by a control-plane quota endpoint
  (`control-plane/src/main.rs:403-424`). This is the nexus-owned vocabulary.
- `routing.accounts.payer_ref` — the payer/vendor of record (`lib.rs:124-128`). **This is the
  only place a billing vendor (Stripe, …) attaches.** It travels on the account, switches on
  transfer, and never enters the wire contract. Keeps the system vendor-free (rules §2).

The gap this change closes is a single cross-plane hop: the identity sidecar never projects
that plan onto enriched requests. So `x-workspace-plan` has no producer and the reserved
`plan` claim stays `None` (`sidecar/src/signer.rs:127`, asserted unpopulated at `signer.rs:229`).

The signing seam is ready: `ContractClaims.plan: Option<String>` (`core/src/contract.rs:82-83`)
is deliberately optional so populating it is a value change, not a contract-version bump. The
enrich path already holds the acting `workspace_id` at mint time (`sidecar/src/main.rs:642-658`,
`683-719`).

## Resolved questions

### R1 — Source of truth: `routing.workspaces.plan` (nexus-owned, not a billing mirror)
Plan is a routing-plane workspace attribute, control-plane-written, `DEFAULT 'free'`. Identity
**projects it read-only**, exactly as it already projects `routing.memberships` SELECT-only. No
external billing system is authoritative for the wire value; a future Stripe integration is a
control-plane writer that maps a subscription → plan string and updates the column +
`accounts.payer_ref`. Vendor isolation lives entirely behind the control-plane write boundary.

### R2 — Vocabulary: open string on the wire, nexus-owned set at the write boundary
The wire carries a bare string (`plan: Option<String>`, `x-workspace-plan: <string>`), so
adding a tier is a value change, never a contract bump. The canonical set is nexus-owned via the
existing config-driven `PlanLimits` and validated where plan is written (control plane) —
mirroring the house pattern for `membership kinds` (`router-core/src/store.rs:231`: bare `&str`,
store persists the wire string, DB CHECK is the backstop). Identity does **not** re-validate;
the read path trusts a value the write path already validated. Unknown/absent → treated as
not-provisioned by the box.

### R3 — Relationship to entitlements: independent axis (no derivation)
Entitlements are **subject-scoped** (`Profile.entitlements`, per user, authored via
`AuthzAuthoring`); plan is **workspace-scoped** (per `workspace_id`). They are orthogonal facts
on separate resolution paths; the box reads both. Plan does not derive entitlements and vice
versa — avoiding the "two overlapping authorization inputs" trap by keeping them physically and
semantically distinct.

## Decisions (build-vs-adopt gate — `/opsx:decide`)

### Decision: Live workspace→plan projection — Extend the in-house LISTEN/NOTIFY projection (Rent Postgres)

- **Status**: approved
- **Why**: The plan is already authoritative in `routing.workspaces.plan`; the only need is a
  live, revocation-consistent read into the identity sidecar. The in-house LISTEN/NOTIFY
  projection (`PgPlatformServiceReader` + resident `watch::Receiver<Arc<HashMap>>`) already
  delivers exactly this — SELECT-only cross-plane read, O(1) prompt downgrade, broker-free, no
  new infra. Cloning it is reuse of a shipped, tested adapter (mirrors the identical call in
  `normalized-principal/design.md` for the platform-service registry).
- **Considered**: *Adopt an external entitlement/feature-flag platform* (LaunchDarkly /
  Flagsmith / Unleash) — rejected: introduces a second source of truth for a plan nexus already
  owns, a vendor dependency (against the vendor-free rule §2), and a hot-path network hop.
  *Build a bespoke fetch* (per-request `SELECT` or a custom Redis cache) — rejected:
  per-request SELECT adds hot-path latency/load, and a custom cache re-implements the freshness
  the LISTEN/NOTIFY pattern already solves in-repo.
- **Isolation**: a read-only `WorkspacePlanReader` port (`identity-rs/core`) with a
  `PgWorkspacePlanReader` adapter over a `SELECT`-only pool (`identity-rs/store-postgres`,
  cloning `platform_services.rs`); the resident snapshot lives on `AppState` and is read
  per-request via `resolve_plan(workspace_id)` mirroring `resolve_platform_scope`
  (`sidecar/src/main.rs:288-292`). The NOTIFY channel is the routing plane's existing
  workspace-invalidation channel (sub-decision below).
- **Tier**: Extend (the in-house projection pattern) + Rent (Postgres + the K8s/routing store).

This decision settles **D1 (Path B — dedicated projection)** below; the comparison is retained
for the rationale.

## Design detail (settled by the decision above)

### D1 — Identity read path: **dedicated plan projection** (chosen) vs. ride membership sync

| | Path A — ride membership sync | **Path B — dedicated projection (recommended)** |
|---|---|---|
| Mechanism | `JOIN routing.workspaces` into membership-sync; carry `plan` on `ResolvedMembership` | SELECT-only `workspace_id → plan` resident snapshot on its own LISTEN/NOTIFY, cloning `PgPlatformServiceReader` |
| Shape fit | ✗ plan is workspace-scoped, membership is subject-scoped → denormalized onto every member | ✓ one row per workspace — matches plan's real shape |
| Prompt downgrade | ✗ a plan change must refresh N member Profiles (fan-out) | ✓ O(1): one row, one NOTIFY, one snapshot update |
| Coupling | ✗ billing/plan events poke the membership path | ✓ independent axis stays physically independent |
| Build-vs-adopt | new join logic in a hot path | ✓ near-verbatim reuse of a shipped, proven adapter (Adopt-by-reuse) |
| Cost | no new resident structure | one more resident watcher (proven pattern) |

Path B honors R3 (independent axis) and the spec's live/revocation-consistent concern (O(1)
downgrade), and the build-vs-adopt gate favors it as reuse of `PgPlatformServiceReader`
(`store-postgres/src/platform_services.rs`) + the `watch::Receiver<Arc<HashMap>>` resident
pattern (`sidecar/src/main.rs:206`, `1139-1182`), read per-request via a `resolve_plan(workspace_id)`
mirroring `resolve_platform_scope` (`main.rs:288-292`).

**Sub-decision (minor):** reuse the routing plane's existing workspace-invalidation NOTIFY
channel (a plan change is a workspace-row change that already fires it) vs. a dedicated plan
channel. Lean reuse unless the existing channel is too chatty to piggyback.

### D2 — Fail mode on resolution miss / store-unavailable
Omit the `plan` claim and `x-workspace-plan` (do **not** 503). A provisioned workspace always
resolves to at least `'free'`; absence therefore only occurs on a genuine miss or cold store,
and the box already treats absent-plan as not-provisioned → fails **closed** on provisioning.
This differs deliberately from membership's `must_fail_closed` 503 (`main.rs:299-301`): missing
membership means "cannot authorize at all"; missing plan means "no entitled tier," a safe
degraded state. Confirm this asymmetry at `/opsx:decide`.

## Open item to verify during apply
- Confirm identity's DB role already has `SELECT` on `routing.workspaces` (it reads
  `routing.memberships` SELECT-only today via `PgSourceMembershipReader`; same posture expected,
  but the grant is worth checking before wiring the reader).

## Coordination
Per `normalized-principal/design.md` **ADR-10**: this change **owns only the `plan` claim**,
lands as an **ADDED** delta (not a MODIFIED rewrite) on `identity-contract-signing`, and its
sole `main.rs` enrich-path edit is **one authored header** — a region distinct from the other
in-flight identity changes. Sync order: after `normalized-principal`; independent of
`identity-existence-hiding`.
