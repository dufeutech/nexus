# Design — membership-profile-propagation

Type: ADD (Architecture Design Document). Motivation in `proposal.md`; behavior contract
in `specs/membership-projection-sync/` and `specs/identity-workspace-authz/`.

## Context

The `nexus-owned-workspace-tenancy` change made the routing control plane the source of
record for memberships (`routing.memberships`, written by `PUT/DELETE
/workspaces/{id}/members`) and made the identity sidecar resolve the acting scope from
`Profile.memberships` (`identity.profiles.doc`, one JSONB doc per `sub`). These live in
**separate databases in production** (`routing-plane` vs `identity-plane` Helm charts,
distinct `ROUTING_PG_URL` / `PROFILE_PG_URL`); they only co-reside in the dev
`docker-compose`. Task 1.4 shipped the two stores but not the wire between them, so:

- A granted/revoked membership never reaches the resolver — the "revocation within
  seconds" guarantee of `identity-workspace-authz` is currently unmet.
- `identity_core::reconcile::build_profile_from_user` emits `memberships: Vec::new()`, and
  while `reconcile::differs` excludes memberships, **any** identity/role drift triggers a
  reconciler `put` that would clobber whatever memberships were projected. (The
  sync-worker is safe — it read-modify-writes from the fetched existing profile.)

Existing seams we build on: routing already owns a `pg_notify` invalidation feed
(`notify_invalidation`, `INVALIDATION_CHANNEL`); the identity `PgProfileStore::put/delete`
already emit a resumable change feed (`pg_notify` `identity_changes`, monotonic `seq`)
that the sidecar's moka cache consumes.

## Goals / Non-Goals

**Goals:**
- A source-of-record membership change is reflected in `Profile.memberships` within
  seconds, and revocation fails closed within that window.
- Identity remains the **sole writer** of profiles; routing only emits a signal. One
  writer per store is preserved.
- Correct across the production two-database topology (no shared-schema assumption).
- Missed best-effort signals self-heal via a bounded-staleness reconcile backstop.
- The reconciler no longer clobbers memberships.
- `Profile.home_org` exists as informational, non-authz context.

**Non-Goals:**
- N4 Phase 2 (emitting `x-auth-requires-role`/`-entitlement`/`-min-aal` and the 403 gate).
- Any change to the edge header/wire contract or `x-identity-contract` version.
- A ReBAC/graph authz engine (the `MembershipResolver` port still resolves from the
  denormalized `Profile.memberships`; swapping the backing store is a later change).
- Two-phase commit / distributed transactions across the two databases.

## Decisions

Decision record for the critical concerns flagged in the proposal. Hierarchy applied:
Rent > Adopt > Extend > Fork > Build (`openspec/guidelines.md`).

### D1 — Propagation mechanism: real-time signal + reconcile backstop (Extend)

**Chosen:** Control-plane emits a "membership changed" `pg_notify` on upsert/delete; a new
identity-plane consumer LISTENs, re-reads the subject's source-of-record memberships, and
does a read-merge-write into the identity profile. A periodic reconcile pass is the
backstop.

**Why over alternatives:**
- *Control-plane dual-write into the identity store (rejected):* simplest single
  write-point, but a routing-plane component would open a connection to the identity DB —
  breaking the strict plane/DB separation and giving `identity.profiles` a second writer,
  with no cross-DB atomicity. Violates "one writer per store."
- *Reconciler-only merge (rejected as sole mechanism):* correct and simple across two DBs,
  but membership changes lag the reconcile interval (~10 min) — fails the "within seconds"
  requirement. Retained only as the **backstop** (D3).
- *Shared-DB cross-schema read (rejected):* only valid under the dev single-DB topology;
  contradicts the production two-database deployment contract.

This is **Extend**, not Build: we reuse the existing routing `pg_notify` invalidation
pattern and the existing identity change feed. No new infrastructure is rented or adopted;
the "transport" is Postgres LISTEN/NOTIFY, already in use on both sides.

### D2 — Change transport: reuse Postgres LISTEN/NOTIFY (Adopt-in-place)

**Chosen:** A dedicated routing notify channel (e.g. `routing_membership_changes`) carrying
a minimal payload `{user_sub, workspace_id, op}`. The consumer treats the payload as a
**hint** and re-reads the source of record (spec: "the signal carries identity, not
authority"), so a coalesced or lost NOTIFY only costs latency, never correctness.

**Why:** Postgres NOTIFY is already the reliability model on both planes; adopting a broker
(Kafka/NATS) would be renting infra disproportionate to one low-volume control-plane
event, and would still need the backstop for delivery guarantees. NOTIFY's best-effort
nature is explicitly compensated by D3.

### D3 — Backstop + no-clobber: fix the merge in the reconcile path (Extend)

**Chosen:** The membership merge is a pure `identity_core` helper (read source-of-record
memberships → set `Profile.memberships` → return the profile to `put`). The reconciler's
identity-attribute path is fixed to **preserve** memberships (read-merge-write from the
stored profile, or merge memberships in as a distinct authoritative input) so an attribute
update never zeroes them. The same helper backs both the real-time consumer and the
periodic reconcile, so there is one convergence definition, not two.

**Why:** Keeps the WHAT ("never clobbered", "self-heals") realized by one core function
reused by two adapters — composable core, thin surfaces.

### D4 — Where the consumer lives: identity plane, new thin binary (Extend)

**Chosen:** A new identity-side entry point (a `membership-sync` worker, sibling to
`sync-worker`/`reconciler`) that owns two connections: a **read-only** routing DB session
(LISTEN + `SELECT` memberships for a `sub`) and the identity `PgProfileStore` (`get`/`put`).
Business logic (the merge) lives in `identity_core`; the binary is a thin adapter that
wires LISTEN → core helper → store, mirroring the existing worker shape.

**Why:** Putting the consumer in the identity plane keeps profiles single-writer there.
The cross-DB coupling is a **read-only** routing connection held by the identity plane
(one direction, least privilege) rather than a routing component writing profiles.

**Deployment consequence:** the identity plane gains a read-only route/credential to the
routing DB's notify channel + memberships table — a Helm/compose wiring change (new
`ROUTING_PG_RO_URL`-style input for the identity plane). Recorded as a risk (R1).

### D5 — Membership read seam from the identity side (Extend)

**Chosen:** Add a small read-only port (e.g. `SourceMembershipReader::memberships_for(sub)`)
implemented against the routing `memberships` table, consumed by the identity worker +
reconciler. Keeps the routing SQL behind an adapter (no raw cross-schema SQL in core).

### D6 — `home_org`: informational field on Profile (Build-trivial)

**Chosen:** Add `home_org: Option<String>` to `identity_core::Profile`, populated from the
authoritative user record at reconcile/sync time (like `org_id`), `#[serde(default)]` for
backward-compatible docs. Excluded from `resolve_membership` and never emitted as an authz
header. No decision hierarchy needed — a denormalized informational field.

## Risks / Trade-offs

- **[R1] New cross-plane DB connection (identity → routing, read-only).** Widens the
  identity plane's blast radius and network policy. → Mitigation: read-only credential,
  scoped to `SELECT` on `memberships` + `LISTEN`; documented as a distinct required input;
  no write grant to routing.
- **[R2] Best-effort NOTIFY can drop (consumer down, connection reset).** → Mitigation: the
  reconcile backstop (D3) re-converges within its interval; the consumer re-reads the
  source of record rather than trusting the payload, so ordering/coalescing is harmless.
- **[R3] Two-DB non-atomicity (routing row written, profile lag).** → Mitigation: bounded
  eventual consistency is acceptable for authz freshness ("within seconds"), and fail-closed
  resolution means the risky direction (revoke) is safe even mid-lag — a not-yet-projected
  revoke still resolves to the old membership only until the signal/backstop lands, matching
  the existing suspension model.
- **[R4] Reconciler change could regress identity-field authoring.** → Mitigation: the
  no-clobber fix is a read-merge-write; unit-cover that an attribute/role change preserves
  memberships and that a membership change preserves attributes.
- **[R5] Profile exists for a `sub` unknown to identity (member in routing, not yet
  synced from IdP).** → Mitigation: the merge helper upserts a minimal profile keyed by
  `sub` (memberships set, identity fields empty) so resolution works; the next IdP sync
  fills identity fields without clobbering memberships.

## Migration Plan

- **Backfill:** no separate ETL — the first reconcile backstop pass merges all existing
  `routing.memberships` into profiles (spec: "existing memberships are backfilled on first
  run").
- **Deploy order:** (1) ship the routing NOTIFY emit (no consumer yet — harmless); (2) ship
  the identity worker + reconciler no-clobber fix with the read-only routing connection
  wired; (3) first reconcile pass backfills. No edge/contract change, so no `x-identity-
  contract` bump and no coordinated edge cut-over.
- **Rollback:** `git revert`; the projection is a rebuildable read-model (drop the worker,
  memberships simply stop refreshing — source of record is untouched).

## Open Questions (resolved at apply time)

- **Read-only routing connection input** → `ROUTING_PG_RO_URL` (mirrors `PROFILE_PG_URL`
  naming); routing NOTIFY channel constant `routing_membership_changes` (shared wire
  contract, duplicated across planes like the `x-workspace-*` header names).
- **Backstop location** → the new `membership-sync` worker (not the reconciler): it already
  holds the routing read-only connection, so the backstop is one tick there rather than a
  new cross-plane dependency in the reconciler. The reconciler keeps only the no-clobber
  fix (carry stored memberships forward).
