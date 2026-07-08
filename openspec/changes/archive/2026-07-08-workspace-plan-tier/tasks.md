> Prerequisite: `normalized-principal` implemented and synced (the `Principal` seam and the
> generalized mint guard). Per `normalized-principal/design.md` **ADR-10**, this change owns only
> the `plan` claim, lands as an **ADDED** delta on `identity-contract-signing`, and its sole
> enrich-path edit is one authored header — rebased onto whatever landed first. Independent of
> `identity-existence-hiding`.
>
> No new schema, writer, or vocabulary: `routing.workspaces.plan` and its write path already ship
> on the routing plane. This change is a read-only projection into the identity plane.

## 1. Store adapter — read-only plan projection

- [x] 1.1 Confirm the identity plane's DB role already holds `SELECT` on `routing.workspaces`
      (it reads `routing.memberships` `SELECT`-only today via `PgSourceMembershipReader`); grant
      it if absent. No write privilege.
      → Confirmed: the reader connects with the same `ROUTING_PG_RO_URL` routing RO role the
      membership-sync worker reads `routing.memberships` with; there is no in-repo grant
      management, so `SELECT` on `routing.workspaces` rides that same role — no new grant needed.
- [x] 1.2 Implement `PgWorkspacePlanReader` over the `SELECT`-only pool — project `workspace_id →
      plan` for provisioned workspaces — a near-verbatim clone of `PgPlatformServiceReader`
      (`store-postgres/src/platform_services.rs`).
- [x] 1.3 Add `watch_active`-style liveness: open a `PgListener` on the routing plane's existing
      workspace-invalidation NOTIFY channel, prime the full set, re-emit on each signal, with a
      poll fallback — mirroring `PgPlatformServiceReader::watch_active`. (Reuse the existing
      channel; only add a dedicated plan channel if the shared one proves too chatty.)

## 2. Core — the plan reader port

- [x] 2.1 Define a read-only `WorkspacePlanReader` port in `identity-rs/core` returning the
      current plan for a `workspace_id` (or none). Keep it language-agnostic of the store.
- [x] 2.2 Treat plan as an opaque wire string; do **not** re-validate the vocabulary in identity
      (the control-plane write boundary owns the canonical set — mirrors the read path trusting a
      previously-validated `membership kind`).

## 3. Sidecar — hold the snapshot & author the plan

- [x] 3.1 Hold the resident `workspace_id → plan` snapshot on `AppState` in a
      `watch::Receiver<Arc<HashMap<..>>>`, refreshed by a `watch_workspace_plans` task —
      mirroring `watch_platform_services` (`sidecar/src/main.rs:1139-1182`).
- [x] 3.2 Add `resolve_plan(workspace_id)` reading the resident snapshot per request, mirroring
      `resolve_platform_scope` (`main.rs:288-292`).
- [x] 3.3 On an enriched request with a resolved acting workspace, author `x-workspace-plan` from
      `resolve_plan`; when no plan resolves, author no header (fail-soft, not a 503 — distinct
      from membership's `must_fail_closed`).
- [x] 3.4 Populate the reserved `plan` claim at mint time — fill `plan: None` at
      `sidecar/src/signer.rs:127` from `resolve_plan(MintInput.workspace_id)`; omit when
      unresolved. Update the existing "stays unpopulated" assertion (`signer.rs:229`).

## 4. Tests

- [x] 4.1 Reader/liveness: a plan change to a workspace propagates to the resident snapshot on
      the next NOTIFY (prompt downgrade and upgrade), with the poll fallback covering a missed
      signal.
- [x] 4.2 Enrich path: enriched request carries the resolved plan as both `x-workspace-plan` and
      the signed `plan` claim; a client-asserted `x-workspace-plan` is ignored.
- [x] 4.3 Fail-soft: an unresolved / unknown workspace omits both the header and the claim (no
      default, no 503) and does not otherwise degrade enrichment.
- [x] 4.4 Contract: end-to-end sign→verify shows a box reading a trusted `plan` from the signed
      contract; the claim is absent (not defaulted) when unresolved.

## 5. Docs

- [x] 5.1 `docs/box-consumer-contract.md`: `x-workspace-plan` gains a producer — document the
      value, the not-provisioned-on-absent rule, and that it is nexus-authored.
- [x] 5.2 Signing docs: mark the `plan` claim populated (was reserved), noting omission-on-unresolved.
