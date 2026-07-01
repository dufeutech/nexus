## Why

The shipped `nexus-owned-workspace-tenancy` change made the routing control plane the
source of record for workspace memberships (`PUT/DELETE /workspaces/{id}/members`), but
left the propagation seam unbuilt (task 1.4, `[~]`). Membership rows land in the routing
database; the identity sidecar resolves the acting workspace scope from
`Profile.memberships` in the **separate** identity database. Nothing bridges the two, so a
granted membership never reaches the resolver and a **revoked membership never takes
effect** — the live-authz promise of the tenancy change is currently unmet. Closing this
seam is also the prerequisite for the roadmap's N4 Phase 2 (role/entitlement/AAL
enforcement), which resolves against exactly this projection.

## What Changes

- Membership CRUD in the control plane **emits a change signal** when a membership row is
  written or removed, carrying the affected `user_sub` (+ `workspace_id`). The routing DB
  stays the source of record; the signal is best-effort notification, not the record.
- A new **identity-plane consumer** reacts to that signal, reads the current
  source-of-record membership set for the subject, and performs a read-merge-write into
  the subject's identity `Profile` so `Profile.memberships` reflects the source of record.
  The existing identity change feed then refreshes the sidecar cache within seconds.
  Identity remains the **sole writer** of profiles — routing only emits an event.
- A **reconcile backstop** periodically re-merges the source-of-record memberships into
  profiles so a missed best-effort signal self-heals (bounded staleness, not permanent
  drift).
- **Fix the reconciler clobber (BREAKING for the reconciler write path):** the
  identity-attribute reconcile path must **preserve** `Profile.memberships` (read-merge-
  write) so an identity/role update never zeroes memberships. Today `build_profile_from_user`
  emits empty memberships and any attribute/role drift triggers a `put` that would clobber.
- Add the informational `home_org` field to the identity `Profile` (deferred from task
  1.4). **Informational/denormalized only — NOT an authz input** (`x-user-org` was retired
  as an authz signal in the tenancy change).

Out of scope: N4 Phase 2 header emission (`x-auth-requires-role`/`-entitlement`/
`-min-aal`) and the 403 enforcement gate. This change only makes membership data flow
correctly into the projection the sidecar already reads, plus `home_org`.

## Capabilities

### New Capabilities

- `membership-projection-sync`: The guarantee that a membership change at the routing
  source of record is reflected in the identity `Profile.memberships` projection within
  seconds via a real-time signal, self-heals via a reconcile backstop if a signal is
  missed, and is never clobbered by an unrelated identity/role update. Names the
  critical concerns whose realization is a build-vs-adopt call for `/opsx:decide`:
  cross-store change delivery (the signal transport) and idempotent read-merge-write
  convergence.

### Modified Capabilities

- `identity-workspace-authz`: Acting-scope resolution is now defined against a projection
  that is kept in sync with the source of record (previously the projection had no writer,
  so resolution was effectively static). Adds `home_org` to the profile as an
  informational, non-authoritative field that MUST NOT influence membership resolution.

## Impact

- **Code — routing plane:** `routing-rs/control-plane` (emit a membership-changed signal
  on upsert/delete), `routing-rs/store-postgres` + `router-core` port (the notify seam,
  reusing the existing invalidation-feed pattern).
- **Code — identity plane:** a new consumer component (LISTENs on the routing signal,
  reads memberships, writes the profile); `identity-rs/core` (`Profile.home_org`, the
  membership read-merge-write helper, reconciler no-clobber fix); `identity-rs/reconciler`
  (backstop merge); `identity-rs/store-postgres` (source-of-record membership read for the
  identity side, or a shared read seam).
- **Deployment:** the new consumer needs a network/credential path to the routing DB's
  notification channel (a new cross-plane connection in the identity plane — a Helm/compose
  wiring change). No change to the strict "identity writes profiles / routing writes
  memberships" ownership.
- **Contract:** no edge header/wire changes; `x-identity-contract` version is unaffected
  (the emitted scope shape is unchanged — only its freshness/correctness improves).
- **Migration:** the reconcile backstop performs the initial backfill of existing
  memberships into profiles on first run; no separate ETL.
