# Tasks — membership-profile-propagation

> Sequence keeps the running system coherent: emit the signal first (no consumer =
> harmless), then the identity-side merge core, then the worker + reconciler backstop, then
> wiring/verify. Cross-DB direction is one-way: identity holds a read-only routing
> connection; routing never writes profiles.

## 1. Core — the membership merge (identity_core, pure)

- [x] 1.1 Add `home_org: Option<String>` to `identity_core::Profile` (`#[serde(default)]`),
  excluded from `resolve_membership`; assert it never affects resolution (unit test). DONE:
  field added (informational, non-authz); both writers populate it from the IdP resource
  owner (`reconcile::build_profile_from_user`, `sync::apply`). Test
  `home_org_never_affects_resolution`.
- [x] 1.2 Pure merge helper `Profile::with_memberships(self, Vec<Membership>) -> Self` —
  the single convergence point (consumer + backstop both call it); replaces only
  memberships, preserves every other field. Tests `with_memberships_replaces_only_
  memberships` + `with_memberships_empty_clears_membership_projection` (revoke-all).
- [x] 1.3 Fix the reconciler clobber: new pure `reconcile::reconciled_profile(user, roles,
  stored)` carries the STORED memberships forward via `with_memberships`; reconciler calls
  it instead of `build_profile_from_user`. `differs` still ignores memberships (no spurious
  puts). Tests `reconciled_profile_preserves_memberships_on_identity_change` +
  `reconciled_profile_no_stored_has_empty_memberships`. (sync-worker was already safe —
  read-modify-write from `existing`.)

## 2. Routing — emit the change signal (source of record stays authoritative)

- [x] 2.1 Added `MEMBERSHIP_CHANNEL = "routing_membership_changes"` + `PgRoutingStore::
  notify_membership_change(user_sub)`, mirroring `notify_invalidation`. Payload is just
  `user_sub` (a hint — consumer re-reads the source of record for the full set), simpler
  than the sketched `{user_sub, workspace_id, op}` and needs no parsing.
- [x] 2.2 Emitted from control-plane `upsert_membership` + `delete_membership` after the
  write commits; best-effort (a notify failure logs a warn and does NOT fail the CRUD — the
  backstop heals it). No CRUD response change. Builds clean.

## 3. Identity — the read seam + consumer worker

- [ ] 3.1 Add a read-only `SourceMembershipReader` port in `identity_core`
  (`memberships_for(sub) -> Vec<Membership>`) and implement it against the routing
  `memberships` table (read-only routing connection; SQL behind the adapter, not in core).
- [ ] 3.2 New thin binary `identity-rs/membership-sync`: LISTEN on the routing channel →
  on signal, `SourceMembershipReader::memberships_for(sub)` → `ProfileStore::get(sub)` →
  `apply_memberships` → `ProfileStore::put` (upserting a minimal profile if `sub` is absent,
  per design R5). Re-reads source of record (never trusts payload). Reconnect/resume on
  LISTEN drop.

## 4. Backstop — periodic reconcile merge

- [ ] 4.1 Add a periodic backstop pass (in the reconciler or the new worker — pick the
  smaller wiring) that re-derives each subject's memberships from the source of record and
  merges via `apply_memberships`, healing missed NOTIFYs and backfilling on first run.
- [ ] 4.2 Confirm the first backstop pass backfills existing `routing.memberships` into
  profiles (no separate ETL).

## 5. Wiring & config

- [ ] 5.1 Add the identity plane's read-only routing DB input (env var, e.g.
  `ROUTING_PG_RO_URL`) + the new worker to docker-compose and the identity-plane Helm chart
  (deployment, values, secret ref). Least-privilege: `SELECT` on `memberships` + `LISTEN`,
  no write grant.
- [ ] 5.2 Document the new cross-plane connection + channel in the deploy README /
  identity-plane NOTES.

## 6. Verify

- [ ] 6.1 Both workspaces: clippy `--all-targets --locked` 0-deny, cargo-deny, tests
  (identity-rs needs `PROTOC`).
- [ ] 6.2 Integration (gated on a throwaway Postgres): membership upsert in routing →
  NOTIFY → worker merges → `Profile.memberships` updated + `identity_changes` fired;
  delete → membership removed within the window; reconcile backstop converges after a
  dropped signal; existing memberships backfilled on first run.
- [ ] 6.3 No-clobber regression: an identity-attribute reconcile pass leaves projected
  memberships intact; a membership change leaves identity attributes intact.
- [ ] 6.4 `home_org`: present-but-non-member fails closed; home_org never emitted as an
  authz header (extend the existing sidecar tests).
