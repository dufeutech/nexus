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

- [x] 3.1 `SourceMembershipReader` port in `identity_core` (`memberships_for(sub)` +
  `all_member_subjects()` for the backstop). Adapter `PgSourceMembershipReader` in
  identity `store-postgres` — its own read-only routing pool, projects ONLY
  `status='active'` rows (fail-closed), maps the wire `member_type` string → `MemberType`
  (unknown dropped). SQL stays in the adapter.
- [x] 3.2 New thin binary `identity-rs/membership-sync`: LISTENs on the routing channel →
  per signal, `memberships_for(sub)` → `ProfileStore::get` → `with_memberships` →
  `put` (upserts a minimal profile if absent; skips creating an empty profile for a
  sub with no profile and no memberships, per design R5). Re-reads the source of record
  (never trusts the payload — payload is just `user_sub`). Listener reconnects with backoff
  on drop.

## 4. Backstop — periodic reconcile merge

- [x] 4.1 Backstop lives in the new worker (resolves design Open Question #2 — smaller
  wiring; the worker already holds the routing read-only connection). `backstop_pass`
  converges the UNION of {subjects with source-of-record memberships} ∪ {profiles still
  carrying memberships}, so it heals missed grants AND missed revokes (incl. revoke-to-zero,
  where the sub left the source set). Runs on startup + every `MEMBERSHIP_BACKSTOP_INTERVAL`
  (default 600s).
- [x] 4.2 First backstop pass (startup) backfills existing `routing.memberships` into
  profiles — no separate ETL. (Runtime-verified in 6.2.)

## 5. Wiring & config

- [x] 5.1 Wired `ROUTING_PG_RO_URL` + the worker everywhere: Dockerfile `membership-sync`
  stage; docker-compose `membership-sync` service; identity-plane Helm — `membership-sync.yaml`
  (deployment+service, gated on `membershipSync.enabled`), `secret-routing-ro.yaml`, `routingPg`
  helpers, values (`images.membershipSync`, `membershipSync`, `routingPg`), ServiceMonitor
  entry. `helm lint`+`template` clean; toggle verified both ways (disabled → 0 objects, no
  routingPg required).
- [x] 5.2 Documented the cross-plane read-only connection + `routing_membership_changes`
  channel in deploy/README.md (new subsection) + identity-plane NOTES.txt; umbrella
  values.yaml points identity-plane `routingPg` at the routing subchart's pg Secret.

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
