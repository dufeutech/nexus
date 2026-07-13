## Why

Workspace and account ids are arbitrary caller-supplied strings ("trusted-broker model:
the authenticated caller supplies the ids", `routing-rs/control-plane/src/orgs.rs:35`),
uniqueness-checked only within nexus's own Postgres tables. Nothing prevents an id nexus
accepts from colliding with an unrelated system's tenant string, and the id format is
propagated verbatim across the whole stack (nexus → runlet → event-logs, per
`Nexus-IDS.md`). The cross-repo decision record fixes this at the source: nexus mints its
own structurally-namespaced ids. Greenfield (0 deployments, 0 users), so there is no
migration cost — this is the cheapest it will ever be.

## What Changes

- **BREAKING** — `POST /accounts` and `POST /workspaces` no longer accept
  caller-supplied `account_id` / `workspace_id`. Nexus mints server-generated,
  typed, time-ordered ids (`acct_<uuidv7>`, `ws_<uuidv7>`) and returns them in the
  create response. Callers supply a display name instead.
- **BREAKING** — workspace create and reconfigure split into distinct operations
  (today one `POST /workspaces` route both creates and updates). Create mints an id and
  never overwrites; reconfigure addresses an existing id and never creates.
- New idempotent-creation contract: create requests carry an optional caller-supplied
  idempotency key; replaying a key returns the originally created resource instead of
  minting a duplicate. This replaces the idempotency that was previously an accident of
  the caller-supplied id being the primary key (signup provisioning is documented as
  "safe to call unconditionally" and must stay that way). Policy about *when* to
  provision (e.g. one auto-provisioned account per subject) stays with the broker, which
  encodes it in its key choice — nexus stores no product policy.
- **BREAKING** — remove the deprecated account-less `/tenants*` alias and the
  `tenant_id`/`workspace_id` synonym drift in docs/OpenAPI; the lab seed and e2e
  scripts move to the `/accounts` + `/workspaces` flow and capture server-minted ids
  from responses instead of hard-coding `acme`/`globex`.
- Delete the now-dead legacy compatibility shims: the guarded `tenant_id →
  workspace_id` in-place migration and the solo-account backfill that reuses a
  workspace id as an account id (impossible under typed prefixes, unnecessary at
  0 deployments).

## Capabilities

### New Capabilities

- `provisioning-idempotency`: safe-to-retry resource creation on the admin surface —
  optional caller-supplied idempotency key, replay returns the existing resource with
  its original id; create vs. reconfigure are distinct, non-overlapping operations.

### Modified Capabilities

- `workspace-tenancy`: the "stable internal ID" requirement gains provenance — ids are
  nexus-minted, structurally typed (`ws_`/`acct_` prefix), time-ordered, and globally
  collision-resistant; callers never choose them. (Critical concern: unique time-ordered
  id generation is correctness-critical — realization is a build-vs-adopt decision for
  `/opsx:decide`, not picked here.)

## Impact

- **Code**: `routing-rs/control-plane` (`orgs.rs` handlers, route table in `main.rs`,
  removal of `tenants.rs` alias), `routing-rs/store-postgres` (idempotency-key columns
  + unique constraints on `routing.accounts`/`routing.workspaces`, delete legacy
  rename-migration and solo-account backfill blocks). Columns are already `text`; no
  format migration.
- **API/docs**: `docs/admin-apis.md`, `docs/openapi/control-plane.yaml`, go-live
  walkthrough/runbook examples — request/response shapes change (id moves from request
  to response; create/reconfigure split; `/tenants*` removed).
- **Fixtures/tests**: `docker-compose.yaml` routing-seed (sole user of `/tenants`),
  five e2e scripts that hard-code the `acme` workspace id must capture ids from create
  responses.
- **Downstream (no action required)**: runlet-js and event-logs treat the id as an
  opaque string; the typed prefix is itself the collision guard they inherit
  (`Nexus-IDS.md` §3). Identity sidecar/Envoy/JWT contract carry the id opaquely —
  format-agnostic, unaffected.
