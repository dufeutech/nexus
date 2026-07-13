## 1. Id minting core (design D1)

- [x] 1.1 Run `/opsx:decide` for the id-generation critical concern (recommendation:
  adopt the `uuid` crate with `v7` feature) and record the decision in design.md.
- [x] 1.2 Add the decided generator as a direct dependency of the routing workspace and
  create the id module in `router_core::domain`: `ws_`/`acct_` prefix constants +
  `mint_workspace_id()` / `mint_account_id()`; unit-test prefix, uniqueness, and
  time-ordering across successive mints.

## 2. Store layer (design D2, D3, D5)

- [x] 2.1 Add nullable `idempotency_key text UNIQUE` to `routing.accounts` and
  `routing.workspaces` in the store-postgres schema.
- [x] 2.2 Delete the legacy `tenant_id → workspace_id` in-place rename migration and the
  solo-account backfill blocks from `store-postgres/src/lib.rs`.
- [x] 2.3 Split `upsert_workspace` into `create_workspace` (insert-only, honors
  idempotency key, returns whether created) and `update_workspace` (update-only,
  returns row-matched); rework `create_account` to take a minted id + optional key.
  Enforce "never overwrites / never creates" in SQL, with the same-key race resolved in
  a single round-trip per design D2's replay-race mitigation.
- [x] 2.4 Integration tests against Postgres: replay with same key returns original id
  (`created: false`); concurrent same-key inserts yield one row; NULL keys never
  conflict; update of unknown id matches zero rows.

## 3. Control-plane handlers (design D2, D3)

- [x] 3.1 Rework `POST /accounts` (`orgs.rs::provision_account`): body carries
  `owner_sub`, `name`, optional `payer_ref` + `idempotency_key` — no `account_id`.
  Mint the id in the handler via the core module, return
  `{account_id, created}`. Reject requests that still carry an id field
  (`deny_unknown_fields` or explicit check) and malformed keys (empty / over the
  length bound — one constant).
- [x] 3.2 Rework `POST /workspaces` to create-only with the same contract (mint `ws_`
  id, optional `idempotency_key`, reject caller-supplied ids); add
  `PUT /workspaces/{id}` for reconfigure (plan/pool/features) returning 404 on unknown
  id; keep cache-invalidation behavior on both paths.
- [x] 3.3 Delete `tenants.rs` and the `/tenants*` routes from `main.rs`; rename
  `orgs.rs` → `tenancy.rs` and fix references.
- [x] 3.4 Handler-level tests for the new contracts (spec scenarios: replay, omitted
  key, malformed key, create-never-overwrites, reconfigure-unknown-404,
  caller-supplied-id rejected).

## 4. Fixtures and e2e (design D4)

- [x] 4.1 Write the shared provision helper (create account + workspace, extract ids
  with `jq`, fail fast on empty) under `scripts/`, and rewrite the `routing-seed`
  service in `docker-compose.yaml` to use it (accounts + workspaces + domains via
  captured ids; no `/tenants`, no hard-coded `acme`/`globex`).
- [x] 4.2 Update the five e2e scripts (`tenancy-edge-e2e.sh`, `existence-hiding-e2e.sh`,
  `authz-global-e2e.sh`, `tenancy-edge-auth-e2e.sh`, `n4-e2e.sh`) plus
  `go-live-smoke.sh` and `contract-signing-e2e.sh` id assertions: drop `/tenants`
  fallbacks and `acme` literals, thread captured ids.
- [x] 4.3 Run the full e2e suite against the compose stack and confirm green.

## 5. Docs and specs

- [x] 5.1 Update `docs/admin-apis.md`: new create/reconfigure contracts, idempotency-key
  semantics + length bound, remove `/tenants*` section and `tenant_id` synonym drift
  (including domain/auth-route response examples).
- [x] 5.2 Update `docs/openapi/control-plane.yaml` (and the other admin OpenAPI surface
  if it names these routes): id from request→response, `PUT /workspaces/{id}`, delete
  `/tenants*` paths, rename `tenant_id` properties.
- [x] 5.3 Update the go-live walkthrough/runbook provisioning steps to the new flow.
- [x] 5.4 Validate the change (`openspec validate --change server-minted-ids`) and run
  `/opsx:sync` to fold the delta specs into main specs when implementation completes.
