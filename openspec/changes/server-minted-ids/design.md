## Context

Today the admin control plane runs a trusted-broker id model: `POST /accounts` and
`POST /workspaces` read `account_id`/`workspace_id` out of the request body
(`routing-rs/control-plane/src/orgs.rs`), and the caller-supplied id doubles as three
things at once — the primary key, the update address (the workspace route is a true
upsert), and the idempotency key (`INSERT … ON CONFLICT DO NOTHING` keyed on it makes
signup provisioning "safe to call unconditionally"). Replacing caller-supplied ids with
server-minted ones therefore breaks three contracts, not one; this design replaces each
deliberately. Confirmed groundwork: the id is treated as an opaque string everywhere
(store columns are `text`, sidecar/Envoy/JWT carry it verbatim, no format validation
anywhere in nexus, runlet-js, or event-logs), so nothing outside these routes cares
about the format change.

## Goals / Non-Goals

**Goals:**
- Ids are nexus-minted, typed (`ws_`/`acct_` prefix), time-ordered, collision-resistant.
- Creation stays blindly retryable (the signup contract) via an explicit idempotency
  key instead of an accidental one.
- Create and reconfigure become distinct, non-overlapping operations.
- Retire the `/tenants*` alias, the `tenant_id` synonym drift, and the dead legacy
  migration/backfill shims in the same pass (they all assume caller-chosen ids).

**Non-Goals:**
- No product policy in nexus (e.g. "one account per subject" — that is the broker's key
  choice, not a schema constraint).
- No change to membership routes, transfer, domains, or the identity plane — they
  address existing ids and are format-agnostic.
- No new migration framework; schema management stays as-is (this change only deletes
  legacy blocks).
- No slug/uniqueness semantics on display names.

## Decisions

### D1 — Id minting: typed UUIDv7, minted in the core, generator behind an adapter

Ids are `ws_<uuidv7>` / `acct_<uuidv7>`. UUIDv7 (RFC 9562) over ULID because it is the
IETF standard solving the same time-ordered-uniqueness problem, and runlet-js's
`$std.crypto.uuid()` already emits v7 — one id scheme across the stack. The prefix is
Stripe-style self-description in logs and the structural collision guard downstream
repos inherit for free.

Placement: a small `router_core::ids` module owns the two prefix constants and the mint
functions (single source of truth — handlers and tests reference these, never literal
`"ws_"`). The concrete generator crate enters only through that module; handlers
(adapters) call `mint_workspace_id()` and stay logic-free. The idempotency-key bounds
live in a sibling `router_core::idempotency` module for the same reason.

*Critical concern (correctness): unique time-ordered id generation — Adopt, do not
hand-write. Recommendation: the `uuid` crate with the `v7` feature (currently only a
transitive dep without v7). Recorded via `/opsx:decide`.*

**Alternatives rejected:** ULID (non-standard, second scheme in the stack);
Postgres-side generation (`gen_random_uuid()` is v4, no native `uuidv7()` here, and
minting in SQL would put domain behavior in the store adapter).

### D2 — Idempotency: nullable `idempotency_key text UNIQUE` column, generic not semantic

Each of `routing.accounts` and `routing.workspaces` gains a nullable
`idempotency_key text UNIQUE` column (Postgres allows many NULLs under UNIQUE, so the
key is genuinely optional). Create flow: mint id → `INSERT … ON CONFLICT
(idempotency_key) DO NOTHING` → if no row inserted, `SELECT` the existing row by key and
return it with `created: false` — byte-for-byte the replay contract `provision_account`
documents today, re-keyed from the id to the request. Keys are validated as non-empty
with a bounded length (single constant next to the handler contract).

The key is **generic**: the broker encodes flow semantics in the value (e.g.
`signup:<sub>`). This is deliberate — the spec places provisioning orchestration with
the broker, and the org model makes `owner_sub UNIQUE` wrong (a user who signs up and
later creates a team account legitimately owns two accounts).

**Alternatives rejected:** semantic keys (`owner_sub`/slug UNIQUE — smuggles product
policy into the schema, forbids legitimate flows); a separate idempotency table with
TTL (machinery this two-caller admin API doesn't need; a column is one concept, one
constraint); `Idempotency-Key` HTTP header (out-of-band from the body the store adapter
sees; a body field keeps the contract visible in one place).

### D3 — Route split: POST creates, PUT reconfigures, neither does the other's job

- `POST /accounts` → create only; returns `account_id`, `created`.
- `POST /workspaces` → create only; returns `workspace_id`; never overwrites.
- `PUT /workspaces/{id}` → reconfigure (plan/pool/features) only; `404` on unknown id;
  never creates. Ownership changes stay on `/transfer`, memberships stay put.

The store's `upsert_workspace` splits into `create_workspace` / `update_workspace` so
the "never overwrites / never creates" guarantees are enforced in SQL (`ON CONFLICT DO
NOTHING` vs `UPDATE … WHERE`), not by handler branching.

**Alternative rejected:** keep one upsert route with server ids — incoherent (nothing
to address on create; a typo'd id on update would silently create a ghost workspace).

### D4 — Retire `/tenants*` and the hard-coded-id fixture ecosystem together

The alias (`tenants.rs`, routes in `main.rs`) is deleted, not deprecated-harder — the
lab seed in `docker-compose.yaml` is its only live caller and must be rewritten for
server-minted ids anyway (create account → capture `acct_…` → create workspace →
capture `ws_…` → attach domains/members using the captured ids). The five e2e scripts
lose the `/workspaces`→`/tenants` fallback and the hard-coded `acme` literal; each
provisions (or looks up) its workspace and threads the captured id. Docs/OpenAPI drop
`tenant_id` in favor of `workspace_id` everywhere (the `admin-apis.md:208` drift).
`orgs.rs` is renamed `tenancy.rs` to match what it implements (Accounts/Workspaces/
Memberships, not ZITADEL orgs).

### D5 — Delete the legacy shims

The guarded `tenant_id → workspace_id` in-place rename migration and the solo-account
backfill (`store-postgres/src/lib.rs`) are deleted. The backfill sets
`account_id = workspace_id`, which typed prefixes make structurally impossible, and
both exist to migrate deployments that don't exist (greenfield, 0 deployments).

### Decision: unique time-ordered id generation — Adopt `uuid` crate (`v7` feature)

- **Status**: approved
- **Why**: de-facto standard, already in both workspace Cargo.locks transitively via
  sqlx (zero new supply-chain surface), and `Uuid::now_v7()` guarantees monotonic
  ordering since 1.9 via its internal `ContextV7` counter — the exact correctness trap
  a hand-rolled v7 would own.
- **Considered**: `uuid7` crate (solid dedicated impl, but a second UUID type/dep for
  capability `uuid` already has); hand-written v7 (Build — ~20 lines of layout, but
  sub-millisecond monotonicity/counter/entropy handling is not worth owning).
- **Isolation**: referenced only inside the `router_core::domain` id module (D1);
  handlers, store, and tests see `mint_workspace_id()`/`mint_account_id()`, never the
  crate.

## Risks / Trade-offs

- **[Replay race]** Two concurrent creates with the same key: one inserts, the other
  hits `ON CONFLICT DO NOTHING` then must `SELECT` — a gap where the row is guaranteed
  committed only because the conflict proves the other insert won. → Single round-trip
  CTE (`INSERT … ON CONFLICT DO NOTHING RETURNING` unioned with a `SELECT` by key) or
  a read-after-conflict retry; pick at implementation, assert with a concurrent test.
- **[Broker contract break]** The (out-of-repo) broker/signup flow must switch from
  supplying ids to reading them back and sending keys. → Greenfield, no deployed
  broker; the new contract is documented in `admin-apis.md` + OpenAPI in the same PR.
- **[e2e id-threading fragility]** Five scripts move from a known literal to captured
  ids; a silent capture failure would cascade confusingly. → Shared provision-helper
  (create + `jq` extract + fail-fast on empty), used by seed and scripts alike.
- **[Doc churn]** `admin-apis.md`, both OpenAPI specs, and the go-live walkthrough were
  freshly written and all show caller-supplied ids. → Mechanical but must land in the
  same change; stale examples here would actively mislead go-live.
- **[Lost free upsert]** Operators lose "re-POST the same body to fix a workspace";
  reconfigure now requires knowing the id. → `GET /workspaces` listing already exists;
  acceptable cost for eliminating silent ghost-creates.

## Migration Plan

None — 0 deployments, 0 users. Rollback is `git revert`; the schema additions are a
nullable column + unique constraint, safe to apply to the empty lab databases by
recreating them (the compose stack's normal reset path).

## Open Questions

- Exact idempotency-key bounds (max length, charset) — pick a boring constant (e.g.
  ≤128 bytes, printable ASCII) at implementation; it only needs to be documented, not
  clever.
- Whether `GET /workspaces?name=` filtering is worth adding now that names are the only
  caller-known handle at create time — defer until a real operator workflow asks.
