# admin-action-audit — design

## Context

Two independent admin services, each fronting its own Postgres store:

- **control-plane** (`routing-rs/control-plane`) — tenancy/routing mutations in
  `tenancy.rs` and the domain handlers; bearer auth in `app.rs` (single
  `CONTROL_AUTH_TOKEN`, constant-time compare, refuses to start unset).
- **authz-admin** (`identity-rs`) — roles/entitlements/suspension/api-key mutations;
  same single-token pattern (`IDENTITY_ADMIN_TOKEN`); already contains mature
  credential machinery for customer api-keys (peppered HMAC hashing, rotation
  lineage, revocation).

Neither service records who did what. Both stores are the natural home for a ledger
because every mutation already runs in a store-owned transaction. The platform id
convention (`ws_`/`acct_` + UUIDv7, documented in `Nexus-IDS.md`) extends naturally
to audit events. Telemetry is deliberately fail-open and PII-scrubbed — unusable as
an audit channel by design.

## Goals / Non-Goals

**Goals:**

- Fail-closed, same-transaction audit recording for every admin mutation on both
  surfaces, plus denial and bootstrap events.
- Individually identifiable admin credentials with rotation/revocation, replacing
  the two shared env tokens (with a migration mode).
- Recorded-but-untrusted operator assertion.
- Per-surface query + export endpoints; retention with purge as the only deletion.

**Non-Goals:**

- Operator OIDC on admin surfaces (v2; the asserted-operator field is its seam).
- A unified cross-plane audit view (each plane serves its own ledger; a reader can
  merge exports by event time).
- Data-plane / workload audit (the box's job, per the trusted-header contract).
- Signing-key custody events (OpenBao's audit device is the record; runbook links it).
- SIEM/OCSF integration (export is NDJSON; a consumer can transform).

## Decisions

### D1. One capability, two co-located ledgers

Each plane gets an `admin_audit_events` table in its own store, written by the same
transaction as the mutation. Rationale: atomicity ("unrecorded ⇒ uncommitted") is
only achievable co-located; admin volume is tiny; a cross-plane store would add a
network dependency to every admin mutation. Alternative rejected: a central audit
service — turns fail-closed into fail-slow/fail-open and adds an availability
coupling between planes.

### D2. Recording lives in the store layer (core), surfaces stay thin

The audit insert is a core store function invoked inside each mutation's
transaction — `record(event, &mut tx)` — never in the HTTP adapter. The adapter
contributes only transport facts (source ip, asserted-operator header, trace id)
passed down as a context value. Denial events (no transaction exists) use a
standalone best-effort insert on the 401 path: a failed denial write logs an error
and stays a denial. Rationale: composable core / thin surfaces; the fail-closed
guarantee must sit where the transaction is.

*Implementation note:* the store layer already owned every transaction, so the
mutating store-port methods gained an `AuditCtx` parameter and record internally.
Two handler flows that previously issued multiple store calls were folded into one
audited transaction each (`provision_account` = account insert + owner membership;
`create_workspace` = insert + create-time ownership), so "one admin mutation, one
event, one transaction" holds — a side benefit is those flows are now atomic
end-to-end. No-op mutations (unknown-id reconfigure, idempotent delete of a missing
row) mutate nothing and record nothing; idempotency-key replays record
`outcome=replay` as specified.

### D3. Event shape and ids

`aev_<uuidv7>` event ids, minted per plane by the same prefix+UUIDv7 convention as
`ws_`/`acct_` (documented in `Nexus-IDS.md`; the convention, not a shared crate, is
the contract — the two workspaces stay uncoupled). Columns: `event_id`,
`occurred_at`, `surface`, `action` (closed vocabulary as a checked string, e.g.
`workspace.transfer`, `role.assign`, `auth.denied`, `bootstrap.grant`), `actor_token_id`,
`asserted_operator` (nullable, length-capped, stored verbatim), `target_kind` +
`target_id`, `outcome` (`ok` | error class | `replay`), `detail` (JSONB: request
semantics minus secrets), `trace_id`, `source_ip`, `idempotency_key`. Schema lives
in a native `.sql` migration file per plane (data-is-not-code).

### D4. Named admin tokens, per plane

A per-plane `admin_tokens` table: `token_id`, `name`, peppered-HMAC secret hash,
`status`, timestamps, rotation lineage. Verification replaces the single env-token
compare in each service's auth layer; multiple concurrently valid tokens.
Build-vs-adopt: see **Decision: named admin credentials** below.

### D5. Legacy-token migration mode

During migration each service accepts the legacy env token **iff**
`ADMIN_LEGACY_TOKEN_OK=true`, attributing events to the reserved token id
`legacy-shared` and logging a deprecation warning per use. Default off for new
deployments. Rollout: ship dual-mode → provision named tokens per caller → flip the
flag off → remove the env token. Rollback at any step is re-enabling the flag.
This is the **BREAKING** surface of the change, made non-atomic on purpose.

### D6. Query and export

`GET /audit/events` on each surface (same admin auth): filters `from`/`to`/
`actor`/`target`, time-ordered, cursor-paginated; `GET /audit/events/export`
streams NDJSON for a time range. Read-only handlers; no mutation endpoints exist
over the ledger. OpenAPI specs updated alongside (`openapi/*.yaml`).

### D7. Append-only enforcement and retention

The service DB role receives `INSERT`/`SELECT` only on the ledger (no
`UPDATE`/`DELETE`); grants live in the migration. Retention is a config value per
plane (`AUDIT_RETENTION_DAYS`, validated at startup against a compile-time floor of
**365 days**, default **450 days** — SOC 2 mandates no period, but auditor
expectation is 12 months and a Type II 12-month observation window needs ~15
months to cover the period plus buffer; the ledger is tiny, so everything stays
hot, no storage tiering); a periodic purge job — the only deleter — runs as a
separate maintenance role. Out-of-band DB access: see **Decision: out-of-band DB
access auditing** below.

### D8. Bootstrap grant event

The existing startup bootstrap path (`AUTHZ_BOOTSTRAP_ADMIN_SUB`) writes a
`bootstrap.grant` event in the same transaction as the grant, actor token id
`bootstrap`; the already-an-admin no-op writes nothing.

### Decision: audit ledger storage & append-only integrity — Build (thin) on Postgres

- **Status**: approved
- **Why**: the fail-closed invariant (unrecorded ⇒ uncommitted) is only achievable
  inside the mutation's own transaction; no mature audit store can participate in
  it, and the build is one table + one insert function + grants per plane.
- **Considered**: immudb / dedicated audit store — network hop breaks
  same-transaction atomicity; hash-chained table — tamper-evidence SOC 2 doesn't
  require, plus chain-repair burden.
- **Isolation**: the `record(event, &mut tx)` store function; schema in native
  `.sql` migrations.

### Decision: named admin credentials — Extend the customer-api-keys machinery

- **Status**: approved
- **Why**: the peppered-HMAC + rotation-lineage + revocation pattern already exists
  in-repo and is proven; no new runtime dependency, callers keep plain bearer
  semantics.
- **Considered**: OpenBao AppRole — puts OpenBao on every admin call's hot path and
  changes all callers; OIDC client-credentials — the v2 operator-OIDC path,
  heavyweight now.
- **Isolation**: each plane's auth layer verifies against its own `admin_tokens`
  table; token provisioning is a store function behind the surface adapter.

### Decision: out-of-band DB access auditing — Adopt pgAudit

- **Status**: approved
- **Why**: actively maintained (per-version branches for PostgreSQL 14–19); closes
  the psql-bypass hole the application ledger cannot see, scoped to write/DDL by
  non-service roles on both admin databases.
- **Considered**: defer with a compensating control (restricted DB access +
  break-glass runbook) — acceptable to auditors but a standing residual finding.
- **Isolation**: DB-layer extension configured in deployment; emits via the
  existing server-log pipeline, never touched by application code.

### Decision: export format — Build-thin NDJSON export

- **Status**: approved
- **Why**: lossless, streamable, ingestible by any SIEM; mapping to a schema
  standard buys nothing until a SIEM consumer exists.
- **Considered**: OCSF-mapped export — rising standard (AWS Security Lake, Datadog)
  worth adopting later as a pure output adapter over the same events.
- **Isolation**: export is a read-only serializer over the ledger; an OCSF adapter
  can be added beside it without touching the record shape.

## Risks / Trade-offs

- [Legacy mode lingers forever] → deprecation warning on every legacy use is
  log-visible; go-live runbook gets an explicit "flag off" step; denial of the flag
  in production config review.
- [Asserted operator read as authenticated identity] → stored in a column named
  `asserted_operator`, marked asserted in exports; docs state it confers nothing.
- [Ledger growth] → tiny admin volume; retention purge; time-ordered UUIDv7 keys
  index cheaply.
- [Denial-event flooding of the ledger by an unauthenticated scanner] → denial
  writes are best-effort and rate-limited per source; the mutation ledger is
  unaffected (separate action class, same table).
- [Migration/maintenance role split adds ops friction] → both roles are created in
  the same migration; runbook documents them once.

## Migration Plan

1. Ship migrations (ledger + tokens tables + grants) and dual-mode auth, flag ON.
2. Provision named tokens for each real caller (broker, ops CLI, CI); update their
   secrets.
3. Flip `ADMIN_LEGACY_TOKEN_OK=false`; verify via denial events that no legacy use
   remains; remove the legacy env tokens.

Rollback: re-enable the flag; the ledger schema is additive and needs no rollback.

## Resolved Questions

- **Retention floor** — resolved in D7: floor 365d, default 450d. SOC 2 mandates no
  period; 12 months is the auditor expectation, and a Type II 12-month observation
  window is covered with buffer at ~15 months.
- **Auto-populating `asserted_operator` from `creator_sub`** — **no**, per the
  industry pattern (AWS STS `SourceIdentity`, OAuth `act` claim): the asserted
  human identity is set explicitly by the authenticated caller at the entry point,
  recorded immutably and distinctly from the authenticated principal, and never
  inferred from payload fields — inference would conflate request semantics
  (`creator_sub` = whom the key is issued for) with attribution (who is performing
  this administrative act). The two stay separate columns with separate meanings.
