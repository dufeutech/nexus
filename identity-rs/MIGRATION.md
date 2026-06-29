# Identity plane: MongoDB → PostgreSQL migration

**Status: SHIPPED.** MongoDB has been removed from the identity plane; profiles
now live in the PostgreSQL that ZITADEL already uses, under an `identity` schema —
exactly the way the routing plane reuses that Postgres under a `routing` schema
(RFC decision 14). One database technology, one freshness primitive
(`LISTEN/NOTIFY`), one backup/HA story, one less stateful system to operate.

> **How it was actually rolled out.** Because the project is **pre-production**,
> the cautious multi-phase cutover originally drafted below (a `PROFILE_PG_URL`
> env *switch* with a `MongoStore` fallback per service, a backfill window, and
> keeping Mongo warm for rollback) was **collapsed into a single hard cutover**:
> Mongo was deleted outright and Postgres wired in directly. The design sections
> (store layout, the `seq`-cursor feed) are exactly what shipped; the phase
> checklist is kept as a record of the reasoning, annotated with what was skipped.

## Why this is low-risk

The identity store is a **rebuildable projection, not a system of record**:

- The **reconciler** (`reconciler/src/main.rs`) reconstructs every profile
  authoritatively from ZITADEL on each pass via `build_profile_from_user`.
- The **sidecar** cache (`sidecar/src/main.rs`) warms **lazily** — readiness
  means "store reachable + feed open", never a full population load.

So there is **no Mongo→Postgres ETL**. Stand up an empty schema, let one
reconcile pass backfill it, the sidecar warms on demand. The store can be dropped
and rebuilt at will. This is the single most important fact de-risking the work.

## What does NOT change

- `core/src/profile.rs` — the `Profile` shape (already `Serialize`/`Deserialize`).
- `core/src/sync.rs` — the event→Profile mapping and the **domain** version guard
  (`version`/`updated_at`). Store-agnostic, pure functions. Untouched.
- `core/src/reconcile.rs` — drift diff. Untouched.
- `core/src/store.rs` — the `ProfileStore` **port** (`get`/`put`/`delete`/
  `scan_all`/`watch`) and the `Change`/`ChangeEvent`/`WatchToken` types. The whole
  point of the port is that a new adapter drops in with zero changes to callers.
- The three binaries' logic — they depend only on `Arc<dyn ProfileStore>`. Only
  their `main()` wiring (which adapter to construct) changes.

That hexagonal boundary is what makes this a contained swap rather than a rewrite.

---

## The one hard part: reproducing `watch` (the resumable change feed)

Mongo change streams give `watch` a **resumable, ordered** feed for free.
`LISTEN/NOTIFY` alone does not (best-effort, no replay, no resume token). But look
at how the *only* consumer — the sidecar — actually uses it
(`sidecar/src/main.rs:297`):

- The resume token is held **in-memory only**, on purpose: "a process restart
  starts with an empty cache, so there is nothing stale to miss — only mid-process
  reconnects need to resume."
- On `Upsert` it refreshes **only entries already in cache** (`contains_key`);
  cold subjects load on demand.

So the real requirement is weaker than "durable replayable log": *during one
process lifetime, don't miss an update/delete to a currently-cached entry across a
reconnect blip.* That is fully satisfied by a **monotonic sequence cursor +
NOTIFY-as-wakeup**:

```
on connect:
  last = after_token.unwrap_or( SELECT coalesce(max(seq),0) )   // None = "from now"
loop:
  rows = SELECT sub, doc, deleted, seq
         FROM identity.profiles WHERE seq > last ORDER BY seq    // drain the gap
  for row in rows:
     yield ChangeEvent { change: deleted ? Delete(sub) : Upsert(doc), token: seq }
     last = seq
  wait for NOTIFY on 'identity_changes'  (with a periodic poll fallback)
```

NOTIFY is purely "something changed, wake up". **Correctness comes from the `seq`
cursor**, so a dropped NOTIFY self-heals on the next signal or the poll tick —
the same best-effort philosophy the routing README already documents, and
strictly more robust than change streams for our usage. `WatchToken` becomes the
8-byte `seq` instead of a BSON resume token; since it's in-memory only there is no
token-format migration to worry about.

---

## Schema (`identity` schema in ZITADEL's Postgres)

Mirror the Mongo adapter's "one collection keyed by `sub`, store the whole
Profile as a document" model — JSONB `doc` is the minimal, exact analogue of
`to_document`/`from_document`, so the Profile shape can evolve with **no schema
migration**. Add three control columns the feed needs.

```sql
CREATE SCHEMA IF NOT EXISTS identity;
CREATE SEQUENCE IF NOT EXISTS identity.profile_seq;

CREATE TABLE IF NOT EXISTS identity.profiles (
    sub     text   PRIMARY KEY,             -- = Profile.sub (was Mongo _id)
    doc     jsonb  NOT NULL,                -- serde_json(Profile)
    deleted boolean NOT NULL DEFAULT false, -- tombstone, see below
    seq     bigint NOT NULL DEFAULT nextval('identity.profile_seq')
);
CREATE INDEX IF NOT EXISTS profiles_seq_idx ON identity.profiles (seq);
```

**Tombstones for resumable deletes.** A hard `DELETE` can't be replayed by a
`seq > last` catch-up query, so `delete` sets `deleted=true` and bumps `seq`
instead of removing the row. `get`/`scan_all` filter `deleted=false`; the feed
maps `deleted=true → Change::Delete(sub)`. This preserves Mongo's delete-event
parity (important: a missed delete with the default 12h TTL would otherwise keep a
removed user resolving for hours). Prune tombstones only when
`seq < (max(seq) - safety_margin)` AND older than `max(cache TTL, reconcile
interval)`, so an unconsumed delete is never dropped. (Suspensions — the
security-critical revocation — are *upserts* `is_suspended=true`, already fully
covered by the upsert catch-up path.)

**Typed-columns alternative:** if you'd rather have queryable columns (mirrors
`routing.tenants`), spell out each field. More code and a real migration on every
Profile change; not worth it for a stable, key-only-accessed projection. Start
with JSONB.

**Optional bonus the relational store enables:** make the domain version guard
*atomic* with `ON CONFLICT (sub) DO UPDATE SET ... WHERE
(EXCLUDED.doc->>'version')::bigint >= (identity.profiles.doc->>'version')::bigint`.
Today's `get`-then-`apply`-then-`put` in the sync-worker has a benign TOCTOU race
(same as Mongo). This closes it. Strictly optional.

---

## What shipped (was Phases 1–5)

- [x] **`identity-rs/store-postgres/`** — `PgProfileStore` implementing
      `ProfileStore` (`get`/`put`/`delete`/`scan_all`/`watch`) + `connect` +
      `init_schema`, mirroring `routing-rs/store-postgres`. JSONB `doc` column,
      tombstone deletes, `seq`-cursor feed with `LISTEN/NOTIFY` wakeup + 30s poll
      fallback. Statement cache disabled for pooler-safety.
- [x] **Workspace wiring** — `store-postgres` added to `members`; `sqlx` added to
      `[workspace.dependencies]` (same features as `routing-rs`).
- [x] **All three binaries hard-wired to Postgres** (no env switch, no `MongoStore`
      fallback — the pre-production simplification): each `main()` constructs
      `PgProfileStore::connect(PROFILE_PG_URL)`. The writers (sync-worker,
      reconciler) call `init_schema()` on startup; the sidecar only reads +
      listens. There is **no `PROFILE_PG_READ_URL`** — the binaries read one URL.
- [x] **`store-mongo` deleted**; `mongodb` + `bson` dropped from the workspace.
- [x] **Root `docker-compose.yaml`** — `mongo`/`mongo-init` services and
      `mongo-data` volume removed; the three identity services take
      `PROFILE_PG_URL: postgres://postgres:postgres@postgres:5432/zitadel` and
      depend on `postgres: { condition: service_healthy }`.
- [x] **`deploy/`** — `helm/identity-plane` gained a `postgres:` values block, a
      `secret-pg.yaml`, pg helpers, and `PROFILE_PG_URL` via `secretKeyRef`,
      mirroring `routing-plane`. `edge-platform`, `deploy/compose`, `.env.example`,
      `deploy/README.md`, and `.github/workflows/ci.yml` all converted.
- [x] **`Dockerfile`** — unchanged (same workspace build; the Mongo crate just
      stops compiling). `protoc` still required for the sidecar.

### Pooler caveat (now applies to the identity store too)

`PROFILE_PG_URL` MUST reach the primary on a **session** connection. A
transaction-mode pooler (PgBouncer, Supabase `:6543`, some RDS-Proxy modes)
silently swallows `LISTEN`, so the sidecar's change feed would connect without
error and simply never receive updates — profiles would stay stale until the
cache TTL. This is the same constraint `deploy/README.md` documents for
`ROUTING_PG_URL`.

### Backfill (no ETL)

The store is a rebuildable projection, so there was no data migration: point the
reconciler at the empty `identity` schema and one reconcile pass reconstructs
every profile from ZITADEL; the sidecar warms lazily.

## Phase 6 — Verification (in progress)

- [x] `cargo build --release` + `cargo test` (all crates) green; zero warnings.
- [x] `store-postgres` integration tests (`tests/integration.rs`) covering
      put/get, upsert, tombstone-delete, `scan_all`, and the `watch` feed
      (catch-up replay, live NOTIFY, resume-without-duplicates). Gated on
      `STORE_PG_TEST_URL`; run against a throwaway Postgres.
- [ ] `docker compose up` end-to-end smoke: profile resolves; a **suspension takes
      effect within seconds** (NOTIFY→seq-cursor path); a delete evicts the cached
      entry; reconciler backfill visible in `reconcile_last_drift_upserts`.

---

## Risk register

| Risk | Mitigation |
| --- | --- |
| Missed delete leaves a removed user cached up to the 12h TTL | Tombstone + `seq` catch-up replays deletes; never prune unconsumed tombstones |
| `LISTEN` silently dropped through a transaction-mode pooler | Feed connection must be a direct/session URL; document like routing; optional `PROFILE_PG_READ_URL` for pooled reads |
| Two writers (sync-worker + reconciler) race on one row | Same as Mongo today; domain version guard in `core::sync` still applies; optionally make it atomic in SQL (`WHERE version >=`) |
| `scan_all` full-table at scale | Unchanged from Mongo; the reconciler's `SHARD_TOTAL`/`SHARD_INDEX` seam still bounds it |
| NOTIFY ordering vs `seq` ordering | Feed is driven by the `seq` cursor, not NOTIFY payload order; NOTIFY is wakeup only |
| Hard cutover has no live rollback | Acceptable pre-production; the store rebuilds from ZITADEL (one reconcile pass), and `git revert` restores the Mongo path if ever needed |

## Net result

Two stores → **one** (ZITADEL's Postgres). Two freshness mechanisms (change
streams + LISTEN/NOTIFY) → **one** (LISTEN/NOTIFY across both planes). The
replica-set operational requirement and the `mongo`/`mongo-init` services
disappear. `core` and all three binaries are untouched except adapter
construction. Roughly: **delete** `store-mongo` (~114 LOC) + two Mongo deps;
**add** `store-postgres` (~180 LOC, mostly mirrored from routing).
