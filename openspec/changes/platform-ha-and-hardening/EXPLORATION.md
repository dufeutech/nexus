# Exploration — platform HA, trust-hardening, and observability frontiers

> Explore-mode capture (2026-07-08). Thinking + verified findings only — **no
> implementation**. Seeds up to three sequenced changes (A / B / D below). Facts here were
> verified against source on this date; re-check before relying on them (esp. the
> CockroachDB feature status, which moves).

## 0. What this is

Everything in the upstream contract (N1–N6) plus the identity plane and telemetry stack is
shipped. This is the "what's next" analysis. Three operational/defensive frontiers were on
the table; the user chose to explore **A, B, D**:

- **A — SLO / burn-rate policy** on the RED baseline ("is nexus healthy, how fast is it burning?")
- **B — trust-boundary hardening** (edge↔box: what may cross it, can it be forged?)
- **D — multi-region / HA** (what state must stay consistent across a region edge?)

(A fifth frontier, **C — self-service wildcard / plan-tier depth**, was noted as the only
*product/revenue*-shaped item and deliberately parked. **E — per-tenant cost attribution** also
parked.)

---

## 1. The spine: all three are "where is the domain boundary?"

- **A** draws a boundary around a *service* → is the latency/error contract met inside, and how fast is the error budget burning?
- **B** draws a boundary around a *box* → what identity/authz claims may cross it, and can they be forged?
- **D** draws a boundary around a *region* → what state must stay globally consistent, and what happens on partition?

### The coupling that decides sequencing: **D deletes B's only security control**

B's sole anti-bypass control today is an **L3 Kubernetes NetworkPolicy** (`edge-origin-trust`).
That works *inside one cluster*. The moment traffic crosses regions (D), edge-in-region-1 →
box-in-region-2 crosses a WAN the pod-selector NetworkPolicy does **not** span — and the bare
(unsigned) trusted headers (`x-user-entitlements`, `x-user-suspended`, geo, plan) become
forgeable on the wire. **B's premise ("trusted network") and D's gap ("cross-region path") are
the same boundary.** You cannot safely go multi-region without first generalizing B's trust off
the single-cluster L3 assumption.

### B itself splits into a floor and a D-gate

```
A — INSTRUMENT (ship first, always; it's the safety net for B and D)
      • fix RED histogram attrs (add `result`)  → outcome-aware SLOs
      • recording rules + multi-window burn-rate on the existing PrometheusRule scaffold
      • make deployment.environment.name a required deploy invariant
        │
B-floor — CARRIES OVER regardless of multi-region (pure hardening ROI)
      • extend signing (or cross-check) so entitlements/suspended aren't bare
      • denylist → allowlist header strip (kill the maintenance invariant)
      • key auto-rotation / KMS (today: manual openssl)
        │
B-gate + D — ONLY IF multi-region is real (one intertwined program)
      • edge↔box mTLS (NetworkPolicy can't span the WAN)
      • replace the pg_notify invalidation transport (see §5)
      • global-uniqueness authority for domains + cert issuance
```

**Sequencing decision (recorded):** **A ships first no matter what** — it's cheap, half-built,
has a real defect worth fixing, and it's the instrument for verifying B/D changes are safe. Then
the fork is a single binary: **is multi-region real (≤ ~1yr)?** If yes → `A → B-floor → (B-gate +
D)`. If "someday" → `A → B-floor → stop; park D`. None of B-floor is wasted if D never happens.

---

## 2. Verified findings (the research — non-obvious, keep)

### A — RED baseline is real but has a defect blocking real SLOs

- Only the two hot-path ext_proc planes emit true duration histograms:
  `router_ext_proc_duration_seconds` (`tenant-router/src/main.rs:81-117`) and
  `sidecar_ext_proc_duration_seconds` (`identity-rs/sidecar/src/main.rs:95-117`), buckets
  `[0.00005 … 5.0]`.
- **Defect:** both histograms are recorded with an **empty attribute set** (`.record(elapsed,
  &[])`, `main.rs:605` / `:1173`). So latency can be sliced only by service/env — **not by
  `result`**. The canonical availability SLO ("99.9% of *non-error* requests < Xms") is
  **impossible today** because success and error latency are fused.
- control-plane / authz-admin emit only labeled *mutation counters* (`control_mutations`,
  `authz_admin_mutations`) — rate/errors by `op`, no duration. membership-sync = counters only.
- Business metrics that exist: `router_authorize_total{result=allow|deny}`,
  `router_ext_proc_requests_total{result=reject}` (unknown-host),
  `sidecar_ext_proc_requests_total{result=forbidden|not_found|unavailable_closed}` (403/404/
  fail-closed 503), `control_mutations_total{op=declare_quota_exceeded|unauthorized}`.
- **Alert scaffold already exists** (Helm `PrometheusRule` CRs, `deploy/helm/*/templates/
  prometheusrule.yaml`, default-off) — but they are **single-window threshold** alerts. **No
  burn-rate, no recording rules, no error-budget** anywhere. Lab Prometheus
  (`monitoring/prometheus/prometheus.yml`) has no `rule_files:` at all.
- **Cardinality ceiling** (collector `transform/cardinality` keep_keys,
  `monitoring/otel-collector/otel-collector.yaml:60-80`): SLOs can slice only by
  `service.*`, `deployment.environment*`, `otel.scope.name`, and low-card RED dims `result`,
  `op`, `tier` (+ `http.*`/`rpc.*`). Everything else is dropped pre-Prometheus.
- `service.name` / `service.version` are dependable + promoted to labels;
  **`deployment.environment.name` is operator-supplied** (`OTEL_RESOURCE_ATTRIBUTES`), not
  code-guaranteed — a per-env SLO layer must make it a required invariant.

### B — sole anti-bypass is L3; the most sensitive headers are the least protected

- **Edge→box is plaintext HTTP, no mTLS.** All `pool_*` clusters are plaintext port 80
  (`edge/envoy.yaml:416-458`). The only anti-bypass control is a default-deny **NetworkPolicy**
  whose only ingress peer is the edge pod selector (`deploy/helm/*/templates/
  networkpolicy-backend.yaml`), the `edge-origin-trust` capability
  (`openspec/specs/edge-origin-trust/spec.md`). Chart render fails closed if it's unset.
- **Only `x-identity-contract` is signed** (ES256 JWS, minted per-request,
  `identity-rs/sidecar/src/signer.rs:116-138`; claims in `identity-rs/core/src/contract.rs`).
  `aud` = destination box (from `x-route-pool`) scopes replay; short TTL (`CONTRACT_TOKEN_TTL_
  SECONDS`, default 60s).
- **Everything else is bare (unsigned) trust:** `x-user-entitlements`, `x-user-suspended`,
  `x-auth-method`, all `x-geo-*`/locale, `x-workspace-plan`, etc. Notably the contract
  **deliberately excludes** entitlements + suspended (revocation-sensitive, always live from the
  profile) — so the two headers gating *"is this user cut off right now"* ride pure bare trust.
- Client-header strip is a **denylist** (explicit `remove:`, first HTTP filter,
  `edge/envoy.yaml:179-262`) — so completeness is a **maintenance invariant**: any trusted header
  a box reads that nobody enumerated is forgeable (caught only for the identity subset via
  contract verification). Mitigated by a defense-in-depth re-strip in the sidecar
  (`sidecar/src/main.rs:662-808`).
- **Keys:** operator-supplied EC P-256 PEM at `SIGNING_KEY_PATH`; JWKS served verbatim at
  `/.well-known/jwks.json` on `:9210` (`sidecar/src/jwks.rs`). **Manual overlap rotation**, no
  KMS, no automation (`docs/runbook-contract-signing-keys.md`).

### D — the routers are already region-safe; the *primary* is the whole gap

- **Region-safe as-is:** routers hold no bulk state, resolve lazily on cache miss, self-heal on a
  **600s TTL** (`ROUTING_CACHE_TTL`, `tenant-router/src/main.rs:847`). L1 (moka) + optional L2
  (Redis) + sidecar profile cache all converge with zero coordination.
- **The single-primary spine (everything hard-couples here):**
  1. one writable Postgres primary per plane (routing, identity); only knob is an optional
     read-pool URL `ROUTING_PG_READ_URL` (pooling, not replica-routing).
  2. `pg_notify` invalidation (`routing_invalidations`, `routing_membership_changes`,
     `identity_changes`) — **intra-server only; physical replicas do NOT deliver NOTIFY**
     (`deploy/README.md:558-560`). This is *the* cross-region blocker.
  3. CertMagic cert store — "one cluster = one Postgres" (`docs/on-demand-tls.md`).
  4. leader-elected TXT poll via session advisory lock `pg_try_advisory_lock`
     (`control-plane/src/main.rs:77`, `VERIFY_POLL_LOCK_KEY`) — only meaningful within one PG.
- **Must be globally unique (no cache can relax):** domain ownership (two regions must not grant
  the same host), cert issuance. Plus globally-consistent: workspaces/plans/quotas, accounts,
  memberships, auth-routes, identity authz facts.
- **So D is not a router rewrite** — it's "replace the invalidation transport + provide a
  global-uniqueness authority for domains + certs."

### What Redis is *actually* used for (corrects an earlier overstatement)

- **One job, one plane:** the **optional L2 shared cache** in tenant-router only
  (`cache-redis/src/lib.rs`, `SharedCache` port). Caches routing *decisions* as JSON under a
  `routing:` prefix with TTL; ops are just `get`/`put`/`invalidate` (`DEL`).
- **Strictly optional** — enabled only if `REDIS_URL` set; connect failure → **degrade to
  L1-only** (a supported prod mode); every op bounded 100ms so a dead L2 never wedges the hot path.
- **Redis is NOT a message bus.** The signal is carried by `pg_notify`; Redis is a *passive
  recipient* of an eviction. The identity plane doesn't use Redis at all.
- Consequence: "reuse Redis as the bus" = a **new usage mode** (pub/sub or Streams, which it
  doesn't do today) **and** promoting Redis from optional → load-bearing. The only real Redis
  advantage vs NATS was "no new *service* to operate," not "reusing an existing capability."

---

## 3. The D decision — DB fork: CNPG vs CockroachDB

**They answer different questions.** The codebase's three Postgres-isms make the cost asymmetric.

| Postgres-ism | Powers | CNPG (CloudNativePG) | CockroachDB |
|---|---|---|---|
| `LISTEN/NOTIFY` | invalidation feed | ✅ unchanged (still PG) | ❌ **unsupported** → rewrite to CHANGEFEED |
| session `pg_try_advisory_lock` | leader-elected TXT poll | ✅ unchanged | ❌ **session-scoped unimplemented** (2026) → rework |
| CertMagic PG storage | shared cert store | ✅ unchanged | ❌ revalidate / likely replace |

**Verified CockroachDB status (mid-2026):** NOTIFY/LISTEN still unsupported (cockroach #41522,
open since 2017; alternative = CHANGEFEED). Advisory locks: transaction-scoped landed (#168355)
but **session-scoped still open/in-progress** (#169981, opened May 2026) — and the codebase uses
the *session-scoped* flavor. Blocking builtins also ignore `lock_timeout` (#170014).

- **CNPG = "Postgres, made HA."** Operator: streaming replication, automated failover,
  single-primary + replicas. All three isms survive → a **deployment** change, near-zero code.
  Solves *availability* (intra-region HA + async cross-region failover, accept an RPO window).
  Does **not** give active-active writes or row-level residency.
- **CockroachDB = "truly distributed SQL."** A **migration**, not config: breaks all three isms.
  But makes **global uniqueness free** (domain ownership + cert issuance as plain constraints in
  one logical cluster) and gives **geo-partitioning** (`REGIONAL BY ROW`) for real residency.

**Collapsed fork:** *one write region, or many?*
- **One write region** (survive failures) → **CNPG**. Cockroach here is all cost, no benefit.
- **Many write regions / data residency** → **CockroachDB**; its NOTIFY cost is mostly sunk
  because you'd rebuild the transport anyway, and you collect uniqueness + residency.

---

## 4. The transport decision — NATS (given it's coming regardless)

The user intends to **run NATS as a platform component either way** (future uses). That collapses
the bus choice: the only thing favoring Redis-as-bus was "no new service," and that's gone.
RabbitMQ was ruled out earlier (wrong category — a work-queue/complex-routing broker for a
broadcast-a-tiny-key-cross-region problem; heaviest ops; weakest cross-region via federation).

**Why NATS fits:**
- Native fan-out pub/sub (subjects) — matches broadcast-to-every-router semantics.
- **JetStream stream-sequence + durable consumer is a 1:1 fit for the `identity_changes` `seq`
  cursor** already hand-built on Postgres.
- Cross-region fan-out (gateways/superclusters) is first-class, not a bolt-on.
- Keeps Redis in its lane (optional value cache); no second personality.

**Strategic bonus — committing to NATS *de-risks staying on CNPG*.** The strongest Cockroach
argument was "you'll rebuild the transport anyway (NOTIFY can't cross regions)." If NATS is your
signal backbone regardless, you solve cross-region freshness *at the NATS layer, independent of
the DB* — so **CNPG + NATS = multi-region reads + fresh invalidation + single write primary**,
no Cockroach needed. Cockroach re-enters only for active-active writes / residency.

### Target architecture

```
   Postgres / CNPG   →  source of truth      (storage, constraints, global uniqueness)
   NATS              →  the nervous system   (ALL async signals, cross-region)
   Redis             →  optional hot cache   (unchanged; stays optional, stays a cache)
```

### Honest caution — "running NATS" is a spectrum

- **core NATS** (fire-and-forget subjects) ≈ free — matches routing invalidation, which already
  tolerates drops via the 600s TTL backstop.
- **JetStream** (durable, replay-from-seq) = real infra (file storage, RAFT) — needed for the
  identity revocation path (`seq` cursor; "suspend within seconds" is security-relevant).
- **JetStream replicated across regions** = the heavy end (stream mirrors/sources, own
  consistency/latency story). Price NATS as a *graduated* commitment.
- Watch the YAGNI trap: if this multi-region work is what actually *pulls NATS in* (vs NATS being
  independently near-term), then it isn't "free here" — keep the first step small.

### Adoption path (thin adapter, reversible — matches CLAUDE.md build-vs-adopt)

1. **Routing invalidation first** — add a `NatsInvalidations` adapter behind the **existing**
   `router_core::store::Invalidations` port (core NATS, fire-and-forget). Router core doesn't
   change; a config swap, fully reversible. Delivers a cross-region win even if D is months out.
2. **Identity `seq` path later** — the sidecar's `identity_changes` listener is **bespoke** (not
   behind a shared port yet), so this needs a port introduced *and* the cursor mapped onto
   JetStream stream sequences. Do it when the durable path actually must cross regions.

---

## 5. Open decisions (still unmade — resolve before proposing)

1. **Multi-region driver:** failure-survival (→ CNPG) vs data-residency / active-active writes
   (→ CockroachDB). This picks the DB row and decides whether D is a program or parked.
2. **Is NATS independently near-term**, or is D pulling it in? Decides whether NATS is "free" here.
3. **B-floor scope for the signed contract:** extend the JWS to cover entitlements/suspended, or
   add a box-side cross-check? (Tension: those are deliberately live/bare for revocation freshness
   — signing them re-introduces a staleness window bounded by the token TTL.)
4. **A's histogram fix:** add `result` (and maybe `route`) as a low-card attribute on the duration
   histograms — confirm it stays within the collector cardinality allow-list.
5. **edge↔box mTLS (B-gate):** independent of the DB choice; still required for cross-region. Not
   yet scoped.

---

## 6. Next steps

1. ~~**`/opsx:propose` for A**~~ — **DELIVERED** as change `slo-burn-rate-policy` (2026-07-08):
   histogram-`result` defect fix (outcome-aware latency in both hot-path ext_proc planes),
   `deployment.environment.name` as a deploy-time fail-closed invariant (Rust startup guard +
   Helm render guard + charts now supply it), and the SLO/burn-rate layer (Adopt Sloth v0.16.0 →
   generated MWMB rules, per-environment, promtool-verified). B and D below remain parked; the
   recorded multi-region driver is failure-survival → CNPG.
2. Resolve **Open Decision 1** (multi-region driver) → then propose either:
   - `B-floor` (signing coverage + allowlist strip + key rotation) as standalone hardening, and
     park D; **or**
   - the `B-gate + D` program: `NatsInvalidations` adapter behind the `Invalidations` port
     (step 1 of §4), CNPG deployment (if failure-survival), edge↔box mTLS.
3. Gate the DB + transport choices through **`/opsx:decide`** (Rent>Adopt>Extend>Fork>Build) and
   record into the change's `design.md`.
