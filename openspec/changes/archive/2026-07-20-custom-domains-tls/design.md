## Context

Customers bring their own domains and point them at the platform; each needs an automatically
obtained, served, and renewed public TLS certificate. The domain set is tenant-driven and unbounded,
so the design's first-order constraint is **growth without rewrite**: getting from thousands to
hundreds of thousands (or more) of domains must be a sequence of swaps behind stable interfaces, never
a re-architecture. Certificate issuance (ACME protocol, rate-limit handling, renewal scheduling,
fleet coordination) is security- and reliability-critical — an adopt-before-build concern.

The platform already has an identity/authz **edge** (Envoy-based) that does tenant resolution,
identity enrichment, and the auth gate. `domain-host-resolution` already mandates that request
routing and **on-demand certificate authorization** resolve the identical host set through one shared
matcher — so this design consumes that matcher rather than inventing a second notion of "known host."
Existing infra provides Postgres, NATS, and OpenBao (Transit).

The build-vs-adopt decisions below are the recommended calls from exploration; `/opsx:decide` ratifies
them before `/opsx:apply`.

## Goals / Non-Goals

**Goals:**
- Obtain/serve/renew customer-domain certificates automatically, on demand, with no per-domain operator action.
- Preserve the invariant: **no rewrite from 1k → 1M domains — every scaling step is a swap behind an existing seam** (storage backend, issuer list, or LB topology), never an application-code change.
- Keep certificate automation a **side tool**: an issuer outage degrades only new-domain onboarding, never live traffic.
- Adopt the ACME engine and the store; build only the thin `ask`-gate adapter over the existing matcher.

**Non-Goals:**
- Wildcard certificates for customer apex domains (requires DNS-01 against DNS zones we do not control) — out of scope; only single-hostname on-demand issuance.
- Changing identity enrichment, the auth gate, tenant resolution, or the trusted-header model.
- Choosing the final CA-scale posture (multi-account shard sizing) now — it is a deferred config swap behind a seam.
- Internal/service-mesh certs (that stays with OpenBao PKI) — this is public customer-domain TLS only.

## Decisions

Dependency direction is **inward-only**: the adopted edge (ACME engine) depends on nexus's
authorization decision and storage adapter; nexus core has no compile-time dependency on the edge.
Concrete tools enter only through adapters. Native-format config (Caddyfile/JSON, SQL) lives in
external files loaded via adapters, never inlined.

### D1 — Adopt certmagic (via Caddy) as the on-demand ACME engine  *(critical concern: reliability/security → ADOPT)*
Caddy embeds certmagic, which is purpose-built for on-demand TLS + `ask` gate + fleet-shared storage
("10 or 1,000 servers sharing certs"). **Recommendation: Adopt.**
Alternatives rejected: *cert-manager + Envoy Gateway* — declarative Certificate-per-domain, no
issue-on-handshake, strains at high cardinality (kept as fallback only if domain count stays bounded);
*rustls-acme* — no on-demand-at-fleet, weak DNS/ecosystem; *hand-roll* — a defect for a security-critical
concern per the adopt-before-build gate.

### D2 — Topology: Caddy TLS-terminating front tier → existing Envoy edge  *(start simple, seam kept open)*
Caddy terminates customer-domain TLS and forwards to the existing identity/authz edge.
**Recommendation: ship this (option #1, zero bridge).** The alternative — certmagic issues into the
store and a small **SDS bridge** feeds Envoy so Envoy terminates (option #2, removes the extra hop) —
stays open because the **Postgres store is the stable seam**; migrating #1 → #2 is non-destructive and
touches no issuance logic.

### D3 — Store backend: Postgres via certmagic's Storage interface  *(critical concern: reliability → ADOPT infra)*
Use the existing Postgres behind certmagic's `Storage` interface; **never filesystem** (breaks ~10k on
inode/lock pressure). **Recommendation: Adopt Postgres now.** The `Storage` interface is the seam:
Postgres → Redis → sharded store is a later adapter swap. The same store provides the distributed lock
that gives fleet single-flight (`certificate-store-durability`).

### D4 — CA relationship: Let's Encrypt + ARI, override + issuer-fallback deferred behind the seam
Enable **ARI** so renewals are rate-limit-exempt — steady-state renewal of a large population is free;
the governed quantity is *net-new onboarding rate* (~2,400 orders/day/account default, overridable).
**Recommendation: LE + ARI now; request a per-account new-order override before any bulk onboarding.**
Multi-account sharding and a second issuer (e.g. ZeroSSL) stay deferred as config behind certmagic's
issuer list — no code change to add them.

### D5 — Keys: ECDSA (P-256), not RSA  *(lock now — expensive to reverse)*
ECDSA gives cheaper handshakes at every scale; changing key type later means re-issuing every
certificate. **Recommendation: ECDSA from day one.**

### D6 — The `ask` gate: a thin nexus endpoint over the shared matcher  *(the one BUILD — thin adapter)*
certmagic calls an `ask` endpoint on first handshake; it is a thin, read-only nexus HTTP handler that
answers via the **existing `domain-host-resolution` matcher** (single source of truth — no second
host-recognition path) and applies negative caching. This is the only bespoke code and it keeps cert
automation a side tool: nexus is a lookup the edge calls, not a dependency of live traffic.

### D7 — Edge scaling: stateless "any node serves any domain", SNI-shard deferred
Start with a stateless edge fleet over the shared store, each node holding a per-node LRU sized to the
**working set** (`certificate-store-durability` bounds memory to hot-set, not total). **Recommendation:
stateless now.** If the hot set later exceeds a node, introduce **SNI-sharded L4 hashing** at the LB —
a topology change, not an app change, precisely because the edge is stateless.

### D8 — Secret custody: ACME account key in OpenBao Transit
The long-lived ACME account key is custodied in OpenBao Transit (consistent with existing signing-key
custody); leaf certs/keys live in Postgres (hot store). Secrets are injected at runtime, referenced by
key, never committed.

### Ratified build-vs-adopt decisions (`/opsx:decide`, 2026-07-09)

The blocks below are the authoritative gate outcomes for this change's critical concerns; D1–D8 above
are the supporting design narrative.

#### Decision: On-demand ACME automation — Adopt certmagic (via Caddy)

- **Status**: approved
- **Why**: Purpose-built for on-demand TLS + `ask`-gate + fleet-shared storage; its ACMEz layer gives native ARI ("just works" on Caddy 2.8+). Hand-rolling the ACME protocol/rate-limits is a defect under the adopt-before-build gate.
- **Considered**: cert-manager + Envoy Gateway (no first-handshake issuance; Certificate/Secret sprawl at high cardinality); rustls-acme (no on-demand-at-fleet; you would build single-flight/negative-cache/store coordination yourself).
- **Isolation**: runs as the TLS-terminating front tier; enters the system only through the `ask` endpoint contract and the storage adapter. Nexus core has no compile-time dependency on it.

#### Decision: Certificate store backend — Adopt Postgres (behind certmagic's Storage interface)

- **Status**: approved
- **Why**: Durable single source of truth already operated in-infra; supplies the distributed lock for fleet single-flight; never filesystem (breaks ~10k on inode/lock pressure).
- **Considered**: Redis module (an extra datastore for a durability-critical store; the declined-domain check is the one certmagic explicitly warns can DDoS storage); S3-compatible (no native lock — single-flight becomes yours; slow per-object hot-path reads).
- **Isolation**: certmagic `Storage` interface (module `certmagic-sqlstorage`); swap to Redis/sharded is an adapter change. Hot path shielded by per-node LRU + the negative cache from `certificate-issuance-authorization`.

#### Decision: CA / issuance provider — Rent Let's Encrypt (+ ARI)

- **Status**: approved
- **Why**: Infrastructure (Rent). Free and ubiquitous; ARI is live in production with a Let's-Encrypt-specific rate-limit exemption, so steady-state renewal of a large population is unthrottled — the governed quantity is net-new onboarding (overridable per-account limit).
- **Considered**: ZeroSSL fallback — **deferred**: ARI unconfirmed (its rate-limit exemption is LE-specific and would not transfer) and it needs EAB credentials; kept as config-only behind the issuer-list seam until onboarding volume or outage-risk justifies the second CA. Commercial high-volume ACME (paid; premature).
- **Isolation**: certmagic issuer list; adding the second issuer later is config-only, no code change.

#### Decision: Certificate-issuance authorization gate — Build (thin adapter)

- **Status**: approved
- **Why**: No external tool authorizes issuance against *our* tenant model; the decision must reuse the existing `domain-host-resolution` matcher (single source of truth). Justified Build — it is inherently our domain logic, kept thin, read-only, and negative-cached.
- **Considered**: certmagic's built-in `ask` URL only *calls out* — it supplies no decision logic to adopt; a static allowlist (rejected — would duplicate the matcher and drift from routing).
- **Isolation**: a thin nexus HTTP `ask` endpoint over the shared matcher; the only bespoke code in this change. certmagic depends on it, not the reverse.

#### Decision: ACME account-key custody — Rent OpenBao (Transit)

- **Status**: approved
- **Why**: Infrastructure (Rent). Consistent with existing signing-key custody; the long-lived account key is a runtime-injected secret, never committed.
- **Considered**: account key in Postgres alongside leaf certs (rejected — mixes a long-lived custody secret into the hot leaf store); env/file secret (rejected — weaker custody and rotation).
- **Isolation**: OpenBao Transit, injected by key at runtime; leaf certs/keys remain in Postgres.

## Risks / Trade-offs

- **Net-new onboarding rate is CA-governed** → ARI exempts renewals; request the per-account override before bulk import; multi-account/issuer-fallback deferred behind certmagic's issuer-list seam (D4).
- **Thundering herd on a brand-new domain across the fleet** → shared-store distributed lock single-flights issuance (D3, `certificate-store-durability`).
- **On-demand issuance is an abuse vector** → the `ask` gate is mandatory and negative-caches refusals so unknown-hostname floods cannot exhaust budget (D6, `certificate-issuance-authorization`).
- **Hot set exceeds node memory at extreme scale** → SNI-shard seam (D7); until then per-node LRU + on-demand load from store.
- **Extra hop Caddy → Envoy adds latency** → accepted for launch; option #2 (SDS bridge) removes it later behind the store seam (D2).
- **Scope-boundary shift: the platform now terminates customer-domain TLS** → a deliberate refinement of the earlier "never terminates TLS" boundary, scoped to customer BYO domains; identity-edge behavior is unchanged. Update the `nexus-scope-boundary` note.
- **Overlaps `platform-ha-and-hardening`** → the shared-store HA and edge-fleet capacity concerns are coordinated with that change rather than duplicated.

## Migration Plan

1. Stand up the Postgres cert-store schema (certmagic `Storage` adapter) and the `ask` endpoint over the existing matcher.
2. Deploy the Caddy front tier alongside the current edge; on-demand + `ask` + ECDSA + ARI enabled; account key in OpenBao.
3. Validate with a handful of real customer domains (issue, serve, kill-issuer-still-serves, renewal).
4. Request the LE per-account new-order override before onboarding volume.
5. Cut customer-domain DNS to the front tier. **Rollback:** point DNS back and remove the front tier; the identity edge and stored certs are untouched.

## Open Questions

- Realistic **new-domains-per-day** onboarding rate — sets whether one LE account suffices or multi-account sharding is needed sooner (drives D4).
  - **CA budget & override path (task 1.2, confirmed).** Let's Encrypt's governed quantity is *net-new orders*: the default is **~300 new orders / account / 3 hours** (≈ **2,400 / day**), while **renewals ride the ARI exemption** (automatic on Caddy 2.8+) and do *not* consume that budget. A per-account increase is requested via Let's Encrypt's **Rate Limit Adjustment / Override form** (<https://letsencrypt.org/docs/rate-limits/> → "Overrides"), citing expected new-domains/day; record the granted number here once approved. Until it is, throttle DNS-cutover rate or bring up the deferred second issuer (D4). The concrete onboarding-rate number remains open pending product's launch plan. See `docs/runbook-custom-domains-tls.md` §4.
- Expected **hot-set fraction** — decides how early D7's SNI-shard seam is exercised.
- Whether option #2 (Envoy-terminates via SDS bridge) is worth building in v1 to avoid the extra hop, or strictly deferred.
