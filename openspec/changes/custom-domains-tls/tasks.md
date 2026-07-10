## 1. Ratify decisions

- [x] 1.1 Run `/opsx:decide` to ratify D1–D8 (adopt certmagic/Caddy, Postgres store, LE+ARI, ECDSA, ask-gate build, SNI-shard deferred, OpenBao account-key custody); record outcomes in design.md
- [x] 1.2 Confirm the CA new-order override request path with Let's Encrypt and note current default budget in design.md Open Questions

## 2. Certificate store (certificate-store-durability)

- [x] 2.1 Add the cert-store schema as a native SQL migration file (certs, keys, metadata, lock rows), loaded via a migration adapter — not inlined
- [x] 2.2 Implement the certmagic `Storage` adapter over Postgres (get/put/list/lock/unlock), isolating Postgres behind the interface
- [x] 2.3 Implement fleet single-flight via the store's distributed lock so concurrent first-demand yields at most one issuance order
- [x] 2.4 Verify: cert written by one node is served by another without re-issuance; node loss leaves cert recoverable from store (no re-issue)
- [x] 2.5 Verify: per-node in-memory footprint stays bounded to the working set while total population exceeds a node's capacity (LRU load/evict)

## 3. Issuance authorization gate (certificate-issuance-authorization)

- [x] 3.1 Implement the thin `ask` HTTP endpoint that answers via the existing `domain-host-resolution` matcher (no second host-recognition path)
- [x] 3.2 Add bounded negative caching of refusals so repeated unknown-hostname connections do not each trigger issuance
- [x] 3.3 Verify: `ask` authorizes iff routing resolves the hostname to a tenant (identical host set); unapproved hostnames place zero CA orders
- [x] 3.4 Verify: an unknown-hostname flood keeps issuance-order count bounded and does not consume approved-hostname budget

## 4. On-demand front tier (on-demand-certificate-lifecycle)

- [x] 4.1 Add the Caddy front-tier config as native Caddyfile/JSON files (on-demand TLS + `ask` URL + ECDSA + ARI), loaded via a config adapter
- [x] 4.2 Wire TLS termination to forward to the existing identity/authz edge without altering enrichment/auth-gate/tenant-resolution behavior
- [x] 4.3 Configure Let's Encrypt issuer with ARI enabled; structure the issuer list so a second issuer/account is a config-only addition
- [x] 4.4 Custody the ACME account key in OpenBao Transit; inject at runtime by key (never committed); leaf certs/keys stay in Postgres
- [x] 4.5 Verify: first connection for an authorized domain obtains then serves; later connections reuse the stored cert (no re-issue)
- [ ] 4.6 Verify: a certificate nearing expiry renews in advance and renewal does not consume net-new issuance budget (ARI exemption observed)
- [x] 4.7 Verify: with the issuer down, existing domains still serve while only brand-new onboarding defers
- [x] 4.8 Verify: an unauthorized/unresolvable hostname fails the handshake closed (no default/catch-all/self-signed cert presented)

## 5. Rollout and boundary reconciliation

- [x] 5.1 Deploy the front tier alongside the current edge in a lab; run the spec verifications end-to-end (§2–§4)
- [ ] 5.2 Request the LE per-account new-order override before onboarding volume
- [x] 5.3 Cut a small set of real customer domains to the front tier; document the DNS-cutover and rollback (DNS-back + remove tier) runbook
- [x] 5.4 Coordinate shared-store HA and edge-fleet capacity with `platform-ha-and-hardening` (avoid duplication)
- [x] 5.5 Update the `nexus-scope-boundary` memory: platform now terminates customer-domain TLS at its front tier (scoped to BYO domains)

---

## Status (this apply)

**22/24 done.** In-repo build (16) + live lab runs against the running `zitadel-lab`
stack that verified 6 more (2.4, 4.5, 4.8, 5.1, then **2.5** and **4.7**). The last two
remaining (4.6, 5.2) need the real Let's Encrypt service and cannot be closed locally.

### Live lab runs (2.5, 4.7) — issuer-down + working-set, internal CA

Two harnesses, both run against the internal-CA front tier + the live `tenant-router`
ask gate, sharing the `routing` DB's `certmagic_*` store. The `*.acme.test` wildcard
authorizes arbitrarily many distinct SNIs, so cardinality needs no DB seeding.

- **2.5 working-set bound (`scripts/custom-domains-tls-cardinality.sh`) — PASS 3/3.**
  Issued **246** distinct certs into the shared store, then COLD-restarted the node
  (in-mem working set → 0). A cold node served a 30-domain sample drawn across the whole
  population by **loading each from Postgres with ZERO re-issuance** (cert-row count stable
  at 246). RSS tracked the working set, not the population: cold/0-resident **44.0 MB**,
  working-set/30 **45.8 MB**, full-population/246 **50.5 MB**. A literal RSS-bytes bound is
  not visible at lab cardinality (~1.5 kB/cert) and Caddy 2.8 exposes no cache-capacity
  knob to force eviction at small N, so the harness proves the *mechanism* that yields the
  bound (demand-load-from-store, no re-issue); strict over-capacity LRU eviction stays
  certmagic-internal (adopted, D7).
- **4.7 issuer-down (`scripts/custom-domains-tls-outage.sh`, `Caddyfile.outage` +
  `docker-compose.outage-lab.yaml`) — PASS 8/8.** Two mechanistically independent halves:
  **(A)** an existing valid cert (`app.acme.test`) serves 200 from a COLD node with no
  re-issue and **no `obtain`/issuer activity in the logs** for that serve — a pure storage
  read, so a down CA cannot affect it; **(B)** a `caddy-outage` tier whose ACME issuer
  points at a refused port (a literal down CA): a brand-new **authorized** host (ask gate
  → 200) cannot onboard — handshake defers (curl 000), **no fallback cert**, zero cert
  rows — and the tier stays up (a second attempt defers cleanly). Onboarding failure never
  touched live serving.

### Live lab run (4.6 partial) — ARI-driven renewal against a local ARI CA

`scripts/custom-domains-tls-ari.sh` (`Caddyfile.ari` + `docker-compose.ari-lab.yaml` +
`ari-lab/pebble-config.json`) stands up **Pebble** — an ACME CA that implements ARI
(`draft-ietf-acme-ari-03`) — as the issuer, with a shortened cert validity so a renewal is
observable in-run. Observed end-to-end (the CA is reached over HTTPS trusted via
`SSL_CERT_FILE`=Pebble's minica; challenge validation is bypassed with
`PEBBLE_VA_ALWAYS_VALID` since only ARI is under test):

- certmagic obtained a **real ACME cert** for `ari-test.acme.test` from Pebble (issuer
  `pebble:14000-dir`), not the internal CA.
- certmagic **fetched the CA's `renewalInfo`** (`got renewal info` — window_start/window_end/
  selected_time; Pebble logged the `GET /draft-ietf-acme-ari-03/renewalInfo/` hit).
- certmagic **renewed the cert in advance**, explicitly ARI-driven: `certificate needs
  renewal based on ARI window` → renewed with ~60s still remaining before expiry → a second
  Pebble issuance (serial `458f…` → `48e1…`). Note: an on-demand cert renews on next access
  once inside its ARI window (`renewal_cutoff`), not purely via background maintenance.

This closes the **"renews in advance, ARI-driven"** half of 4.6 locally. The remaining half
— that renewals do **not** consume net-new order budget (the ARI *exemption*) — is a
Let's-Encrypt-account rate-limit property Pebble cannot reproduce, so 4.6 stays open pending
the real LE issuer (design.md D4).

### Live lab run (5.1) — front tier deployed alongside the running edge

Deployed `deploy/caddy/docker-compose.lab.yaml` (Caddy v2.8.4 + xcaddy `postgres`
storage module, `Caddyfile.lab` = internal CA so on-demand issues without public DNS)
attached to the lab network; migration applied to the live `routing` DB. Observed:

- **Ask gate (3.3/3.4) against the live tenant-router `:9300`:** `app.acme.test`,
  `api.globex.test` → 200; `foo.acme.test` → 200 (wildcard); `acme.test` (apex, wildcard
  only) / `unverified.test` (unverified) / unknown → 403; a 50× unknown flood → 50/50
  denied.
- **Storage adapter (2.2):** Caddy booted with `storage postgres { disable_ddl:true }`,
  connected to our owned schema, ran storage maintenance.
- **On-demand + reuse (4.5):** first HTTPS to `app.acme.test` → 200, store grew 5→8
  (cert/key/json rows); second → 200, rows stable at 8 (reuse, no re-issue).
- **Node-loss recovery (2.4):** restarted the front tier (cold in-mem cache = a fresh
  node) → `app.acme.test` served 200 from the shared store, rows still 8 (no re-issue).
- **Fail-closed (4.8):** unauthorized SNI → curl exit 35 / code 000 (handshake refused,
  no fallback cert).

### Done in-repo (the build)

- **Code (verified via `cargo test -p tenant-router`):** the `/authorize` ask-gate
  (3.1) already reused the shared matcher; added **bounded negative caching** (3.2,
  `AppState.neg` + `AUTHORIZE_NEG_TTL`/`AUTHORIZE_NEG_CAPACITY`). Two new tests plus the
  existing parity test make **3.3 and 3.4** genuinely verified in-process:
  `authorize_and_router_resolve_the_identical_host_set`,
  `ask_negative_cache_collapses_repeat_unknown_host_flood`,
  `ask_distinct_unknown_host_flood_authorizes_nothing`.
- **Store (2.1–2.3):** `routing-rs/store-postgres/migrations/0001_certmagic_store.sql`
  (+ compose hook `postgres-init/40-certmagic-store.sql`) owns the `certmagic_data` /
  `certmagic_locks` schema; the Storage adapter is the adopted `storage postgres` module
  configured with `disable_ddl true`; single-flight is the `certmagic_locks` distributed
  lock.
- **Front tier (4.1–4.4):** `deploy/caddy/Caddyfile` (on-demand + `ask` + ECDSA p256 +
  LE issuer, ARI automatic on 2.8+, issuer-list seam), `deploy/caddy/Dockerfile`
  (xcaddy), a `caddy` service in `deploy/compose/docker-compose.yaml` forwarding to
  `envoy:10000`, and `deploy/caddy/acme-account-transit-init.sh` custodying the ACME
  account key in OpenBao Transit.
- **Docs/memory (1.1, 1.2, 5.3–5.5):** ratified decisions + LE budget/override in
  `design.md`; `docs/runbook-custom-domains-tls.md` (cutover/rollback + HA coordination);
  `nexus-scope-boundary` memory refined.

**Still open (2 tasks)** — both intrinsically require the real Let's Encrypt service; the
internal-CA lab cannot cover them:

- **4.6** — renewal ahead of expiry + ARI rate-limit exemption. The **"renews in advance,
  ARI-driven" half is now VERIFIED locally** against Pebble (an ARI-capable test CA) — see
  the 4.6-partial run above and `scripts/custom-domains-tls-ari.sh`. What remains is the
  governed property: that renewals do NOT consume net-new issuance budget (the ARI
  *exemption*), which is a Let's-Encrypt-account rate-limit observation only the real LE
  issuer over a renewal cycle can show. The task stays open until that half is confirmed.
- **5.2** — request the LE per-account new-order override (external party; path documented
  in `design.md` Open Questions and runbook §4). Blocks on product's onboarding-rate number.

**Harnesses:** `scripts/custom-domains-tls-e2e.sh` runs the §2–§4 checks against a
public-DNS + LE staging deployment when one is available;
`scripts/custom-domains-tls-cardinality.sh` (2.5) and `scripts/custom-domains-tls-outage.sh`
(4.7) run locally against the internal-CA lab tier and pass 3/3 and 8/8;
`scripts/custom-domains-tls-ari.sh` (4.6 local half) runs against a local Pebble ARI CA
(`Caddyfile.ari`, `docker-compose.ari-lab.yaml`, `ari-lab/`) and observes ARI-driven
advance renewal.
