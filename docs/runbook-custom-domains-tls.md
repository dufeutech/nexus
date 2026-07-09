# Runbook — customer-domain TLS front tier (custom-domains-tls)

The Caddy/CertMagic front tier terminates TLS for tenant **bring-your-own-domains**,
obtains certificates **on demand** (gated by the tenant-router `/authorize` predicate),
stores them in the **shared Postgres** cert store, and forwards cleartext to the Envoy
edge. See `deploy/caddy/README.md` for build/config and the change
`openspec/changes/custom-domains-tls/` for the design.

The governing invariant: **certificate automation is a side tool** — an issuer outage
degrades only new-domain onboarding, never live traffic for already-provisioned domains.
Rollback is always DNS-back + remove the tier; the identity edge and stored certs are
untouched by it.

## 1. Onboard a customer domain (DNS cutover)

Preconditions:
- The domain is declared + **verified** in the routing store, so `/authorize` returns
  `200` for it (the front tier will refuse to issue otherwise — fail-closed by design).
- The LE per-account new-order override has been requested if onboarding volume is near
  the default budget (see §4).

Steps:
1. Confirm the gate authorizes the host:
   `curl -s -o /dev/null -w '%{http_code}' http://<edge-host>:9300/authorize?domain=<host>`
   → must be `200`. A `403` means the domain is not verified/routable — fix routing first.
2. Point the customer's DNS **A/AAAA/CNAME** at the front tier's public address (the
   caddy `:443` listener / its load balancer), NOT at Envoy directly.
3. First HTTPS request triggers on-demand issuance: the fleet single-flights the order
   via `certmagic_locks`, stores the cert in `certmagic_data`, and serves it. Subsequent
   requests reuse the stored cert on every node.
4. Verify: `scripts/custom-domains-tls-e2e.sh` (point `TLS_HOST` at the domain).

Start with a **small set** of real domains (migration plan step 5.3), watch issuance
metrics and the LE account rate-limit view, then widen.

## 2. Rollback (DNS-back + remove tier)

The front tier is additive — Envoy still listens on `:10000` alongside it during the
parallel-run. To roll a domain (or the whole tier) back:

1. **Point DNS back** to the prior target (Envoy / the previous LB). Traffic drains to
   the identity edge exactly as before the front tier existed.
2. Optionally scale the `caddy` front tier to zero / remove the service.

Nothing else changes: the identity edge, the routing store, and the stored certificates
are untouched. Because the cert store is the stable seam, re-introducing the tier later
re-adopts every stored cert with no re-issuance.

## 3. Issuer outage

If Let's Encrypt (or the network path to it) is down:
- **Existing domains keep serving** from `certmagic_data` — no action needed. Confirm on
  a provisioned host: HTTPS still returns `200`.
- **Only brand-new onboarding defers** — a first-ever handshake for a not-yet-issued
  host stalls/closes until the issuer returns. Hold new DNS cutovers until then.
- Adding a **fallback CA** (e.g. ZeroSSL) is a config-only second `cert_issuer` line
  (`deploy/caddy/Caddyfile`); it stays deferred until an outage justifies the EAB setup
  (design D4). Its ARI exemption is LE-specific and would not transfer.

## 4. Let's Encrypt new-order budget & override (tasks 1.2 / 5.2)

- The governed quantity is **net-new onboarding rate**, not total certs. LE's default
  is ~**300 new orders / account / 3 hours** (rolling), and renewals ride the **ARI
  exemption** (automatic on Caddy 2.8+), so steady-state renewal of a large population
  does **not** consume new-order budget.
- **Before bulk onboarding**, request a per-account **Rate Limit Adjustment** from Let's
  Encrypt via their rate-limit adjustment request form
  (<https://letsencrypt.org/docs/rate-limits/> → "Overrides"), citing the expected
  new-domains/day. Record the granted limit in the change's `design.md` Open Questions.
- If the override is not yet granted and volume approaches the cap, throttle DNS cutover
  rate (§1) or bring up the second issuer (§3) — do not remove the `ask` gate.

## 5. Shared-store HA & edge-fleet capacity (coordinate with `platform-ha-and-hardening`)

The cert store lives in the **same Postgres** as the routing store, and the front tier is
a **stateless** edge fleet ("any node serves any domain" over the shared store, design
D7). Both concerns are owned by the `platform-ha-and-hardening` change, not duplicated
here:
- **Postgres HA / backup** for the `routing` DB now also protects `certmagic_data` /
  `certmagic_locks` — losing it loses the cert store. Size backups/failover there.
- **Edge-fleet capacity**: per-node memory is bounded to the working set (LRU load/evict
  from the store), so scale is horizontal. If the hot set later exceeds a node, introduce
  **SNI-sharded L4 hashing** at the LB — a topology change, not an app change (D7).

Route `CADDY_STORAGE_PG_URL` to the primary on a **direct/session** connection (CertMagic
uses locks; a txn-mode pooler breaks them), consistent with the `ROUTING_PG_URL` caveat.
