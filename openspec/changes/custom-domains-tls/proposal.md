## Why

Customers point their own domains ("bring-your-own-domain") at the platform, and every such
domain needs a valid public TLS certificate that is obtained, served, and renewed automatically —
without an operator touching each one. The domain set is tenant-driven and unbounded: it must work
at whatever scale it grows to (thousands today, potentially hundreds of thousands or more) with no
architectural rewrite between those points. Certificate issuance is security- and reliability-
critical, so the platform adopts a mature automation component rather than hand-rolling the ACME
protocol, rate-limit handling, and renewal scheduling.

## What Changes

- Introduce a TLS-terminating front tier for customer domains that obtains a certificate **on
  demand** — on first need for an authorized hostname — and serves it, without the domain being
  pre-provisioned in any static list.
- Add an **issuance authorization gate**: a certificate is obtained only for a hostname that the
  platform approves, reusing the single shared host matcher owned by `domain-host-resolution`; every
  other hostname is refused, and refusals are remembered so a flood of unknown hostnames cannot
  drive unbounded issuance attempts.
- Add a **fleet-shared, durable certificate store** so any edge node can serve any customer
  domain, issuance is single-flighted across the fleet (no thundering-herd storm against the CA),
  and live traffic keeps being served from the store even while the issuing component is unavailable.
- Renew certificates ahead of expiry automatically, in a way that does **not** consume net-new
  issuance rate-limit budget, so steady-state renewal of a large cert population never throttles.
- Keep per-node memory bounded to the **working set** of currently-hot domains rather than the
  total registered-domain count, so the total population can grow far beyond what any single node
  holds in memory.
- This front tier terminates TLS and forwards to the existing identity/authz edge; it does **not**
  change identity enrichment, the auth gate, or tenant-resolution behavior.

## Capabilities

### New Capabilities

- `on-demand-certificate-lifecycle`: The observable contract for a customer domain's certificate
  over its life — obtained on first need, served for live TLS, renewed ahead of expiry without
  exhausting issuance budget, and continuing to serve existing certificates through an issuer
  outage. Critical concern (reliability/security): the ACME automation itself is a **build-vs-adopt**
  decision deferred to `/opsx:decide`.
- `certificate-issuance-authorization`: The gate deciding *whether* a hostname may receive a
  certificate at all — approve only hostnames the platform authorizes (via the shared matcher owned
  by `domain-host-resolution`), refuse everything else, and remember refusals so unknown-hostname
  floods cannot cause unbounded issuance. Critical concern (security/abuse-resistance).
- `certificate-store-durability`: The fleet-wide persistence and coordination contract — any node
  serves any domain from a shared store, issuance for a given hostname is single-flighted across the
  fleet, stored certificates survive the loss of any single node, and per-node memory is bounded to
  the working set. Critical concern (reliability): the store backend is a **build-vs-adopt** decision
  deferred to `/opsx:decide`.

### Modified Capabilities

<!-- None. `domain-host-resolution` already requires that routing and on-demand certificate
     authorization share one host matcher; this change consumes that contract without changing its
     requirements. -->

## Impact

- **New surface:** a TLS-terminating front tier for customer domains, fronting the existing edge.
- **Depends on** `domain-host-resolution` (shared host matcher; issuance authorization must resolve
  the identical host set as routing) — consumed, not modified.
- **Adjacent, unchanged:** `edge-auth-gate`, `edge-origin-trust`, `edge-trust-anchor-integrity`,
  identity enrichment — the front tier terminates TLS and forwards; it does not alter their behavior.
- **New dependencies (deferred to `/opsx:decide`):** an ACME automation component, a public CA/ACME
  provider relationship (including rate-limit posture), and a shared certificate store backend.
- **Scope note:** this establishes that the platform terminates customer-domain TLS at its own front
  tier — a refinement of the earlier "never terminates TLS" boundary, now scoped to customer BYO
  domains.
