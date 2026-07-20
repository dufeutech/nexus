# Design — Helm front-tier TLS (closing infra finding N12)

## Context

`custom-domains-tls` delivered the customer-domain TLS front tier as a **Caddy** service that lives
only in the compose deployment (`deploy/caddy/` + `deploy/compose/docker-compose.yaml:333-363`).
The Helm chart (`deploy/helm/edge-platform`, an umbrella over `routing-plane` + `identity-plane`)
ships **no front tier at all** — no `:443` listener, no Caddy workload, no certificate-store wiring.
The go-live runbook tells operators to point customer DNS at a `:443` entry point a Helm install
never creates; infra's live L4 SNI router is held waiting for it. This is finding **N12**
(`docs/infra-findings.md:143-196`).

Two hard blockers, both confirmed against the tree:

1. **The `ask` gate has no in-cluster address.** `tenant-router` serves `/authorize` on `:9300`
   (`routing-rs/tenant-router/src/api.rs:53`, `main.rs:227`). In the umbrella it exists as a
   `containerPort` used only for the readiness probe (`edge-deployment.yaml:77-83`); it is
   **deliberately** kept off every Service (`edge-service.yaml:13-14`, "…the router debug + metrics
   ports are deliberately NOT here"). A front tier in its own pod cannot reach it over loopback.
2. **No PROXY-protocol acceptance anywhere.** The edge Envoy listener declares **no
   `listener_filters`** (`edge-configmap.yaml:48-50`); no Caddyfile configures `listener_wrappers`
   (grep finds the string only in `docs/infra-findings.md`, i.e. it's a proposal, not code).

What already exists and is reused, not rebuilt: the env-driven `Caddyfile` explicitly written to
serve compose **and** Helm from one file (`deploy/caddy/Caddyfile:11`); the ConfigMap-glob mount
pattern (`identity-policy-configmap.yaml:18`, `.Files.Glob`); the CertMagic Postgres schema
(`routing-rs/store-postgres/migrations/0001_certmagic_store.sql`) in the same `routing` DB the chart
already wires; the `existingSecret`/`existingSecretKey` convention; and pod-hardening defaults
(`runAsNonRoot`, `runAsUser: 10001`, `readOnlyRootFilesystem: true`).

## Goals / Non-Goals

**Goals:**
- A Helm install renders the customer-domain TLS front tier: a `:443` (and `:80`) workload that
  terminates TLS on demand and forwards cleartext to the existing edge with the original `Host`.
- The `ask`/authorize gate is reachable by the front tier within the cluster, without weakening the
  deliberate local-only posture of the edge's debug/admin/metrics ports.
- Optional PROXY-protocol acceptance at the front tier's `:443` and (opt-in, default off) at the
  edge Envoy listener, so an L4 SNI router preserves the real client IP.
- The shared, durable certificate store and ACME account material are wired from k8s config/secrets,
  reusing the compose store — one behavior contract, two deployment targets.

**Non-Goals:**
- No change to the on-demand-issuance behavior, the ask predicate, or the store schema — those are
  owned by `custom-domains-tls` and carried over verbatim. This change is packaging + reachability.
- Not the first-party `*.example.com` ingress path (nginx + cert-manager); that stays as-is.
- Not the shared-store HA decision itself — coordinated with `platform-ha-and-hardening`, not
  re-decided here.
- No fork of the `Caddyfile`: it stays a single env-driven file mounted into both deployments.

## Decisions

Most critical concerns (ACME automation, renewal, rate-limit handling, the durable cert store) were
already resolved **Adopt** by `custom-domains-tls` (Caddy + CertMagic + `postgres-storage`). This
change carries those forward and only decides **packaging + topology**. Items marked → `/opsx:decide`
are the genuinely new choices to confirm at the gate.

- **D1 — Front tier as a separate Deployment + Service in the umbrella, not a sidecar.** Independent
  `:443` lifecycle and scaling; the edge `:10000` stays up alongside for parallel-run/rollback
  (mirrors `docker-compose.yaml:331-332`). Put it directly in `edge-platform/templates` (not a
  subchart) so no `.tgz` re-vendor (`helm dependency update`) is needed. *Alt rejected:* sidecar in
  the edge pod — couples lifecycles, blocks independent scale and the rollback path.
- **D2 — Mount the existing `Caddyfile` verbatim via the `.Files.Glob` → ConfigMap pattern.** The
  file is already the single source of truth for both deployments; config is data, kept in its
  native format and loaded through a ConfigMap adapter — never inlined. Adopt/carry-over.
- **D3 — Expose the ask gate via a dedicated ClusterIP Service** selecting the edge pod,
  `targetPort: 9300`, distinct from the public data-plane Service; a `NetworkPolicy` admits only the
  front-tier pod → edge `:9300`. Keeps the deliberate local-only posture of admin/metrics intact
  while giving the front tier a stable address (`/opsx:decide` **approved** — Rent the k8s Service
  primitive). *Alt rejected:* add `:9300` to the data-plane Service — broadens exposure beyond need
  and breaks the stated posture.
- **D4 — Certificate store: reuse the `routing` Postgres + committed CertMagic schema via a new
  DML-only role**, wired as `CADDY_STORAGE_PG_URL` behind `existingSecret`/`existingSecretKey`. The
  DDL is nexus-owned, so Caddy runs `disable_ddl true`. Connection MUST be session/direct (CertMagic
  locks) — never a transaction-mode pooler. HA coordinated with `platform-ha-and-hardening`. Adopt.
- **D5 — ACME account key via the chart's `existingSecret` convention, delivery out-of-band**
  (`/opsx:decide` **approved**). The chart exposes `acmeAccount.existingSecret`/`existingSecretKey`
  and stays delivery-agnostic — exactly how `identity-plane/templates/signing.yaml:49-53` delivers
  the Transit-backed signing token (populated out-of-band via a Kubernetes-auth role; operators may
  use ESO / the OpenBao Secrets Operator / a Vault-agent, none of which the chart hard-depends on).
  The Secret mounts into an `emptyDir{medium: Memory}` at the `ACME_ACCOUNT_KEY_FILE` path, which
  also reconciles `readOnlyRootFilesystem` (plus the Caddy data/config dirs). This removes the
  unimplemented boot-time seed entrypoint (`deploy/caddy/README.md:78-82`) from the critical path.
  *Corrects an earlier draft that leaned toward bundling ESO into the chart — the repo convention
  argues against a hard ESO dependency.*
- **D6 — PROXY protocol via native features, opt-in, default off.** Front tier: add
  `servers.listener_wrappers: [{proxy_protocol}, {tls}]` to the Caddyfile global options behind an
  env/flag. Edge: add a `proxy_protocol` listener filter to the Envoy listener behind a values
  toggle. Both are mature native features — hand-rolling PROXY parsing would be a defect. Default off
  preserves today's direct-connection reads; an enabled listener rejects un-framed connections rather
  than mis-parsing (per `edge-client-ip-preservation`). (`/opsx:decide` **approved** — Adopt native.)
- **D7 — Image pinning follows the chart's existing tag-only convention.** `_helpers.tpl:169-172`
  builds `repo:tag` with **no `@sha256` support**; the front-tier image uses `global.image.tag` /
  a per-image `tag` like every other component. (Corrects an earlier "re-pin digests" assumption —
  this chart does not pin digests.)
- **D8 — Pin `Host` preservation explicitly in the `Caddyfile`** rather than leaning on Caddy's
  implicit `reverse_proxy` default, so the spec's Host-preservation contract is durable and
  test-visible. A one-line edit to the shared adopt source.

### Build-vs-adopt gate (`/opsx:decide`) — recorded decisions

Carry-over adopts from `custom-domains-tls` (on-demand TLS/ACME/renewal → Caddy + CertMagic; durable
cert store → CertMagic `postgres-storage`) are reaffirmed, not re-litigated here.

#### Decision: Client-IP preservation (PROXY protocol) — Adopt native (Caddy `proxy_protocol` wrapper + Envoy `proxy_protocol` listener filter)

- **Status**: approved
- **Why**: PROXY-header parsing feeds auth/rate-limit/trust decisions; both components already ship
  the feature natively (Envoy's descriptor is vendored), so hand-writing a parser would be a
  security-critical build the gate exists to prevent.
- **Considered**: Build a PROXY v1/v2 header parser — rejected (high blast radius, no upside over the
  native filters).
- **Isolation**: Off by default behind a `values.yaml` toggle (edge) and a Caddyfile env/flag (front
  tier); an enabled listener rejects un-framed connections rather than mis-parsing.

#### Decision: ACME account-key delivery — Extend the chart's `existingSecret` convention (delivery out-of-band)

- **Status**: approved
- **Why**: Matches how the platform already delivers the Transit-backed signing token
  (`identity-plane/templates/signing.yaml:49-53`) — the chart references a Secret and stays agnostic
  to how it is populated; no hard operator dependency, and it takes the unimplemented seed entrypoint
  off the critical path.
- **Considered**: Adopt External Secrets Operator in-chart (rejected — adds an ESO CRD dependency the
  rest of the platform does not take); Build a `bao read` seed entrypoint (rejected — bespoke code on
  the start path for a long-lived key, unimplemented even in compose).
- **Isolation**: `acmeAccount.existingSecret`/`existingSecretKey` values; Secret mounted into an
  `emptyDir{medium: Memory}` at `ACME_ACCOUNT_KEY_FILE`. Operators may back it with ESO / the OpenBao
  Secrets Operator / a Vault-agent / a K8s-auth role — none of which the chart requires.

#### Decision: Ask-gate in-cluster reachability — Rent the native k8s `Service` primitive

- **Status**: approved
- **Why**: A dedicated ClusterIP `Service` (+ `NetworkPolicy`) is the platform-native way to give the
  front-tier pod a stable address for the edge's `:9300` authorize endpoint without publishing it on
  the data-plane Service; no third-party tool involved.
- **Considered**: Add `:9300` to the public data-plane Service — rejected (breaks the deliberate
  local-only posture of admin/debug/metrics ports).
- **Isolation**: A separate `Service` object + a `NetworkPolicy` admitting only front-tier → edge
  `:9300`; the front tier reaches it via `AUTHORIZE_URL`.

## Risks / Trade-offs

- **[ACME account-key seed is unimplemented, even in compose]** → resolved by D5: the key is
  pre-materialized into an `existingSecret` out-of-band and mounted as a file, so no bespoke seed
  entrypoint is on the critical path. Still validate Caddy boots and registers/loads the account in a
  lab before any real cutover.
- **[`readOnlyRootFilesystem` vs Caddy's writable dirs]** → mount in-memory `emptyDir` for the key
  path and Caddy data/config; a chart test must assert the pod boots under the hardened SecurityContext.
- **[PROXY-protocol mismatch]** → if a listener expects the header but the fronting router doesn't
  send it (or vice-versa), handshakes break. Keep default off; enable front tier and infra router in
  lockstep; rely on the spec's "reject un-framed on an enabled listener" behavior.
- **[Postgres connection mode]** → a transaction-mode pooler silently breaks CertMagic locks and
  single-flighting. Document and default the store URL to a session/direct connection.
- **[Change ordering]** → this change packages the `custom-domains-tls` specs; it MUST land after
  that change syncs to `openspec/specs/`. Note the dependency at apply/sync time.

## Migration Plan

1. Render and deploy the front tier alongside the existing edge in a lab (edge `:10000` stays up).
   Run the `custom-domains-tls` spec verifications end-to-end against the Helm-rendered tier.
2. Enable PROXY protocol on the front tier and point infra's L4 SNI router at `:443` for a small set
   of real customer domains.
3. **Rollback:** DNS/router back to the prior entry point and remove the front tier — the edge never
   went down (parallel run). Mirrors the `custom-domains-tls` §5.3 DNS-cutover runbook.

## Open Questions

- ~~**ACME account-key delivery (D5):**~~ Resolved at `/opsx:decide` — Extend the `existingSecret`
  convention; delivery is out-of-band and not the chart's concern.
- ~~**Front-tier `:80`:**~~ Resolved at apply — publish both `:80` and `:443` (matches compose;
  keeps HTTP-01 / redirect available).
- ~~**Placement:**~~ Resolved at apply — umbrella `edge-platform/templates` (no subchart, no re-vendor).

## Implementation notes (apply-time refinements)

Three details the design under-specified, settled during `/opsx:apply`; the decisions above stand,
these refine *how*:

- **D2 mechanism — `tpl (.Files.Get …)`, not `.Files.Glob.AsConfig`.** Glob renders a file verbatim
  and cannot gate the opt-in PROXY `listener_wrappers` block; `tpl` lets one Helm conditional control
  it while Caddy `{$ENV}` / `{host}` tokens pass through. Consequence: the Caddyfile is **vendored**
  (`edge-platform/files/caddy/Caddyfile`) rather than truly un-forked — Helm's `.Files` can't read
  outside the chart. The copy diverges from `deploy/caddy/Caddyfile` only by the one guarded block;
  this dual-copy mirrors the existing Cedar policy set (present in both `deploy/compose/policy/` and
  `edge-platform/files/policy/`).
- **Front-tier SecurityContext adds `NET_BIND_SERVICE`.** The tier binds `:443`/`:80` (privileged),
  so — unlike the combined edge which drops ALL capabilities — it keeps `drop: [ALL]` but adds
  `NET_BIND_SERVICE`, staying non-root + `readOnlyRootFilesystem`. Exposed as `frontTier.securityContext`.
- **Ask NetworkPolicy (D3) is opt-in and additive-safe.** A naive ingress policy on the edge pods
  would default-deny the data plane; the shipped policy re-permits `:10000`/`:9210` from any source
  and narrows only `:9300` to the front tier, gated by `frontTier.askNetworkPolicy.enabled`
  (default off, like `originEnforcement.networkPolicy`).
