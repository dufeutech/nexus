## Why

The customer-domain TLS front tier (on-demand HTTPS for bring-your-own domains) ships
**only in the compose deployment** — `deploy/helm/` contains no front tier at all. The go-live
runbook instructs operators to point customer DNS at a `:443` listener, but a Helm install never
creates one, so the behavior promised by `custom-domains-tls` is undeliverable on the platform's
own k8s packaging. Infra's L4 SNI router is live and pre-positioned; the `:443` cutover is held
until nexus provides a front tier in Helm to point it at. This is infra finding **N12**.

## What Changes

- **Package the TLS-terminating front tier into the Helm chart** so a Helm install renders the
  same on-demand-HTTPS behavior the compose deployment already provides: a front-tier workload
  bound to `:443` with its config supplied as data (not baked into an image), on-demand issuance
  driven by the platform's authorization gate, and cleartext forwarding to the existing edge with
  the original `Host` preserved.
- **Make the issuance-authorization gate reachable within the k8s deployment.** The front tier's
  on-demand issuance consults `tenant-router`'s authorize endpoint (`:9300`), which the edge
  Service **deliberately** does not expose. This change exposes that endpoint so the gate is
  reachable by the serving tier — without which the feature is not implementable in k8s at all.
- **Preserve the real client IP through a fronting L4 router.** Add PROXY-protocol acceptance at
  the front tier's `:443`, and — as an independent, cheap win — expose a PROXY-protocol / listener-
  filter passthrough on the edge Envoy listener, so an L4 SNI router can front either tier without
  the platform losing the true client source address.
- **Wire the shared, durable certificate store and ACME account material from k8s-native config**
  (referenced secrets and config, not committed values), reusing the store the compose tier uses so
  any edge node serves any customer domain. Shared-store HA is coordinated with
  `platform-ha-and-hardening` to avoid duplicating that decision.

## Capabilities

### New Capabilities
- `deployment-front-tier-parity`: The platform's packaged k8s deployment provides the customer-domain
  TLS front tier, and the issuance-authorization gate the front tier depends on is reachable by the
  serving tier within the deployment boundary. A deployment package that terminates customer-domain
  TLS but cannot reach its own issuance gate is a defect.
- `edge-client-ip-preservation`: When the platform is fronted by an L4 router that speaks PROXY
  protocol, the real client source address is preserved end-to-end rather than replaced by the
  router's address — at the customer-domain front tier and, optionally, at the edge listener.

### Modified Capabilities
<!-- None in the synced main specs. The TLS behaviors this change packages are defined by the
     in-flight `custom-domains-tls` specs (certificate-issuance-authorization,
     certificate-store-durability, on-demand-certificate-lifecycle), which are not yet synced to
     openspec/specs/. This change realizes those contracts in a second deployment target; it does
     not alter their requirements. It must land after `custom-domains-tls` syncs. -->

## Impact

- **Deployment / packaging (primary):** `deploy/helm/edge-platform` (or the appropriate subchart) —
  new front-tier Deployment + Service on `:443`, a ConfigMap for the front-tier config, and Secret
  references for ACME account material; a Service (or Service port) exposing the authorize endpoint;
  `values.yaml` toggles/wiring following existing chart conventions; digest re-pinning where the
  umbrella vendors subcharts.
- **Edge listener:** the edge Envoy ConfigMap gains an opt-in PROXY-protocol / `listener_filters`
  passthrough (currently declares none).
- **Adopt source:** `deploy/caddy/` (the existing compose front tier + its README) is the reference
  implementation being ported — an adopt/extend, not a rebuild. The on-demand TLS component and the
  certificate store are existing choices carried over, recorded via `/opsx:decide`.
- **Config & secrets:** the shared certificate store (`certmagic_data` / `certmagic_locks`) and
  `ACME_ACCOUNT_KEY_FILE` are supplied from k8s config/secrets rather than committed values.
- **Coordination:** shared-store HA with `platform-ha-and-hardening`; unblocks infra's held `:443`
  cutover; closes N12 in `docs/infra-findings.md`.
