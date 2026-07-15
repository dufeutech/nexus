## Why

The `edge-platform` umbrella is the documented production topology (one combined tenant-first
edge), yet enabling identity-contract signing on it has **no effect**: the combined edge's
identity sidecar is wired with none of the signing configuration, so a production umbrella deploy
serves enriched traffic **silently unsigned** — no `x-identity-contract` signature is minted and
no JWKS is published for boxes to verify against. Signing is wired only on the *standalone*
identity-plane edge, which the umbrella disables to run its single combined edge. This was raised
by infra as finding **N11** while integrating nexus 0.0.7, and it blocks a signed go-live (and the
OpenBao Transit custody already provisioned for it) through the supported topology.

## What Changes

- Enabling signing (`identity-plane.sidecar.signing.enabled`) on the `edge-platform` umbrella
  takes effect on the **combined** edge: the co-located identity sidecar mints signed contracts
  and publishes its JWKS, identically to the standalone identity-plane edge — including the
  OpenBao Transit custody path and the break-glass manual-PEM fallback.
- The combined edge publishes its verification JWKS on the same public `:9210` endpoint (on the
  pod and its Service) that consumers already expect, so boxes can fetch and verify.
- No behavior of the *signing itself* changes, and no images change — this closes a
  topology-dependent gap where an enabled configuration was silently dropped. Signing remains
  default-off; an existing unsigned umbrella deploy is unaffected until it opts in.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `identity-contract-signing`: add the requirement that an **enabled** signing configuration takes
  effect in **every** supported production edge topology — a deployment MUST NOT serve enriched
  traffic through an edge that omits the signature and JWKS when signing is enabled. Today the
  requirement set constrains *how* a contract is signed/published/rotated but never states that
  configuring signing must actually reach the edge that stamps the contract, which is precisely the
  gap the combined-edge topology fell through.

## Impact

- **Charts:** `deploy/helm/edge-platform/templates/edge-deployment.yaml` (combined-edge identity
  sidecar: signing env, `:9210` port, break-glass volumes) and
  `deploy/helm/edge-platform/templates/edge-service.yaml` (public `:9210` JWKS port). The
  subchart's `signing.yaml` already renders the break-glass Secret/ConfigMap and dev bao-token in
  the umbrella — they are currently orphaned and become consumed.
- **Versioning:** `edge-platform` chart `version` 0.2.0 → 0.2.1 (template change). `appVersion`
  stays `0.0.7` — images are unchanged (signing already ships in the sidecar image).
- **CI:** the helm-render / guard matrix already exercises the umbrella; extend it to assert the
  combined edge renders the signing env and `:9210` port when signing is enabled, so the topology
  gap cannot silently return.
- **Not affected:** the standalone identity-plane edge (already correct), the routing plane, and
  the signing implementation in the sidecar image.
