# Infra integration findings (from `infra-v1`)

Findings surfaced while integrating the nexus edge platform into the `infra-v1` fleet
(k3s / ArgoCD / OpenBao). Each is something infra hit that is **nexus-side** to resolve.
Numbering continues the `N` series (N1–N10 are prior integration findings).

---

## N11 — the `edge-platform` umbrella's COMBINED edge does not wire contract signing

**Status:** open · **Found:** 2026-07-15, rendering `edge-platform` `0.2.0` (chart @ `f42554f`,
appVersion `0.0.7`) · **Severity:** blocks a **signed** go-live via the umbrella.

### What

The umbrella's **combined** edge (`deploy/helm/edge-platform/templates/edge-deployment.yaml`)
co-locates the identity sidecar, but that container is **not** given any signing configuration:

- **No** `SIGNING_TRANSIT_KEY` / `SIGNING_TRANSIT_MOUNT` / `BAO_TOKEN` env.
- **No** `JWKS_LISTEN` env and **no** `:9210` container port (its ports are only
  `id-ext-proc:50051`, `id-profile:9200`, `id-metrics:9202`).
- `edge-platform/values.yaml` has **no** signing block.

Contract signing (`SIGNING_TRANSIT_*`, `BAO_TOKEN`, `JWKS_LISTEN`, the `:9210` jwks port) is wired
**only** in the identity-plane **standalone** edge
(`deploy/helm/identity-plane/templates/edge-deployment.yaml`, ~lines 75–112, gated on
`sidecar.signing.enabled`) — which the umbrella **disables** (`identity-plane.edge.enabled: false`)
to run its single combined edge. Setting `identity-plane.sidecar.signing.*` on the umbrella therefore
renders **nothing** on the combined edge.

### Why it matters

Deploying via the umbrella (the documented production topology — one combined tenant-first edge)
brings the planes up **UNSIGNED**: no `x-identity-contract` ES256 signature and no JWKS served on
`:9210`. That contradicts:

- `docs/box-signing-handoff.md` (boxes verify a signed contract and fetch the JWKS at
  `http://<identity-plane-host>:9210/.well-known/jwks.json`), and
- the go-live checklist's "verify JWKS + a signed contract" step.

On the infra side this blocks consuming the OpenBao **Transit** signing custody that has already been
provisioned for it (the `identity-contract-signing` key, a least-privilege policy, and a
Kubernetes-auth role are ready) — there is simply nowhere on the combined edge to feed the token.

### Evidence (reproduce)

```
helm template edge deploy/helm/edge-platform \
  --set identity-plane.sidecar.signing.enabled=true \
  --set identity-plane.sidecar.signing.transit.enabled=true \
  --set identity-plane.sidecar.signing.transit.tokenExistingSecret=identity-plane-bao-token
# -> the combined-edge identity-sidecar container has NO SIGNING_TRANSIT_*/BAO_TOKEN env
#    and NO :9210 port. Grep the rendered output for SIGNING_TRANSIT / 9210 -> empty.
```

### Suggested fix (nexus-side)

Wire the identity-plane signing config into the **combined**-edge identity-sidecar in
`edge-platform/templates/edge-deployment.yaml`, driven by `identity-plane.sidecar.signing.*`
(or a dedicated `edge.signing` passthrough on the umbrella):

- add `JWKS_LISTEN`, `SIGNING_TRANSIT_KEY`, `SIGNING_TRANSIT_MOUNT` env and the `BAO_TOKEN`
  `secretKeyRef` (from `transit.tokenExistingSecret`), plus the `pollSeconds` / `maxClockSkewSeconds`
  the standalone edge passes;
- expose the `:9210` (`jwks`) container port on the combined-edge pod + its Service;
- ensure the break-glass path (`signing.yaml`'s Secret/ConfigMap for `existingSecret` / `jwks`) is
  mounted/consumed by the combined edge as well.

After the fix, the `helm template` above should render `SIGNING_TRANSIT_*` env + a `:9210` port on
the combined-edge sidecar.

_Raised by infra-v1 (change `edge-platform-deploy`). Infra's overlay already carries the intended
signing config; it is inert until this is wired._
