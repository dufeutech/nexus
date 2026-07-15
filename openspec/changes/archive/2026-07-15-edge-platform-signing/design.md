## Context

Contract signing is fully implemented in the identity sidecar image and wired into the
**standalone** identity-plane edge (`identity-plane/templates/edge-deployment.yaml`, gated on
`sidecar.signing.enabled`): the signing env block, the public `:9210` JWKS port, and the
break-glass volumes. The **umbrella** (`edge-platform`) runs a *single combined edge* and disables
the subchart's standalone edge (`identity-plane.edge.enabled=false`), re-declaring the identity
sidecar in `edge-platform/templates/edge-deployment.yaml`. That re-declaration was written without
any signing wiring, so the two templates **drifted**: enabling signing on the umbrella renders
nothing. The subchart's `signing.yaml` still renders the break-glass Secret/ConfigMap and dev
bao-token in the umbrella (it gates on `sidecar.signing.enabled`, not `edge.enabled`), so those
resources already exist — they are simply orphaned. The only critical concern here — custody of the
signing key — was already decided as **Adopt OpenBao Transit** in `automate-signing-key-rotation`;
this change introduces no new external dependency and thus no new `/opsx:decide` entry.

## Goals / Non-Goals

**Goals:**
- Enabling `identity-plane.sidecar.signing.enabled` on the umbrella makes the combined edge mint
  signed contracts and publish its JWKS on `:9210`, identically to the standalone edge (Transit
  custody + break-glass fallback included).
- Structurally prevent the drift that caused N11 from recurring: the signing env is defined **once**
  and consumed by both edges.
- No image change; `appVersion` stays `0.0.7`.

**Non-Goals:**
- Changing any behavior of the signing itself (token shape, rotation, key custody) — unchanged.
- Touching the routing plane or the standalone edge's observable behavior.
- Making signing default-on — it stays opt-in; unsigned umbrella deploys are unaffected.

## Decisions

**D1 — Single-source the signing env via a shared named template (root fix for the drift).**
Extract the signing environment block into a named template `identity-plane.signingEnv` (in the
identity-plane subchart's `_helpers.tpl`), taking an explicit dict `{ signing, fullname }` so it is
independent of which chart's `.Values` is in scope. Both the standalone edge-deployment and the
umbrella edge-deployment `include` it. Helm compiles parent + subchart templates into one global
namespace, so the umbrella can include a subchart-defined template. _Alternative — copy-paste the
env block into the umbrella (as originally scoped): rejected, because it reinstates the exact
two-sources-of-truth drift that produced N11._

**D2 — Consume the subchart's already-rendered signing resources; render nothing new in the
umbrella.** The bao-token Secret, break-glass private-key Secret, and JWKS ConfigMap are already
produced by the identity-plane subchart under `<release>-identity-plane-*`. The combined edge
references them via the existing `edge-platform.identityFullname` helper (the same one
`edge-platform.identityPgSecret` already uses), honoring `tokenExistingSecret` / `existingSecret`
overrides first. _Alternative — re-render duplicate signing resources in the umbrella: rejected;
duplicates the same key material behind two owners._

**D3 — Expose `:9210` publicly on the combined-edge Service, gated on signing.** Mirror
`identity-plane/templates/edge-service.yaml`: the JWKS is public by design (boxes fetch it to
verify). The combined-edge pod names the port `id-jwks` (consistent with its `id-*` port naming);
the Service publishes it as `jwks`. Admin/profile/metrics stay unexposed, unchanged.

**D4 — Version + guard.** Bump `edge-platform` chart `version` 0.2.0 → 0.2.1 (template change;
`appVersion` unchanged). Add an assertion to the CI helm-guard matrix that rendering the umbrella
with `identity-plane.sidecar.signing.enabled=true` (+ transit) yields `SIGNING_TRANSIT_*` env and a
`9210` port on the combined edge — locking the spec invariant so the topology gap cannot silently
return.

## Risks / Trade-offs

- **Refactoring the already-correct standalone template (D1) could regress it** → the reference-stack
  e2e already boots the standalone edge with signing enabled and verifies a real signed JWS; the CI
  helm-render matrix renders both edges; the new D4 guard asserts both. A render/behavior regression
  fails CI before merge.
- **Cross-chart template coupling (umbrella includes a subchart-defined template)** → mitigated by
  passing an explicit dict (no reliance on ambient `.Values`); this coupling already exists via the
  shared image/fullname helpers.
- **Secret-name coupling across the subchart boundary (D2)** → uses the existing
  `edge-platform.identityFullname` helper already relied on for the PG secret, so naming stays in
  one place; explicit `tokenExistingSecret`/`existingSecret` overrides bypass it for production.
- **JWKS now publicly reachable on the combined edge (D3)** → this is the intended, required
  behavior (public verification material); it exposes no private key — the private key stays in the
  sidecar / OpenBao per the unchanged custody requirement.
