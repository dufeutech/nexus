## 1. Single-source the signing env (D1)

- [x] 1.1 Define a named template `identity-plane.signingEnv` in `deploy/helm/identity-plane/templates/_helpers.tpl` that takes a dict `{ signing, fullname }` and emits the full signing env block (SIGNING_ISSUER, CONTRACT_TOKEN_TTL_SECONDS, JWKS_LISTEN; transit: SIGNING_TRANSIT_KEY, SIGNING_TRANSIT_MOUNT, BAO_ADDR, BAO_TOKEN via secretKeyRef defaulting to `<fullname>-bao-token`, SIGNING_KEY_POLL_SECONDS, CONTRACT_MAX_CLOCK_SKEW_SECONDS, optional SIGNING_ROTATION_PERIOD_SECONDS; break-glass: SIGNING_KEY_PATH, SIGNING_KID, JWKS_FILE), preserving the existing `required` guards.
- [x] 1.2 Replace the inline signing env in `deploy/helm/identity-plane/templates/edge-deployment.yaml` with an `include "identity-plane.signingEnv" (dict "signing" .Values.sidecar.signing "fullname" (include "identity-plane.fullname" .))`, keeping the `sidecar.signing.enabled` gate and the existing indentation.
- [x] 1.3 `helm template` the standalone identity-plane edge with signing enabled (transit + break-glass) and confirm the rendered env is byte-identical to pre-refactor output.

## 2. Wire the umbrella combined edge (D1–D3)

- [x] 2.1 In `deploy/helm/edge-platform/templates/edge-deployment.yaml`, gate on `$iv.sidecar.signing.enabled` and `include "identity-plane.signingEnv" (dict "signing" $iv.sidecar.signing "fullname" (include "edge-platform.identityFullname" .))` on the `identity-sidecar` container.
- [x] 2.2 Add the `{ name: id-jwks, containerPort: 9210 }` port to the `identity-sidecar` container, gated on `$iv.sidecar.signing.enabled`.
- [x] 2.3 Add the break-glass volumeMounts (`signing-key` → /etc/nexus/signing-key, `signing-jwks` → /etc/nexus/signing-jwks, readOnly) on the `identity-sidecar`, gated on `$iv.sidecar.signing.enabled` AND `$iv.sidecar.signing.kid`.
- [x] 2.4 Add the corresponding pod `volumes` referencing `<identityFullname>-signing-key` Secret (honoring `$iv.sidecar.signing.existingSecret`) and `<identityFullname>-signing-jwks` ConfigMap, same gate as 2.3.
- [x] 2.5 In `deploy/helm/edge-platform/templates/edge-service.yaml`, add the public `jwks` port (`port: 9210`, `targetPort: id-jwks`), gated on `$iv.sidecar.signing.enabled`, mirroring the standalone Service.

## 3. Version + guard (D4)

- [x] 3.1 Bump `deploy/helm/edge-platform/Chart.yaml` `version` 0.2.0 → 0.2.1 (leave `appVersion: "0.0.7"`); note the reason in the version comment.
- [x] 3.2 Add an assertion to `scripts/helm-guards-test.sh` that rendering `edge-platform` with `identity-plane.sidecar.signing.enabled=true` + transit (+ a `tokenExistingSecret`) yields `SIGNING_TRANSIT_` env and a `9210` port on the combined edge, and that the edge Service exposes port 9210.
- [x] 3.3 Add a negative assertion: with signing NOT enabled, the combined edge renders no `SIGNING_` env and no `9210` port (guards against always-on regressions).

## 4. Verify

- [x] 4.1 Run `bash scripts/helm-guards-test.sh` and the umbrella render steps from `.github/workflows/ci.yml` (helm-lint job) locally/CI; confirm all three `monitoring.delivery` modes still render.
- [x] 4.2 Render the umbrella with signing enabled and eyeball the combined-edge identity-sidecar: `SIGNING_TRANSIT_*` + `BAO_TOKEN` env present, `:9210` port present, break-glass volumes present when `kid` set; and the edge Service exposes `9210`.
- [x] 4.3 Confirm no diff to the routing plane or to the standalone identity-plane edge's rendered output (other than the env now coming from the shared template).
