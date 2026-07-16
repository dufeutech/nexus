## 1. Gate decisions (run /opsx:decide first)

- [x] 1.1 Resolve D1 (additive fields vs `mode:` enum), D2 (shared partial placement), and D6
      (acceptance harness) at the build-vs-adopt gate; record each in design.md.
- [x] 1.2 Resolve the bootstrap open question for control-plane pepper mode enough to know whether
      routing can go live pepper-only or must start in legacy-migration.

## 2. Shared posture/guard partial (author once — D2)

- [x] 2.1 Write a named-template `define` that, given a plane's env-var names (token / disabled /
      pepper) and value paths, emits the correct auth env vars for the selected posture.
- [x] 2.2 In the same partial, implement the fail-closed guard: `fail` unless disabled OR pepper
      configured OR (`legacyTokenOk` AND legacy token present); also `fail` on `legacyTokenOk`
      with no legacy token. Message names the three postures, matching the binary's stderr.
- [x] 2.3 Place the partial per the D2 decision (shared file vs canonical-copied); ensure both
      charts consume the identical logic, not two hand-edited copies.

## 3. identity-plane (authz-admin)

- [x] 3.1 values.yaml: add `authzAdmin.tokenPepper.{existingSecret, existingSecretKey, value}` and
      `authzAdmin.legacyTokenOk: false`, with docs explaining the three postures and that a plain
      legacy token now requires `legacyTokenOk`.
- [x] 3.2 templates/authz-admin.yaml: replace the inline auth env block with the shared partial,
      passing `IDENTITY_ADMIN_TOKEN` / `IDENTITY_ADMIN_AUTH_DISABLED` / `ADMIN_TOKEN_PEPPER` and the
      `authDisabled` gate polarity.
- [x] 3.3 templates/secret-authz-admin.yaml + `_helpers.tpl`: extend the owns-secret helper to also
      manage an inline pepper Secret when `tokenPepper.value` is set (mirror the token handling).
- [x] 3.4 Chart.yaml: bump `version` per D5; add a changelog comment noting the new postures.

## 4. routing-plane (control-plane)

- [x] 4.1 values.yaml: add `controlPlane.auth.tokenPepper.{existingSecret, existingSecretKey, value}`
      and `controlPlane.auth.legacyTokenOk: false`, with the same posture docs.
- [x] 4.2 templates/control-plane.yaml: replace the inline auth env block with the shared partial,
      passing `CONTROL_AUTH_TOKEN` / `CONTROL_AUTH_DISABLED` / `ADMIN_TOKEN_PEPPER` and the
      `auth.enabled` gate polarity (inverted vs identity).
- [x] 4.3 templates/secret-control-auth.yaml + `_helpers.tpl`: extend the owns-secret helper to
      manage an inline pepper Secret when `tokenPepper.value` is set.
- [x] 4.4 Chart.yaml: bump `version` per D5; add a changelog comment.

## 5. edge-platform umbrella

- [x] 5.1 values.yaml: document the new `identity-plane.authzAdmin.*` and
      `routing-plane.controlPlane.auth.*` passthrough knobs (no template change — pure passthrough).
- [x] 5.2 Chart.yaml: bump umbrella `version` per D5.
- [x] 5.3 Regenerate `Chart.lock` via `helm dependency update`.

## 6. Acceptance (per D6)

- [x] 6.1 Assert `helm template` with `tokenPepper.existingSecret` renders `ADMIN_TOKEN_PEPPER`
      (from the Secret) and no legacy env — both planes.
- [x] 6.2 Assert `helm template` with `legacyTokenOk: true` + a legacy `existingSecret` renders the
      legacy token env AND `ADMIN_LEGACY_TOKEN_OK=true` — both planes.
- [x] 6.3 Assert `helm template` with disabled posture renders the `*_AUTH_DISABLED=true` env and no
      credential — both planes.
- [x] 6.4 Assert render `fail`s when no posture is selected, and when `legacyTokenOk` is set with no
      legacy token — both planes.
- [x] 6.5 Assert the umbrella passes each posture through to both subcharts (`helm template` on
      `edge-platform` with the passthrough values).
- [x] 6.6 Land the D6 acceptance check (script/fixtures) so the assertions are reproducible.

## 7. Verify & document

- [x] 7.1 Run the full acceptance set green; confirm `helm lint` passes on all three charts.
- [x] 7.2 Update ADMIN-AUTH-CHART-GAP.md status to resolved (or remove it — it was the scratch
      finding; the contract now lives in specs) and note the infra re-vendor handoff.
