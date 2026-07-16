## Why

The 0.0.7 admin planes (`control-plane`, `authz-admin`) are fail-closed: they refuse to
start unless the deployment selects exactly one admin-auth posture — named tokens
(`ADMIN_TOKEN_PEPPER`), legacy shared token in migration mode
(`<CONTROL_AUTH_TOKEN|IDENTITY_ADMIN_TOKEN>` **plus** `ADMIN_LEGACY_TOKEN_OK=true`), or an
explicit dev opt-out (`*_AUTH_DISABLED=true`). The Helm charts only ever wire the legacy
token env (never the `_OK` flag) or the disabled flag, so **no startable production posture
exists**: both planes `CrashLoopBackOff` with `"missing admin auth configuration"`. This
blocks the `edge-platform` go-live (revenue path). The chart fell behind its own binary's
security contract; the deployment surface must be brought back into lockstep.

## What Changes

- Expose the **named-token (pepper)** posture as chart values on both admin surfaces and wire
  `ADMIN_TOKEN_PEPPER` into each Deployment (from an `existingSecret` — the prod path — or an
  inline dev value the chart wraps in a managed Secret, mirroring how the legacy token is
  handled today).
- Expose the **legacy migration** posture: a `legacyTokenOk` value that wires
  `ADMIN_LEGACY_TOKEN_OK=true` alongside the already-wired legacy token env.
- Add a **render-time fail-closed guard** to each chart that `fail`s at `helm template` unless
  exactly one valid posture is selected (disabled, pepper, or legacy+ok) — projecting the
  binary's startup contract onto the config surface so a misconfig is caught before a pod
  crash, including the binary's edge case (`legacyTokenOk` with no legacy token → refuse).
- Keep the existing value fields and the disabled posture **backward-compatible**; the new
  fields default to off, so no current install's behavior changes silently.
- Factor the posture selection + guard logic into a **single shared template partial** each
  chart consumes, so the precedence rule is authored once rather than hand-mirrored across two
  templates (the drift that caused this incident).
- Bump chart `version` on `identity-plane`, `routing-plane`, and the `edge-platform` umbrella
  (`appVersion` stays `0.0.7`; the umbrella is pure subchart passthrough — value-surface change
  only, no umbrella template change) and regenerate `edge-platform/Chart.lock`.

## Capabilities

### New Capabilities
<!-- none — the runtime behaviors already have specs; this change projects one onto the deployment surface -->

### Modified Capabilities
- `admin-plane-authorization`: add a requirement that the **deployment configuration surface**
  can express every admin-auth posture the plane supports (disabled / named-token / legacy
  migration) and is **fail-closed at configuration time** — a render that selects no valid
  posture, or an incomplete posture, is refused rather than producing a manifest that cannot
  start. This mirrors the existing runtime "Authorization is fail-closed" requirement onto the
  config layer.

## Impact

- **Charts:** `deploy/helm/identity-plane` (`values.yaml`, `templates/authz-admin.yaml`,
  `templates/secret-authz-admin.yaml`, `templates/_helpers.tpl`, `Chart.yaml`),
  `deploy/helm/routing-plane` (`values.yaml`, `templates/control-plane.yaml`,
  `templates/secret-control-auth.yaml`, `templates/_helpers.tpl`, `Chart.yaml`),
  `deploy/helm/edge-platform` (`Chart.yaml`, `Chart.lock`, `values.yaml` docs).
- **Binaries:** none — `control-plane` and `authz-admin` are unchanged (appVersion stays 0.0.7).
- **Downstream (infra):** unblocks `infra-v1` edge go-live; infra re-vendors the umbrella
  (`helm dependency update`), re-pins digests, and sets either `*.tokenPepper.existingSecret`
  (prod, OpenBao/ESO-seeded pepper) or `*.legacyTokenOk: true` (fastest-to-green migration).
- **Value-shape asymmetry:** the fix must slot into two different existing structures — identity's
  flat `authzAdmin.*` gated by `authDisabled`, and routing's nested `controlPlane.auth.*` gated by
  `auth.enabled` (inverted polarity) — behavior symmetric, wiring not copy-paste.
