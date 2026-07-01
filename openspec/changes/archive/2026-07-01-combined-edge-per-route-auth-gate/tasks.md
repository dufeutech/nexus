# Tasks — combined-edge per-route auth gate

> Config-only change. No Rust. Validate each edge with `helm template` /
> `envoy --mode validate` (or the repo's CI helm steps) after editing.

## 1. Combined edge — adopt the inverted per-route gate

- [x] 1.1 `deploy/compose/envoy/envoy.yaml`: replace the `jwt_authn` rule
  `prefix:/ → requires: zitadel` with the two-rule inverted gate
  (`x-auth-required=="false" → allow_missing`, then `prefix:/ → zitadel`).
- [x] 1.2 `deploy/helm/edge-platform/templates/edge-configmap.yaml`: same rules
  swap. Keep the values-templated issuer/JWKS.
- [x] 1.3 Reconciled `publicPaths`: kept as **enrichment-disable-only** (C10
  sidecar-outage degradation), explicitly decoupled from auth — auth is governed
  solely by the per-route gate (`x-auth-required`). Documented in `values.yaml`.

## 2. Backport to canonical

- [x] 2.1 `edge/envoy.yaml`: replace its `[true→verify, /→allow_missing]` rules with
  the inverted `[false→allow_missing, /→verify]` gate so canonical is fail-safe too.

## 3. Documentation truth-up

- [x] 3.1 Fixed the `x-auth-required` comments: compose + edge-platform now describe
  the actual inverted gate; identity-plane's comment now states it is NOT consumed
  there (no tenant-router) and is stripped as C3 hygiene only.
- [x] 3.2 Added operator note to edge-platform `NOTES.txt`: unconfigured tenants are
  **public by default**; protect via `auth_routes` (a `/` rule locks the whole site;
  specific prefixes carve out). References the control-plane auth-routes API. Also
  corrected the stale "missing/invalid token → 401" line to the per-route reality.

## 4. Verify

- [x] 4.1 `helm template` edge-platform renders the two-rule gate, false-rule first.
  All three configs (compose, canonical, **rendered** edge-platform) pass Envoy
  `--mode validate` (real schema, not just YAML parse) — jwt rules accepted.
- [x] 4.2 **DONE — real Envoy integration test** (docker `envoyproxy/envoy:v1.31.0`).
  Ran the actual production filter chain — C3 strip → tenant-router stand-in (Lua
  sets `x-auth-required` by path) → the shipped inverted `jwt_authn` rules →
  `direct_response 200` — with real RS256 verification via inline `local_jwks` (an
  RSA key + matching minted token; no ZITADEL needed). **11/11 assertions pass:**
  protected → 401 no-token / 200 valid / 401 expired / 401 garbage; public → 200
  anon / 200 valid / **401 invalid**; forged client `x-auth-required:false` on
  `/app` → 401 (strip wins); **absent signal → 401 (fail-CLOSED)**. Contrast run
  with canonical polarity (B) proved the same absent case returns **200 (fail-open)**
  — empirically confirming why the inverted catch-all (strategy C) is safer.
  Stubbed (each separately verified elsewhere): the router's policy resolution
  (`router-core::auth` unit tests) and the JWKS source (ZITADEL, prod-only). The
  security-critical logic under test — the inverted rules + strip interaction — is
  the real production config.
- [x] 4.3 Confirmed by inspection: `failureModeAllow:false` (verified in all values)
  + tenant-router always emits ⇒ the "absent signal" path is unreachable (ext_proc
  failure rejects before jwt_authn); and the inverted catch-all verifies if it ever
  were absent (fail-closed). Config structure validated by `--mode validate`.

## 5. Out of scope (do NOT do here)

- identity-plane per-route adoption / split-topology `x-auth-required` handoff
  (separate change — see design.md "Follow-up").
- N4 phase-2 (role/entitlement/AAL gate).
