## 1. Edge image pinning (D3)

- [x] 1.1 Resolve `v1.34-latest` to its concrete patch + digest (`v1.34.14@sha256:cfc0678…`)
- [x] 1.2 Pin both compose defaults (`docker-compose.yaml`, `deploy/compose/docker-compose.yaml`)
- [x] 1.3 Pin both env files (`.env`, `deploy/compose/.env.example`) with a re-resolution note
- [x] 1.4 Pin both Helm values (`identity-plane`, `routing-plane`); confirm umbrella inherits
- [x] 1.5 Verify: compose `config` resolves to the pinned digest; no floating tag remains outside comments
- [x] 1.6 Update the deploy checklist item that claimed Envoy still floats

## 2. Edge config reconciliation (D4)

- [x] 2.1 Add the missing phase-2 removes (`x-auth-requires-*`, `x-auth-min-aal`) to the compose edge
- [x] 2.2 Verify both edges strip an identical set (`diff` of sorted `remove:` lists is empty)
- [x] 2.3 Record the sync `diff` as a maintained invariant in the consumer-contract doc

## 3. Consumer contract + front-door docs

- [x] 3.1 Write `docs/box-consumer-contract.md` (complete header table, origin-trust, reject rules, telemetry)
- [x] 3.2 Cross-link it from `nexus-upstream-requirements.md`
- [x] 3.3 Add a copy-pasteable CNI-enforcement probe to `deploy/README.md`
- [x] 3.4 Write the top-level `README.md` (system, planes, deploy paths, doc index, status)

## 4. Load/capacity harness (edge-load-capacity spec, D1/D2)

- [x] 4.1 External generator scenario file `scripts/load/edge-load.js` (3 cost paths, open-model, thresholds)
- [x] 4.2 Thin POSIX launcher `scripts/load/run-load.sh` (preflight, warm-up, env params, exit-coded)
- [x] 4.3 `scripts/load/README.md` (usage, knobs, caveats — placeholder SLOs, run off-box)
- [x] 4.4 Verify: JS parses, launcher `sh -n` clean, launcher is executable

## 5. Record the build-vs-adopt decision (D1)

- [x] 5.1 Run `/opsx:decide` and record the load-generator Adopt decision (k6) against the alternatives in design D1

## 6. Latent hardening verification (D5)

- [x] 6.1 Grep the Rust sources (`temp_dir`, `NamedTempFile`, `/tmp`, on-disk writes) for the read-only-rootfs containers lacking a writable `/tmp` (control-plane, sidecar, tenant-router) — result: zero writes; only `fs::read_to_string` of a secret file (a read) exists, in sync-worker/reconciler which already mount `/tmp`
- [x] 6.2 None write to `/tmp` → finding recorded in design D5; **no chart change made** (adding mounts would be unjustified churn)
- [x] 6.3 N/A — no chart change was made, nothing to re-render

## 7. Close out

- [x] 7.1 `/opsx:sync` — fold the `edge-load-capacity` delta spec into the main specs
- [x] 7.2 `/opsx:archive` — archive the change once 5/6 are complete
