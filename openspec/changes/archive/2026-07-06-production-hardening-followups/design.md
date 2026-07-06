## Context

The CI e2e release gate certifies edge **correctness** but not **capacity**, the edge ran on a
mutable image tag, the lab and compose edge configs had drifted in their header-strip lists,
and the consumer-facing contract + a front-door README were missing. This change closes those
operator-facing gaps. Most of it is ops/config/docs; the one part with a real engineering
decision is the capacity validation, which depends on a load generator whose measurement
correctness is load-bearing (see Decisions). All edits are scoped to config, docs, and an
operator-side script — no product code, API, store, or schema changes.

## Goals / Non-Goals

**Goals:**
- An operator can measure edge throughput + tail latency and gate it against explicit SLOs.
- The edge image is reproducible (patch version + immutable digest) on every deploy path.
- Both edge configs strip an identical, verifiable trusted-header set.
- A box author has one complete document of the header + telemetry contract; a newcomer has a
  front-door README.
- Record the build-vs-adopt decision the capacity harness entails.

**Non-Goals:**
- Wiring capacity validation into the per-change CI gate (it belongs in a scheduled/perf job).
- Measuring *backend* capacity (the lab echo backend is trivial by design).
- Changing any spec-level behavior of edge-origin-trust / edge-auth-gate / box-telemetry
  (the strip reconciliation and consumer doc are implementation/documentation of existing
  requirements, not new behavior).
- Load-testing from inside a service image (the generator runs from an operator host).

## Decisions

### Decision: load-generation & tail-latency measurement — Adopt k6

- **Status**: approved (`/opsx:decide`, 2026-07-06)
- **Why**: capacity numbers are trustworthy only if the load model avoids coordinated omission
  and the percentiles are correct — a correctness-critical concern (Rent > **Adopt** > Extend
  > Fork > Build). k6 is the only evaluated option that *natively* provides the two things the
  `edge-load-capacity` spec requires: an open-model constant-arrival-rate executor **and** a
  pass/fail SLO gate via `thresholds` (non-zero exit, code 99, on breach), plus the three cost
  paths scripted in a single run. AGPLv3, but run as a standalone operator subprocess (not
  linked, not redistributed) — not a license reject.
- **Considered**: `vegeta` (MIT, avoids coordinated omission, but no native SLO exit gate and
  no multi-scenario — needs external threshold logic + aggregation); `oha` (MIT, coordinated-
  omission correction + TUI, but single-shot: no SLO gate, no scripted scenarios); hand-rolled
  `sh` loop (rejected — hand-computing percentiles and an open-model scheduler in shell is the
  exact footgun this gate exists to prevent).
- **Isolation**: k6 enters only through the harness (D2) — the external generator-native
  scenario file `scripts/load/edge-load.js` and the thin POSIX launcher `run-load.sh`. The
  `edge-load-capacity` spec stays vendor-agnostic; no k6 reference leaks into `specs/` or
  `config.yaml`. Swapping generators is a harness-local change.

### D2 — Harness = thin launcher (adapter) + external scenario file (data-not-code)

The scenario definition (paths, thresholds, executors) lives in an external generator-native
script (`scripts/load/edge-load.js`), not inlined as strings in shell. A thin POSIX launcher
(`scripts/load/run-load.sh`) is the adapter: it does preflight (tool present, target
reachable), warm-up, parameter passing (all via env), and delegates to the generator — no
measurement logic of its own. All tunables (target, offered rate, duration, SLOs, route
overrides) are env inputs with documented placeholder defaults, keeping a single source of
truth for each value.

### D3 — Pin the edge image to patch version + digest

Pin Envoy to `v1.34.14@sha256:cfc0678…` (the immutable identity `v1.34-latest` resolved to on
2026-07-06) everywhere it is referenced: both compose defaults, both `.env`s, both Helm
`values.yaml` (the umbrella inherits via the routing-plane subchart). The tag is kept for
human readability; the digest is the reproducibility guarantee. Re-resolution command is
documented in each location and the deploy checklist. Rationale: a rolling tag makes deploys
non-reproducible and silently re-pulls unverified image content.

### D4 — Reconcile the two edge configs to an identical strip set

`deploy/compose/envoy/envoy.yaml` gains the three phase-2 removes (`x-auth-requires-role`,
`x-auth-requires-entitlement`, `x-auth-min-aal`) it was missing, making both edges strip an
identical 39-entry set. This was defense-in-depth-covered by the sidecar's own strip already,
so it closes a consistency gap, not a live hole. A one-line `diff` check is documented as the
maintained invariant so future header changes update both files.

### D5 — Verify the `/tmp` item before changing anything

The Helm audit flagged read-only-rootfs containers without a writable `/tmp` as a *latent*
crash risk. Rather than blanket-add `emptyDir` mounts (cargo-cult hardening), first grep the
Rust sources for temp-file writes (`temp_dir`, `NamedTempFile`, `/tmp`, `std::io` to disk); add
an `emptyDir` mount **only** to containers whose binary actually writes there. If none write,
record that and make no chart change.

**Verification outcome (2026-07-06): no mount needed — no chart change made.** A repo-wide
grep for temp-file and filesystem-write patterns (`tempfile`/`NamedTempFile`/`TempDir`/
`temp_dir`, `/tmp`, `fs::write`/`File::create`/`OpenOptions`/`write_all`/`create_dir`, and
`tempfile`/unix-socket deps in every `Cargo.toml`) found **zero writes** in the three gap
containers (control-plane, identity-sidecar, tenant-router). control-plane has no `fs`/`File`
usage at all; tenant-router and sidecar matched only `.key`/`.keys()` false positives. The
only filesystem usage anywhere is `fs::read_to_string` in sync-worker and reconciler reading a
secret PAT file — a **read** (fine on read-only rootfs), and those two already mount their own
`/tmp`. So the latent risk does not materialize; adding `emptyDir` mounts would be unjustified
churn. If a container ever fails with a read-only-filesystem write error in future, add the
mount to that container then.

## Risks / Trade-offs

- **Placeholder SLOs treated as real** → the harness prints them as placeholders and the docs
  state a capacity test without real targets is just a number; the exit code is only a gate
  once the operator sets thresholds.
- **Generator co-located with the edge skews the tail** → documented: run the generator
  off-box for real numbers.
- **Digest drift on version bump** → the re-resolution command is documented inline and in the
  deploy checklist; bumping the tag without re-resolving the digest is a documented step, and
  a stale digest fails the pull loudly rather than silently running the wrong image.
- **Adding an operator tool dependency (k6)** → operator-side only, not in any image; the
  launcher fails fast with install guidance when absent.
- **`/tmp` verification concludes a mount IS needed on a hot-path container** → an `emptyDir`
  is cheap and non-privileged; the risk is only unnecessary churn, avoided by D5's grep-first.
