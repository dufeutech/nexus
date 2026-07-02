# TODO — production readiness

Open items to take the **docker-compose** deploy (`deploy/compose/`) from "correct
baseline" to "hardened production". The Helm path (`deploy/helm/`) already covers
most of the hardening via Kubernetes; these are the compose-specific gaps.

Status legend: `[ ]` open · `[~]` partial · `[x]` done

---

## 0. Bug — must fix (stack won't start as-is)

- [ ] **Healthchecks call `wget`, which isn't in the runtime images.** The images
      are `debian:bookworm-slim` with only the binary copied in (no `wget`/`curl`).
      A compose `healthcheck` runs _inside_ the container, so it needs an in-image
      HTTP client. Result today: `tenant-router` / `identity-sidecar` never report
      `healthy` → Envoy's `depends_on: service_healthy` never fires → the stack
      never comes up. - Fix: add a minimal HTTP client to the Dockerfile runtime stages
      (`identity-rs/Dockerfile`, `routing-rs/Dockerfile`), **or** switch the
      checks to a TCP-style probe that needs no client. - (Helm is unaffected: the kubelet runs its HTTP probes externally.)

## 1. Blocker for public exposure

- [ ] **No TLS at the edge.** The edge publishes plaintext `:10000`. The trust
      model treats the edge as the trust boundary, so plaintext leaks bearer
      tokens. Either: - put a TLS-terminating LB / reverse proxy in front (document it as a hard
      requirement), **or** - add a TLS-terminating reverse-proxy service to the stack (e.g. Caddy /
      Envoy TLS) terminating north–south and forwarding to `envoy:10000`.

## 2. Hardening (Helm has it, compose doesn't)

- [ ] **Resource limits** — set `mem_limit` / `cpus` per service. The sidecar's
      working-set cache can grow unbounded per container otherwise.
- [ ] **Log rotation** — the default `json-file` driver grows without bound on a
      long-running host. Set a `logging:` block (`max-size`, `max-file`) per
      service (or globally).
- [ ] **Container hardening** — the Rust images run as **root** with a writable
      rootfs and full caps. The Helm charts run them non-root + read-only rootfs +
      `cap_drop: [ALL]` (the images support it). Mirror in compose:
      `user`, `read_only: true`, `tmpfs: /tmp`, `cap_drop: [ALL]`,
      `security_opt: ["no-new-privileges:true"]`.
- [ ] **Healthchecks for all five services** — currently only the two hot-path
      planes have them (and those are the broken ones). Add for `control-plane`
      (`:9400/healthz`), `sync-worker` (`:8080/healthz`), `reconciler`
      (`:9000` metrics/tcp). Depends on item 0 (need an in-image client).
- [ ] **Pin images** — `ENVOY_VERSION=v1.34-latest` is a rolling tag; the
      first-party images default to `0.1.0`. Pin Envoy to a concrete patch and the
      first-party images to a digest or immutable tag for reproducible deploys.

## 3. Foot-guns to document / guard

- [ ] **`deploy/compose/envoy/envoy.yaml` ships with placeholders** —
      `auth.example.com`, `*-backend.example.com`, and the hardcoded JWKS issuer
      `https://auth.example.com` MUST be edited before first run. Make this loud in
      the README (and/or fail fast if left as the example value).

## 4. Inherent to compose — accept or move to Helm

These are limitations of single-host compose, not fixable in the file:

- **No HA / no autoscaling / no rolling deploys.** One of each service on one host;
  host dies → everything down. The `sync-worker` is single-owner by design, but the
  edge / router / sidecar being single instances is a compose limitation.
- For HA + zero-downtime, use the **Helm/Kubernetes** path
  (`deploy/helm/edge-platform`) or run multiple compose hosts behind an external LB.

---

## Verdict (2026-06-20)

Architecture is sound (external state, fail-closed ext_proc, unforgeable headers,
secrets mounted, control-plane on loopback). But as a production artifact the
compose stack is **not ready**: startup-breaking healthcheck bug (item 0), no TLS
(item 1), and no resource/log/container hardening (item 2).

- **OK now:** single-node internal/staging deploy _after_ fixing items 0 + 1.
- **Not OK:** HA public production — use the Helm path.
