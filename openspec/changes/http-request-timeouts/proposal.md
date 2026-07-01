## Why

A tool-assisted DoS audit found that **no axum/HTTP server in the platform has a
per-request timeout** — only a Postgres `statement_timeout` (which bounds a query,
not a slow HTTP client). A client that dribbles a request body or stalls a handler
holds the connection and its task open indefinitely (Slowloris / slow-body). The
externally reachable surfaces — the tenant-router `/authorize` (on-demand-TLS ask,
`:9300`) and the sync-worker `/webhook` (`:8080`) — are the realistic vectors.

## What Changes

- Add a per-request total timeout to every **axum** server, returning `408 Request
  Timeout` when exceeded: control-plane admin (`:9400`) + ops (`:9401`),
  tenant-router (`:9300`), identity sidecar profile API (`:9200`), sync-worker
  (`:8080`).
- The timeout is operator-tunable via an env var per service, with a safe default.
- **Excluded (deliberately):** the two gRPC **ext_proc** servers (sidecar `:50051`,
  tenant-router `:50052`). Their RPC is a long-lived bidirectional stream (one per
  downstream Envoy connection); a per-RPC timeout would sever healthy streams. They
  are bounded instead by the trusted-Envoy client set and the existing
  `mpsc::channel(8)` backpressure — noted, not changed here.

## Capabilities

### New Capabilities
- `http-request-resilience` — the observable contract that an HTTP request which
  does not complete within a bounded time is terminated with a timeout response
  rather than holding server resources indefinitely.

### Modified Capabilities
- None.

## Impact

- **Reliability-critical, adds one dependency.** Introduces a request-timeout
  middleware to both Rust workspaces (`routing-rs`, `identity-rs`). The concrete
  library is a build-vs-adopt decision recorded in design.md (`/opsx:decide`).
- No behavior change for well-behaved clients under the timeout.
- Does not address the header-read (pre-routing) dribble in the accept loop — that
  is a lower-level server-builder concern, noted as a residual in design.md.
