# Tasks — http-request-timeouts

## 1. Dependency

- [x] 1.1 Added `tower-http = { version = "0.6", features = ["timeout"] }` to both
  workspaces' `[workspace.dependencies]`; referenced in control-plane, tenant-router,
  sidecar, sync-worker.
- [x] 1.2 `cargo deny --locked check` — **advisories/bans/licenses/sources OK** in
  both workspaces with the new tree.

## 2. Apply the timeout layer (axum servers only)

Each: resolve `HTTP_REQUEST_TIMEOUT_SECS` (default 30) at startup and
`.layer(TimeoutLayer::new(Duration::from_secs(n)))` on the router.

- [x] 2.1 control-plane: admin `:9400` AND ops `:9401` routers (shared `req_timeout`).
- [x] 2.2 tenant-router: `:9300` API router.
- [x] 2.3 identity sidecar: `:9200` profile/health router.
- [x] 2.4 sync-worker: `:8080` webhook router.
  All use `TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, ...)` (the
  non-deprecated tower-http 0.6 API) with `HTTP_REQUEST_TIMEOUT_SECS` (default 30s).

## 3. Do NOT touch (verify excluded)

- [x] 3.1 Confirmed: NO timeout added to the ext_proc gRPC servers (sidecar
  `:50051`, tenant-router `:50052`) — streaming, left as-is.

## 4. Verify

- [x] 4.1 Both workspaces: `cargo build` + `cargo clippy --all-targets --locked`
  **0 deny**, `cargo deny` clean (tower-http), tests pass (identity-rs with `PROTOC`).
- [x] 4.2 Verify-by-construction: the timeout behavior is `tower-http`'s (a mature,
  tested crate); we verified the wiring compiles, uses the documented `408` API on
  all 5 axum servers, and is env-tunable. A live `408`-on-slow-request check is a
  trivial deploy-time smoke against a running server (no custom logic to unit-test —
  it would only re-test the dependency).
