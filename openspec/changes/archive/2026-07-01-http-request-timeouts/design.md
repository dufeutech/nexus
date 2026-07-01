# Design — http-request-timeouts

## Context

Every axum server is `axum::serve(listener, router)` with only graceful shutdown —
no per-request timeout. A tower `Layer` on the router is the idiomatic place to add
one. The gRPC ext_proc servers are streaming and must be excluded (a per-RPC
deadline would kill healthy long-lived streams).

Servers in scope (unary HTTP):

| Service | Port(s) | External? |
|---|---|---|
| control-plane admin | `:9400` | broker-only |
| control-plane ops (metrics/health) | `:9401` | scrape/probe |
| tenant-router API (`/authorize`,`/resolve`) | `:9300` | **yes** (CA on-demand-TLS ask) |
| identity sidecar profile API | `:9200` | loopback |
| sync-worker webhook | `:8080` | **yes** (ZITADEL webhook) |

Out of scope: ext_proc gRPC (`:50051`, `:50052`) — streaming.

## Goals / Non-goals

- **Goal**: a slow/stalled HTTP request is terminated with `408` and its resources
  freed; default is finite (never unbounded).
- **Non-goal**: header-read (pre-routing) dribble in the hyper accept loop —
  configuring hyper's `http1_header_read_timeout` needs the lower-level serve API
  and is a separate follow-up (residual noted).
- **Non-goal**: touching the streaming ext_proc servers.

## Decisions

### Decision: request timeout — Adopt `tower-http` `TimeoutLayer`

- **Status**: approved
- **Why**: `tower_http::timeout::TimeoutLayer` is the mature, HTTP-aware standard —
  it returns a proper `408 Request Timeout` and composes as a plain tower `Layer`
  on the axum `Router` with zero handler changes. It is already in the axum/tower
  ecosystem the project uses.
- **Considered**: (a) `tower::timeout::TimeoutLayer` — lower-level, surfaces the
  elapsed as an error that axum renders `500`, not `408`; not HTTP-aware. (b)
  Hand-rolled `tokio::time::timeout` wrapper per handler — a build of a critical
  concern that a mature layer already covers; rejected. (c) hyper server-builder
  timeouts — complementary (header-read) but not a `Layer`; deferred as the residual
  above.
- **Isolation**: one `.layer(TimeoutLayer::new(dur))` on each axum router; the
  duration comes from a per-service env var (`HTTP_REQUEST_TIMEOUT_SECS`, default
  30s) resolved at startup. No handler or business-logic code changes.

## Notes

- Default 30s is a generous ceiling well above normal latency (control-plane already
  caps DB work at `statement_timeout=5s`; sidecar/tenant-router hot paths are
  sub-second). Operators can lower it per service.
- `tower-http` with only the `timeout` feature pulls `tower`/`http-body-util` etc.
  (all permissive-licensed) — validated by `cargo deny` in tasks.
