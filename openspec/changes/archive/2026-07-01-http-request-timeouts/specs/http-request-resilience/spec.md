# http-request-resilience

The observable contract for bounding per-request time on the HTTP servers, so a
slow or stalled client cannot hold server resources indefinitely.

## ADDED Requirements

### Requirement: HTTP requests are bounded by a total timeout

Each HTTP (axum) server SHALL enforce a maximum total duration for handling a
request. When a request — including reading its body and running its handler —
exceeds the configured timeout, the server SHALL terminate it and respond with
`408 Request Timeout`, releasing the connection and its task.

#### Scenario: A slow request is terminated
- **WHEN** a client sends a request whose body or handler does not complete within
  the configured timeout
- **THEN** the server SHALL respond `408 Request Timeout` and free the associated
  connection/task, rather than remaining blocked indefinitely

#### Scenario: A normal request is unaffected
- **WHEN** a request completes within the configured timeout
- **THEN** the server SHALL respond normally, with no behavior change from the
  timeout

### Requirement: The timeout is operator-configurable with a safe default

Each server's request timeout SHALL be configurable by the operator and SHALL apply
a safe bounded default when unset (never "no timeout").

#### Scenario: Default applies when unconfigured
- **WHEN** the operator provides no timeout configuration
- **THEN** the server SHALL apply a finite default timeout, not run unbounded

### Requirement: Long-lived streaming RPCs are not force-timed-out

A per-request timeout SHALL NOT be applied to long-lived bidirectional streaming
RPCs (the identity/routing `ext_proc` gRPC streams), because a single stream stays
open for the lifetime of a trusted downstream connection; terminating it on a fixed
per-RPC deadline would sever healthy traffic.

#### Scenario: An ext_proc stream survives past the HTTP timeout
- **WHEN** a trusted Envoy holds an `ext_proc` gRPC stream open longer than the HTTP
  servers' request timeout
- **THEN** the stream SHALL remain open and continue processing messages
