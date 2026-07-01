# edge-auth-gate

## Purpose

The per-route authentication contract enforced at the combined production edge:
how the edge decides, per request, whether a verified credential is required,
optional, or the request is rejected — driven by the tenant's per-route policy
signal and fail-safe under signal loss. The mechanism is the Envoy `jwt_authn`
filter branching on the `x-auth-required` header emitted by the tenant-routing
stage; this spec is language-agnostic and states only the observable behavior.

## Requirements

### Requirement: Per-route authentication is driven by the tenant policy signal

The edge SHALL determine each request's authentication requirement from the
`x-auth-required` header emitted by the tenant-routing stage (derived from the
tenant's per-route `auth_routes` policy), not from a blanket per-domain rule. A
route MUST be able to be public (anonymous allowed) and another route on the same
domain MUST be able to require a verified credential.

#### Scenario: Route marked protected requires a credential
- **WHEN** the tenant policy resolves the request path to `auth_required = true`
  (signal `x-auth-required: "true"`) and the request carries no credential
- **THEN** the edge SHALL reject the request as unauthenticated (401)

#### Scenario: Route marked public allows anonymous
- **WHEN** the tenant policy resolves the request path to `auth_required = false`
  (signal `x-auth-required: "false"`) and the request carries no credential
- **THEN** the edge SHALL allow the request to proceed as anonymous

#### Scenario: Zero-config tenant is public by default
- **WHEN** a tenant has configured no `auth_routes` rule matching the request path
- **THEN** the tenant policy SHALL resolve to pass-through (`auth_required = false`)
  and the edge SHALL allow the request to proceed as anonymous

### Requirement: An invalid credential is always rejected, even on public routes

The edge SHALL reject a request that presents a malformed, expired, or otherwise
invalid credential, regardless of whether the route is public or protected. Only a
genuinely absent credential is permitted on a public route.

#### Scenario: Invalid token on a public route
- **WHEN** a route resolves to public (`x-auth-required: "false"`) and the request
  presents an invalid/expired bearer token
- **THEN** the edge SHALL reject the request (401) rather than treat it as anonymous

### Requirement: The gate is fail-safe under a missing signal

The edge SHALL treat the **absence** of the `x-auth-required` signal as
"credential required" (fail-closed), not as "public". An explicit
`x-auth-required: "false"` is the only condition that opens a route to anonymous
access.

#### Scenario: Signal absent falls through to required
- **WHEN** a request reaches the credential-verification stage with no
  `x-auth-required` header present
- **THEN** the edge SHALL require a verified credential (reject if absent/invalid)

### Requirement: The authentication signal is unforgeable by clients

The edge SHALL strip any client-supplied `x-auth-required` header before the value
is produced by the trusted tenant-routing stage, so a client cannot self-assert a
route as public or protected.

#### Scenario: Client-supplied signal is discarded
- **WHEN** an inbound request carries a client-set `x-auth-required` header
- **THEN** the edge SHALL remove it before the tenant-routing stage emits the
  authoritative value, and the client value SHALL have no effect on the gate
