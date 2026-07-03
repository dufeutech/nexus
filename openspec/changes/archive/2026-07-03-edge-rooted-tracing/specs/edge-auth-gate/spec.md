# edge-auth-gate — delta spec

## MODIFIED Requirements

### Requirement: The trusted header family is unforgeable by clients

The edge SHALL strip every client-supplied trusted header before its authoritative
value is produced by a trusted stage, so a client cannot self-assert any of them.
This family includes the per-route auth signals (`x-auth-required`,
`x-auth-requires-role`, `x-auth-requires-entitlement`, `x-auth-min-aal`), the
acting-scope headers (`x-workspace-id`, and any `x-requested-workspace` hint is
treated as non-authoritative), the identity headers (`x-user-*`, including
`x-user-type` and `x-user-role`), the identity-contract stamp
(`x-identity-contract`), and the trace-context headers (`traceparent`,
`tracestate`), which only the edge may originate on the internal network. A client
MAY hint a desired workspace but SHALL NOT be able to assert the authoritative
scope, the contract version, any per-route policy signal, or trace context.

#### Scenario: Client-supplied auth signal is discarded
- **WHEN** an inbound request carries a client-set `x-auth-required` header
- **THEN** the edge SHALL remove it before the tenant-routing stage emits the
  authoritative value, and the client value SHALL have no effect on the gate

#### Scenario: Client-supplied requirement signal is discarded
- **WHEN** an inbound request carries a client-set `x-auth-requires-role`,
  `x-auth-requires-entitlement`, or `x-auth-min-aal` header
- **THEN** the edge SHALL remove it before the tenant-routing stage emits the
  authoritative values, so a client can neither add nor suppress a requirement

#### Scenario: Client-supplied acting-scope is discarded
- **WHEN** an inbound request carries a client-set `x-workspace-id`, `x-user-type`,
  `x-user-role`, or other `x-user-*` header
- **THEN** the edge SHALL remove it before the identity plane resolves membership,
  and only the nexus-produced authoritative values SHALL reach the backend

#### Scenario: Client-supplied contract stamp is discarded
- **WHEN** an inbound request carries a client-set `x-identity-contract` header
- **THEN** the edge SHALL remove it before the identity plane stamps the authoritative
  version, so a client can neither forge a contract version nor mask a bypass of the
  edge enrichment

#### Scenario: Client-supplied trace context is discarded
- **WHEN** an inbound request carries a client-set `traceparent` or `tracestate`
  header
- **THEN** the edge SHALL remove it before any trusted stage or backend observes it,
  so a backend that continues an arriving trace is always continuing an edge-rooted
  trace, never a client-controlled one
