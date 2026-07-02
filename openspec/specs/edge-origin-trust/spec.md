# edge-origin-trust

## Purpose

Names the deployment invariant the entire trusted-header model rests on: a tenant
backend consuming the edge-emitted identity/routing header family is reachable
ONLY through the edge that emits it. The network path — not any header value —
is the control that makes the trusted-header family unforgeable in practice.

## Requirements

### Requirement: Identity-enriched backends accept requests only via the edge

A conformant deployment SHALL ensure that a tenant backend consuming the
`x-workspace-*`/`x-user-*`/`x-identity-contract` header family is reachable only through
the edge that emits them. There SHALL be no network path by which a party other than the
edge can deliver a request bearing those headers to the backend. This origin enforcement —
not any header value — is the control that makes the trusted-header family unforgeable in
practice. The complementary contract — that the `x-identity-contract` stamp is a
version/drift-coordination signal and MUST NOT be treated as an authentication or anti-bypass
boundary — is owned by the `identity-workspace-authz` capability and is not restated here.

#### Scenario: A direct-to-backend request is refused

- **WHEN** a party other than the edge attempts to connect to an identity-enriched backend
  directly, bearing a self-set `x-identity-contract` and `x-workspace-id`/`x-user-*`
- **THEN** the connection SHALL be refused by the deployment's origin control before the
  request reaches application logic, regardless of the header values presented

#### Scenario: Origin enforcement is an explicit, verifiable part of the deployment

- **WHEN** a deployment topology that runs identity enrichment is assembled
- **THEN** it SHALL include an explicit, inspectable control (e.g. a network policy or
  equivalent) that restricts backend ingress to the edge, and the absence of that control
  SHALL be treated as a misconfiguration, not a default-safe state
