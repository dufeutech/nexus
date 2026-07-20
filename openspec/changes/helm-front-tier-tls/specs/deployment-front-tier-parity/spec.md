## ADDED Requirements

### Requirement: Every supported deployment method provides the customer-domain TLS front tier

The platform's customer-domain TLS termination (on-demand HTTPS for bring-your-own domains) MUST be
provided by every supported deployment method, not just one. A deployment method that the platform
publishes as production-capable, yet which brings up no listener able to terminate TLS for customer
domains, is a defect: the documented cutover (pointing customer DNS at the platform's HTTPS entry
point) MUST succeed on any such method without an operator hand-building the tier.

#### Scenario: A production install exposes an HTTPS entry point for customer domains

- **WHEN** the platform is installed through any deployment method it documents as production-capable
- **THEN** the resulting deployment exposes a reachable HTTPS entry point that terminates TLS for
  authorized customer domains
- **AND** an operator following the DNS-cutover runbook can point a customer domain at that entry
  point and serve it over HTTPS without adding any component the platform did not ship

#### Scenario: The front tier serves through to the existing edge

- **WHEN** a request for an authorized customer domain reaches the front tier over HTTPS
- **THEN** the front tier terminates TLS and forwards the request in cleartext to the platform's
  existing edge, preserving the original request host
- **AND** the response is returned to the client over the terminated TLS connection

### Requirement: The issuance-authorization gate is reachable by the serving tier within the deployment

On-demand certificate issuance is gated by an authorization decision from the platform's issuance
gate (owned by `certificate-issuance-authorization`). The deployment MUST make that gate reachable
by the tier that terminates customer-domain TLS. A deployment in which the serving tier cannot reach
the gate MUST NOT issue certificates unauthorized as a fallback; such a deployment is invalid.

#### Scenario: The serving tier can consult the gate for a first-seen hostname

- **WHEN** the front tier receives a TLS handshake for a customer hostname it holds no certificate for
- **THEN** it can reach the issuance-authorization gate to obtain an allow/deny decision for that
  hostname before attempting issuance

#### Scenario: An unreachable gate fails closed, never open

- **WHEN** a deployment terminates customer-domain TLS but the serving tier cannot reach the
  issuance-authorization gate
- **THEN** issuance for a first-seen hostname fails closed (the handshake is refused)
- **AND** the deployment never issues a certificate for a hostname the gate did not authorize
