# edge-trust-anchor-integrity

## Purpose

Protects the root of all token verification: the edge's JWT signature-verification
keys (the trust anchor / JWKS) must be obtained over a channel an on-path attacker
cannot tamper with — a substituted key set is a full authentication bypass. A
configuration that cannot guarantee this fails closed rather than shipping silently.

## Requirements

### Requirement: The edge obtains JWT verification keys over an integrity-protected channel

The edge SHALL obtain the JWT signature-verification keys (the trust anchor / JWKS) over a
channel that authenticates the source and protects the response against tampering, so that
an on-path attacker cannot substitute the signing keys the edge trusts. The integrity of
this fetch is the root of all token verification; it SHALL NOT depend on the honesty of the
network path between the edge and the key source.

#### Scenario: On-path key substitution is rejected

- **WHEN** an attacker positioned on the path between the edge and the key source returns a
  JWKS response containing attacker-controlled keys
- **THEN** the edge SHALL NOT adopt those keys; the substituted response SHALL be rejected
  because the channel's integrity/authenticity check fails

#### Scenario: A non-integrity-protected trust-anchor configuration fails closed

- **WHEN** the edge is configured to fetch the trust anchor over a channel that does not
  authenticate the source or protect integrity, on a path that is not otherwise trusted
- **THEN** the deployment SHALL fail closed — refusing to start or refusing to serve
  token-verified routes — rather than silently trusting keys fetched over an unprotected
  channel
