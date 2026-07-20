# edge-client-ip-preservation

## Purpose

The contract for recovering the real client source address when the platform is fronted by a
layer-4 router that hands off connections while prepending the original client's address. Preservation
applies at the customer-domain TLS front tier and MAY be enabled at the edge listener so either tier
can sit directly behind such a router; it is off by default, and an enabled listener rejects an
un-framed connection rather than mis-parsing it. This spec is language-agnostic and states only the
observable behavior.

## Requirements

### Requirement: The real client address is preserved behind a connection-preserving front router

The platform MUST be able to recover and act on the real client source address rather than a fronting
router's address when it is fronted by a layer-4 router that hands off connections while prepending
the original client's address. This applies at the customer-domain TLS front tier, and MAY be enabled
at the edge listener so that either tier can sit directly behind such a router.

#### Scenario: The front tier recovers the original client address

- **WHEN** a client connects to the customer-domain front tier through a layer-4 router that prepends
  the original client address to the connection
- **THEN** the front tier accepts the connection, recovers the original client address, and treats
  that address — not the router's — as the client for logging, tracing, and any address-dependent
  decision

#### Scenario: The edge listener can opt in to the same preservation

- **WHEN** address preservation is enabled on the edge listener and a connection arrives through a
  layer-4 router that prepends the original client address
- **THEN** the edge recovers and uses the original client address end-to-end

#### Scenario: Preservation is off by default and direct connections are unaffected

- **WHEN** address preservation is not enabled on a listener
- **THEN** that listener treats incoming connections as direct and reads the peer address as the
  client address, unchanged from today's behavior
- **AND** a connection that arrives without the prepended-address framing on a preservation-enabled
  listener is rejected rather than mis-parsed
