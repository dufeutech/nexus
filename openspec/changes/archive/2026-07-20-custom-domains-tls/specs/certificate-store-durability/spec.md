## ADDED Requirements

### Requirement: Any node serves any customer domain from a shared store

The system SHALL persist obtained certificates in a store shared by the whole edge fleet, so that any
node can serve any customer domain without re-obtaining its certificate, and no certificate exists
only in a single node's local state.

#### Scenario: A certificate obtained by one node is served by another
- **WHEN** one node obtains a certificate for a hostname and a later connection for that hostname
  reaches a different node
- **THEN** the second node SHALL serve the stored certificate without initiating a new issuance

### Requirement: Issuance for a hostname is single-flighted across the fleet

The system SHALL ensure that concurrent first-time demand for the same hostname across multiple nodes
results in at most one issuance order being placed with the certificate authority; the other nodes
SHALL wait for and then serve the resulting certificate rather than each placing their own order.

#### Scenario: Simultaneous first connections cause one issuance
- **WHEN** several nodes concurrently receive a first connection for the same brand-new authorized
  hostname
- **THEN** at most one issuance order SHALL be placed, and every node SHALL serve the single resulting
  certificate

### Requirement: Stored certificates survive the loss of any single node

The system SHALL keep every stored certificate available after the loss of any single edge node, so
recovery of a hostname's certificate does not require re-issuing it.

#### Scenario: Losing a node does not lose its certificates
- **WHEN** a node that was serving a hostname is lost
- **THEN** the hostname's certificate SHALL remain available from the shared store and SHALL be
  servable by another node without re-issuance

### Requirement: Per-node memory is bounded to the working set, not the total population

The system SHALL bound each node's in-memory certificate footprint to the set of currently active
hostnames rather than the total registered-domain count, loading certificates from the shared store
on demand and evicting inactive ones, so the total population can exceed what any single node holds in
memory without failure.

#### Scenario: Total population exceeds a node's in-memory capacity
- **WHEN** the total number of registered customer domains far exceeds what a single node can hold in
  memory at once
- **THEN** the node SHALL continue serving by loading active certificates on demand and evicting
  inactive ones, without failing due to the total population size
