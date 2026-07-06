# identity-data-residency

## Purpose

The residency boundary for nexus's authorization data: all identity and routing
data the system relies on to make authorization decisions lives in a datastore the
system owns and administers, kept administratively separate from any external
identity provider's datastore. This lets the identity provider be replaced,
relocated, or operated by a third party without moving nexus's data, and guarantees
no query for authorization data reaches across into provider-owned tables. The
requirement is language-, database-, and vendor-agnostic and states only the
observable boundary, not how the databases are provisioned.

## Requirements

### Requirement: Authorization data resides in a system-owned datastore separate from the identity provider

All identity and routing data the system relies on for authorization SHALL reside
in a datastore that the system owns and administers, distinct from the datastore of
any external identity provider. The two SHALL be separable administrative units —
each with its own access boundary, backup and recovery scope, and lifecycle — so
that the identity provider's datastore can be replaced, relocated, or operated by a
different party without moving the system's authorization data.

#### Scenario: System data is addressed independently of the provider's data

- **WHEN** the system's identity and routing stores are provisioned
- **THEN** they SHALL be addressed as a datastore the system owns, not as the
  identity provider's datastore, even when both are hosted on shared infrastructure

#### Scenario: Provider datastore can be removed without moving system data

- **WHEN** the external identity provider's datastore is decommissioned or relocated
- **THEN** the system's authorization data SHALL remain intact and reachable with no
  data migration, because it was never stored inside the provider's datastore

### Requirement: The system holds no cross-datastore dependency on provider-owned tables

The system's authorization data access SHALL NOT depend on reading, joining, or
referencing any table, view, or object owned by the identity provider. Every query
the system issues for authorization data SHALL be satisfiable entirely within the
system-owned datastore.

#### Scenario: Authorization resolves without the provider's datastore present

- **WHEN** the system resolves a profile, membership, or routing decision while the
  identity provider's datastore is unavailable or absent
- **THEN** the resolution SHALL succeed from the system-owned datastore alone,
  demonstrating no cross-datastore dependency

### Requirement: Data residency is preserved across every deployment surface

The system SHALL preserve the separation between the system-owned datastore and the
identity provider's datastore identically across all deployment surfaces — local,
staging, and production. No surface SHALL default the system's data onto the
identity provider's datastore.

#### Scenario: A development surface does not co-locate data with the provider

- **WHEN** the system is brought up on a local or development surface
- **THEN** its authorization data SHALL target the system-owned datastore, matching
  the residency boundary used in production rather than pointing at the provider's
  datastore
