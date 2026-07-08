## ADDED Requirements

### Requirement: Authorization resolution branches on principal kind
The system SHALL select how it resolves a principal's authority by the principal's **kind**:
workspace-scoped principals (human users, api keys) resolve to a **workspace authority** from live
membership, while core platform services resolve to a **platform authority** from their live platform
permissions. Both paths SHALL remain live and revocation-consistent (taking effect within seconds), and
both SHALL be deny-by-default when no authority resolves.

#### Scenario: A user resolves via membership
- **WHEN** a human-user principal is resolved
- **THEN** its authority SHALL come from its live workspace membership, unchanged from the existing
  behavior

#### Scenario: A service resolves via platform permissions
- **WHEN** a service principal is resolved
- **THEN** its authority SHALL come from its live platform permissions, not from any workspace membership

#### Scenario: Neither path resolving is deny-by-default
- **WHEN** a principal matches neither a live membership nor a live platform registration
- **THEN** it SHALL be treated as holding no authority and refused, consistent with deny-by-default
