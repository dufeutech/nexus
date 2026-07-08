## ADDED Requirements

### Requirement: API-key principal resolves to intersected workspace authority
The system SHALL resolve an API-key principal's authority as the creating user's **live** workspace
memberships **intersected** with the key's scopes, so a key can never exceed its creator and follows the
creator's revocation.

#### Scenario: Key inherits a subset of the creator's memberships
- **WHEN** an API-key principal acts on a workspace
- **THEN** it is authorized only if the creating user is a live member of that workspace AND the key's
  scopes admit that workspace and action

#### Scenario: Creator's revocation cascades to the key
- **WHEN** the creating user's membership for a workspace is revoked
- **THEN** the key's authority for that workspace is withdrawn within seconds, without touching the key

#### Scenario: Scope narrows but never widens
- **WHEN** a key's scopes are narrower than the creator's memberships
- **THEN** the resolved authority is the intersection — never broader than either input

#### Scenario: No intersection fails closed
- **WHEN** an API-key principal acts on a workspace outside the intersection
- **THEN** it resolves to no authority and is rejected, never admitted open
