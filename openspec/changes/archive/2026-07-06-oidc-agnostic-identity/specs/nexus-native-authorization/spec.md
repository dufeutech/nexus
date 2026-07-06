## ADDED Requirements

### Requirement: Authorization facts are system-authored, never identity-provider-sourced

The system SHALL author and own a subject's global authorization facts: its roles,
its entitlements, and whether it is suspended. The identity provider SHALL
supply only authentication (proof of subject identity) and basic profile attributes;
it SHALL NOT be a source of any authorization fact. A role, grant, or status asserted
by the identity provider or carried in the authentication token SHALL confer no
authorization in the system unless the system itself has authored it.

#### Scenario: A provider-asserted role confers nothing

- **WHEN** a subject presents a valid token that asserts a role (as a claim), but the
  system has authored no such role for that subject
- **THEN** the subject SHALL be treated as not having that role, and any route
  requiring it SHALL be refused

#### Scenario: Authentication and authorization are separate answers

- **WHEN** a subject authenticates successfully
- **THEN** its authorization SHALL be determined solely from system-authored facts,
  independently of which identity provider authenticated it

### Requirement: Absent authorization is deny-by-default

A subject about which the system holds no authorization facts SHALL be treated as
authenticated but unprivileged — holding no roles, no entitlements, and not
suspended. Elevated access SHALL require an authorization fact the system has
explicitly authored; it SHALL never arise implicitly from authentication alone.

#### Scenario: A newly authenticated subject has no privileges

- **WHEN** a subject authenticates for the first time and the system has authored no
  authorization facts about it
- **THEN** a route requiring a role or entitlement SHALL be refused, while a route
  requiring only authentication SHALL admit the subject as unprivileged

#### Scenario: Absence of a suspension fact means not suspended

- **WHEN** the system holds no suspension fact for an authenticated subject
- **THEN** the subject SHALL be treated as not suspended (the safe default), not
  blocked for lack of a record

### Requirement: Authorization is resolved live and revocation takes effect within seconds

The system SHALL resolve a subject's authorization facts from the live authoritative
store on the request path, so that authoring a grant, revoking it, or suspending the
subject takes effect within seconds on subsequent requests, WITHOUT requiring a new
authentication token. Suspension SHALL deny the subject within that window.

#### Scenario: Suspension denies without re-authentication

- **WHEN** a subject is suspended while it still holds a valid authentication token
- **THEN** its subsequent requests SHALL be denied within seconds, without the token
  being reissued or revoked at the provider

#### Scenario: A granted role becomes effective without a new token

- **WHEN** the system authors a new role for a subject that is currently authenticated
- **THEN** the subject's subsequent requests SHALL satisfy a route requiring that
  role within seconds, without re-authentication

#### Scenario: A revoked grant stops being effective

- **WHEN** a previously authored role or entitlement is revoked
- **THEN** the subject's subsequent requests SHALL no longer satisfy a route requiring
  it, within seconds

### Requirement: Authorization facts are created and revoked only through the system's administrative surface

Authorization facts SHALL be authored (created, changed, revoked) only through the
system's own administrative authoring surface, which is the single source of record
for them. No external event, token, or identity-provider action SHALL create or
elevate a subject's authorization. The system SHALL provide a bootstrap path by which
an initial administrator can be established when no administrator yet exists, so the
authoring surface is never unreachable.

#### Scenario: Only the administrative surface can grant

- **WHEN** an authorization fact appears for a subject
- **THEN** it SHALL have originated from the system's administrative authoring surface,
  and no inbound request or token SHALL have been able to author it

#### Scenario: The first administrator can be bootstrapped

- **WHEN** the system is first stood up with no administrator authored yet
- **THEN** there SHALL be a defined bootstrap path that establishes an initial
  administrator, so authorization can be provisioned from an empty state

### Requirement: The authorization backend is resolved behind a replaceable boundary

Enforcement and enrichment points SHALL obtain authorization facts through an abstract
authorization contract, not by depending on a specific storage shape. Replacing the
authorization backend SHALL NOT require changing the points that enforce or consume
authorization.

#### Scenario: Backend replacement does not change enforcement

- **WHEN** the authorization backend is replaced with a different implementation that
  answers the same authorization questions
- **THEN** the enforcement and enrichment behavior SHALL be unchanged, and the
  consuming points SHALL require no modification
