# nexus-native-authorization

## Purpose

Make the system the authoritative source of a subject's global authorization facts —
roles, entitlements, and suspension — so the identity provider answers only "who am I"
(authentication + basic profile) while the system answers "what may I do here." Facts are
authored only through the system's own administrative surface, resolved live on the
request path (deny-by-default when absent, revocation within seconds without a new token),
and obtained behind an abstract authorization contract so the backend is replaceable.

## Requirements

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
