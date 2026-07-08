## MODIFIED Requirements

### Requirement: Only authenticated, membership-resolved requests are signed

The identity plane SHALL mint a signed assertion only for a request whose subject was authenticated AND
whose **authority was resolved** — either an acting-workspace membership (for a user or api-key
principal) or a platform permission set (for a service principal). It SHALL NOT mint a token for an
anonymous or unauthenticated request, nor for a principal that resolves to no authority. Whether a
backend permits anonymous access on a given route is the backend's decision; nexus contributes no signed
attestation in the absence of a resolved authority.

#### Scenario: An anonymous request carries no signed assertion

- **WHEN** a request has no authenticated subject or resolves to no authority
- **THEN** the identity plane SHALL NOT mint an `x-identity-contract` assertion for it

#### Scenario: An enriched user request carries a signed assertion

- **WHEN** a request's subject is authenticated and its acting-workspace membership is resolved on an
  identity-enriched route
- **THEN** the identity plane SHALL mint and stamp a signed `x-identity-contract` assertion conveying that
  resolved identity

#### Scenario: An authorized service request carries a signed assertion

- **WHEN** a service principal is authenticated and resolves to a platform permission set on an
  identity-enriched route
- **THEN** the identity plane SHALL mint and stamp a signed `x-identity-contract` assertion for it, even
  though it holds no workspace membership

## ADDED Requirements

### Requirement: The signed assertion identifies the principal kind

The signed assertion SHALL carry the **principal kind** it conveys, so a backend can authorize on kind
(for example admitting a service as a writer while gating a human by role). For a service principal the
assertion SHALL carry the acting workspace and the service's platform permissions in place of a workspace
member type and role. The kind and its accompanying authority SHALL be nexus-authored and SHALL NOT be
assertable by the caller.

#### Scenario: A backend reads the principal kind from the assertion

- **WHEN** a backend receives an enriched request whose assertion verifies
- **THEN** it SHALL be able to read the principal kind from the token's claims and authorize on it

#### Scenario: A service assertion conveys platform authority, not a member role

- **WHEN** the identity plane mints an assertion for a service principal
- **THEN** the token SHALL convey the service kind, the acting workspace, and the platform permissions,
  and SHALL NOT claim a workspace member type or role for the service
