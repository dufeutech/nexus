# provisioning-idempotency

## ADDED Requirements

### Requirement: Resource creation is safely retryable via a caller-supplied idempotency key

Creation requests for accounts and workspaces SHALL accept an optional caller-supplied
idempotency key. When a creation request carries a key that was already used to create
a resource of that kind, the system SHALL NOT create a second resource; it SHALL return
the originally created resource, including its original identifier, and indicate that
no new resource was created. Semantics of the key value (e.g. encoding a signup flow)
belong to the caller; the system SHALL treat the key as opaque and SHALL NOT derive
policy from it.

#### Scenario: Replaying a creation returns the original resource
- **WHEN** a caller creates an account with idempotency key K, then repeats the same
  request with key K
- **THEN** the second response SHALL carry the same account identifier as the first and
  SHALL indicate that no new account was created

#### Scenario: Blind retry of signup provisioning is safe
- **WHEN** a provisioning flow re-runs unconditionally (e.g. a retried first-signup)
  using a stable key for that flow
- **THEN** exactly one account SHALL exist for that key regardless of how many times the
  request is made

#### Scenario: Concurrent creations with the same key yield one resource
- **WHEN** two creation requests with the same idempotency key race
- **THEN** exactly one resource SHALL be created, and both callers SHALL receive its
  identifier

#### Scenario: Omitting the key opts out of replay protection
- **WHEN** a caller creates a workspace twice without an idempotency key
- **THEN** two distinct workspaces SHALL be created, each with its own identifier

#### Scenario: Malformed keys are rejected
- **WHEN** a creation request carries an empty key or one exceeding the documented
  length bound
- **THEN** the request SHALL be rejected with a validation error and no resource SHALL
  be created

### Requirement: Create and reconfigure are distinct, non-overlapping operations

The system SHALL expose resource creation and resource reconfiguration as distinct
operations. Creation SHALL mint a new identifier and SHALL NOT modify any existing
resource. Reconfiguration SHALL address an existing identifier and SHALL fail — not
create — when that identifier is unknown.

#### Scenario: Creation never overwrites
- **WHEN** a caller issues a creation request while a resource with the same display
  name already exists
- **THEN** a new resource with a new identifier SHALL be created and the existing
  resource SHALL be unmodified

#### Scenario: Reconfiguring an unknown id fails instead of creating
- **WHEN** a caller reconfigures a workspace using an identifier that does not exist
- **THEN** the system SHALL return a not-found error and SHALL NOT create a workspace
