# platform-service-authz

## Purpose

Authorize core platform services from a **platform-level permission set** they own, rather than from
per-workspace membership. A platform service acts across workspaces without holding a membership record in
any of them; its authority is a least-privilege set of named permissions, resolved live so revocation
takes effect within seconds. Each request still names the specific workspace the service is acting on,
system-determined from the trusted routing context.

## Requirements

### Requirement: A platform service is authorized by platform permissions, not workspace membership
The system SHALL authorize a core platform service from a **platform-level permission set** it owns,
rather than from per-workspace membership. A platform service SHALL NOT require a membership record in a
workspace to act on that workspace; its authority to act SHALL come from its platform permissions.

#### Scenario: A service acts without a workspace membership
- **WHEN** a platform service acts on a workspace in which it holds no membership record
- **THEN** the system SHALL authorize it from its platform permissions, not deny it for lack of a
  membership

#### Scenario: A workspace-scoped principal is not authorized platform-wide
- **WHEN** a user or api-key principal (which resolves via membership) attempts an action
- **THEN** its authority SHALL remain bounded by its workspace memberships, never widened to platform
  scope

### Requirement: Platform permissions are least-privilege
The system SHALL express a platform service's authority as a set of **named permissions**, not as blanket
access. A platform service SHALL be able to perform only the operations its named permissions admit,
even though those permissions may apply across workspaces.

#### Scenario: A service is limited to its named permissions
- **WHEN** a platform service attempts an operation its permission set does not include
- **THEN** the system SHALL refuse that operation, even if the service is otherwise authenticated and
  registered

### Requirement: Platform permissions are resolved live with revocation within seconds
The system SHALL resolve a platform service's permissions from the live authoritative store on the
request path, so that registering, changing, or revoking them takes effect within seconds on subsequent
requests, without the service re-authenticating. Revocation SHALL deny the service within that window.

#### Scenario: Revoking a service denies it promptly
- **WHEN** a platform service's registration or permissions are revoked while it still holds a valid
  credential
- **THEN** its subsequent requests SHALL be denied within seconds, without any credential reissue

### Requirement: An unregistered service resolves to no authority
The system SHALL treat a service whose credential verifies but which is not registered with platform
permissions as holding **no authority** — rejected and unsigned, never admitted open.

#### Scenario: An unknown service fails closed
- **WHEN** a verified service credential belongs to a service absent from the platform registry
- **THEN** the request SHALL be refused and no identity assertion SHALL be minted

### Requirement: A platform service still acts on a named workspace per request
The system SHALL identify the specific workspace a platform service is acting on for each request, even
though the service is authorized across workspaces. The acting workspace SHALL be system-determined (from
the trusted routing context), never asserted by the service.

#### Scenario: The acting workspace is named and system-determined
- **WHEN** a platform service makes a request against a workspace
- **THEN** the resolved identity SHALL name that acting workspace, taken from the trusted routing
  context and not from a service-supplied value
