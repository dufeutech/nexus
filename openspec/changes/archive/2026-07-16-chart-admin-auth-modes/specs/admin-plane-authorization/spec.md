## ADDED Requirements

### Requirement: The deployment surface can express every supported admin-auth posture

The system's deployment configuration surface SHALL be able to produce a startable
configuration for each admin-auth posture the admin plane supports: an explicitly disabled
gate (trusted-network/dev), a named-token posture (the production credential of record), and a
legacy shared-token migration posture. Selecting the named-token posture SHALL supply the
verification key material by reference to an externally-managed secret without requiring the
material to be embedded in configuration values. No supported posture SHALL be unreachable
from configuration.

#### Scenario: Named-token posture renders a startable configuration

- **WHEN** an operator configures the named-token posture with a reference to an externally-held
  verification key
- **THEN** the rendered deployment carries the named-token verification material sourced from
  that reference and no legacy shared-token material, and the plane starts in the named-token
  posture

#### Scenario: Legacy migration posture renders a startable configuration

- **WHEN** an operator configures the legacy migration posture together with the legacy shared
  token
- **THEN** the rendered deployment carries both the legacy shared token and the explicit
  migration opt-in, and the plane starts in the legacy shared-token posture

#### Scenario: Disabled posture renders an unauthenticated configuration

- **WHEN** an operator explicitly selects the disabled posture
- **THEN** the rendered deployment carries the explicit disable signal and no credential
  material, and the plane starts with the admin gate open

### Requirement: The deployment surface is fail-closed at configuration time

The system's deployment configuration surface SHALL refuse to produce a deployment when no
valid admin-auth posture is selected, or when a selected posture is incomplete — including a
legacy migration opt-in without its shared token — rather than emitting a configuration that
cannot start. The refusal SHALL name the missing choice. Configuration-time refusal SHALL
mirror the plane's runtime fail-closed startup contract, so an unstartable posture is rejected
before deployment rather than surfacing as a crash after it. This requirement SHALL hold
identically for every admin surface the platform deploys.

#### Scenario: No posture selected is refused before deployment

- **WHEN** a deployment is rendered for an admin surface with no admin-auth posture selected
- **THEN** rendering is refused with a message naming the available postures, and no deployment
  manifest is produced

#### Scenario: An incomplete migration posture is refused before deployment

- **WHEN** the legacy migration opt-in is selected but no legacy shared token is supplied
- **THEN** rendering is refused, mirroring the plane's runtime refusal for the same
  configuration, and no deployment manifest is produced

#### Scenario: The guard holds across every admin surface

- **WHEN** any admin surface the platform deploys is rendered without a valid posture
- **THEN** it is refused identically, so no admin surface can be deployed in an unstartable state
