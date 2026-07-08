## ADDED Requirements

### Requirement: A verified credential yields one normalized principal
The system SHALL, from any verified credential, produce a single normalized principal carrying a
**kind** (one of: human user, api key, service), a **subject** identifying it, and — where the credential
acts for someone else — an **on-behalf-of** subject. Authentication MAY use a different mechanism per
trust boundary, but it SHALL always yield this same principal shape, and authorization SHALL operate on
the principal alone, independent of which mechanism authenticated it.

#### Scenario: Different credentials, one principal shape
- **WHEN** a caller authenticates by any supported mechanism
- **THEN** the system SHALL resolve a normalized principal with a kind, a subject, and (if applicable) an
  on-behalf-of subject
- **AND** subsequent authorization SHALL depend only on the principal, not on the mechanism

#### Scenario: Authorization is blind to the authentication mechanism
- **WHEN** two principals hold the same kind, subject, and resolved authority but authenticated by
  different mechanisms
- **THEN** they SHALL receive identical authorization outcomes

### Requirement: Principal kind is system-authored, never caller-asserted
The system SHALL determine a principal's kind, subject, and on-behalf-of solely from the verified
credential and its own resolution. A kind, subject, or on-behalf-of value asserted by the caller (in a
header, body, or token claim) SHALL confer nothing.

#### Scenario: A caller-asserted kind is ignored
- **WHEN** a request asserts a principal kind that differs from what the credential proves
- **THEN** the system SHALL use only the credential-derived kind and ignore the asserted one

### Requirement: A core service authenticates by infrastructure-level trust, not the human identity provider
The system SHALL authenticate a core platform service by an infrastructure-level trust mechanism, and
SHALL NOT require it to authenticate through the human identity provider. The mechanism SHALL verify the
service's credential against trusted, published verification material, never by an unverifiable network
assumption alone.

#### Scenario: A service credential is verified, not assumed
- **WHEN** a core service presents its infrastructure-issued credential
- **THEN** the system SHALL verify it against trusted published material before admitting the caller as a
  service principal

#### Scenario: The human identity provider is not required for services
- **WHEN** a core service authenticates
- **THEN** it SHALL do so without a human identity-provider session

### Requirement: An authenticated principal that resolves to no authority is rejected
The system SHALL admit a principal only after resolving it to an authority (a workspace authority for
user/api-key principals, or a platform authority for service principals). A principal whose credential
verifies but resolves to no authority SHALL be rejected and SHALL receive no signed identity assertion —
never admitted open.

#### Scenario: Verified but unauthorized fails closed
- **WHEN** a credential verifies but the principal resolves to no authority
- **THEN** the request SHALL be refused and no identity assertion SHALL be minted

### Requirement: Principal kind is orthogonal to workspace member type
The system SHALL keep a principal's **kind** distinct from a workspace **member type** (such as staff or
customer). Kind describes what authenticated; member type describes a role held within a workspace. A
principal SHALL be able to carry a kind independent of whether it holds any workspace member type.

#### Scenario: A service principal has a kind but no member type
- **WHEN** a service principal is resolved
- **THEN** it SHALL carry the service kind and MAY hold no workspace member type at all
