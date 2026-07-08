# identity-contract-signing

## Purpose

Makes the `x-identity-contract` stamp a **cryptographically verifiable** proof that the
enrichment was authored by nexus, not merely a plain version string trusted because of the
network path. nexus signs the resolved identity into a short-lived, asymmetrically-signed
token; a backend verifies it against nexus-published keys. This is **defense-in-depth**: it
augments, and never replaces, `edge-origin-trust` origin enforcement (which remains the
primary anti-bypass control). The token's shape/version contract and how a backend requires
it are owned by `identity-workspace-authz`; this capability owns the signing, key
publication, and rotation.

## Requirements

### Requirement: The identity contract is a signed, verifiable assertion

The identity plane SHALL emit the `x-identity-contract` value as a self-contained token that is cryptographically signed over the resolved identity it conveys — at minimum the authenticated subject, the acting workspace, and the acting role. A backend SHALL be able to verify the token's authenticity using only the identity plane's **publicly published verification material**, with no shared secret and no ability to mint a token itself. The signature scheme SHALL be asymmetric: the signing (private) key is held only by nexus; backends receive only the verification (public) key.

#### Scenario: A backend verifies a genuine assertion

- **WHEN** a backend receives an enriched request whose `x-identity-contract` token was signed by the identity plane and matches its published verification key
- **THEN** the backend SHALL accept the token as authentic and MAY read the resolved identity (subject, acting workspace, role) from its claims

#### Scenario: A tampered assertion is rejected

- **WHEN** any byte of the token or its conveyed claims is altered after signing
- **THEN** signature verification SHALL fail and the backend SHALL reject the request rather than trust the altered claims

#### Scenario: A backend cannot forge an assertion for another backend

- **WHEN** a backend (or any party holding only the public verification material) attempts to mint a token that would verify as nexus-signed
- **THEN** it SHALL be unable to produce a valid signature, because the signing key is asymmetric and held only by the identity plane

### Requirement: The assertion is audience-scoped, issuer-identified, and short-lived

Each signed assertion SHALL carry an issuer identifying nexus as the origin, an audience identifying the specific intended backend, and an expiry after which it is no longer valid. A backend SHALL reject a token whose issuer is not the expected nexus issuer, whose audience is not itself, or whose expiry has passed. These bounds SHALL make a captured token unusable against a different backend or after its short lifetime.

#### Scenario: An expired assertion is rejected

- **WHEN** a backend receives a token whose expiry is in the past
- **THEN** the backend SHALL reject the request, so a captured token cannot be replayed after its lifetime

#### Scenario: An assertion presented to the wrong backend is rejected

- **WHEN** a token minted with one backend's audience is presented to a different backend
- **THEN** the receiving backend SHALL reject it on the audience mismatch, so a token captured at one backend cannot be replayed at another

#### Scenario: An assertion from an unexpected issuer is rejected

- **WHEN** a token verifies cryptographically but its issuer is not the nexus issuer the backend expects
- **THEN** the backend SHALL reject the request

### Requirement: Verification keys are published and rotated without breaking in-flight tokens

The identity plane SHALL publish its current public verification key(s) at a stable location reachable by every consuming backend, each key carrying an identifier that lets a backend select the correct key for a given token. Key rotation SHALL overlap: a new key SHALL be published before any token is signed with it, and a retired key SHALL remain published until every token signed with it has expired. A backend SHALL fetch and cache the published keys and SHALL tolerate rotation without rejecting tokens signed by a still-valid key.

#### Scenario: A backend fetches published keys and verifies

- **WHEN** a backend has fetched the identity plane's published verification keys and receives a token identifying one of them
- **THEN** it SHALL verify the token against that key with no shared secret

#### Scenario: Rotation does not reject in-flight tokens

- **WHEN** the identity plane rotates to a new signing key while tokens signed by the previous key are still within their (short) validity window
- **THEN** both keys SHALL be published, and a backend SHALL verify tokens signed by either the new or the not-yet-expired previous key

### Requirement: Only authenticated, membership-resolved requests are signed

The identity plane SHALL mint a signed assertion only for a request whose subject was authenticated AND whose **authority was resolved** — either an acting-workspace membership (for a user or api-key principal) or a platform permission set (for a service principal). It SHALL NOT mint a token for an anonymous or unauthenticated request, nor for a principal that resolves to no authority. Whether a backend permits anonymous access on a given route is the backend's decision; nexus contributes no signed attestation in the absence of a resolved authority.

#### Scenario: An anonymous request carries no signed assertion

- **WHEN** a request has no authenticated subject or resolves to no authority
- **THEN** the identity plane SHALL NOT mint an `x-identity-contract` assertion for it

#### Scenario: An enriched user request carries a signed assertion

- **WHEN** a request's subject is authenticated and its acting-workspace membership is resolved on an identity-enriched route
- **THEN** the identity plane SHALL mint and stamp a signed `x-identity-contract` assertion conveying that resolved identity

#### Scenario: An authorized service request carries a signed assertion

- **WHEN** a service principal is authenticated and resolves to a platform permission set on an identity-enriched route
- **THEN** the identity plane SHALL mint and stamp a signed `x-identity-contract` assertion for it, even though it holds no workspace membership

### Requirement: The signing key is a runtime secret held only by the identity plane

The private signing key SHALL be delivered to the identity plane at runtime as an injected secret referenced by key, never committed to source and never embedded in an image or config file. It SHALL NOT be distributed to any backend. A deployment that exposes the private signing key outside the identity plane, or that ships it as static config, SHALL be treated as a misconfiguration.

#### Scenario: The private key is never distributed to backends

- **WHEN** a deployment is assembled
- **THEN** backends SHALL receive only the public verification material, and the private signing key SHALL be present only within the identity plane as a runtime-injected secret

### Requirement: The signed assertion identifies the principal kind

The signed assertion SHALL carry the **principal kind** it conveys, so a backend can authorize on kind (for example admitting a service as a writer while gating a human by role). For a service principal the assertion SHALL carry the acting workspace and the service's platform permissions in place of a workspace member type and role. The kind and its accompanying authority SHALL be nexus-authored and SHALL NOT be assertable by the caller.

#### Scenario: A backend reads the principal kind from the assertion

- **WHEN** a backend receives an enriched request whose assertion verifies
- **THEN** it SHALL be able to read the principal kind from the token's claims and authorize on it

#### Scenario: A service assertion conveys platform authority, not a member role

- **WHEN** the identity plane mints an assertion for a service principal
- **THEN** the token SHALL convey the service kind, the acting workspace, and the platform permissions, and SHALL NOT claim a workspace member type or role for the service

### Requirement: Contract carries the api-key kind and on-behalf-of principal
The signed identity contract SHALL, for an API-key principal, carry a `principal_kind` of `apikey` and an
`on_behalf_of` claim naming the creating user, alongside the acting workspace, so a box can attribute the
action to both the key and the human behind it.

#### Scenario: Api-key contract names both principals
- **WHEN** the system mints a contract for an API-key principal
- **THEN** the contract's `principal_kind` is `apikey`, its subject is the key ID, and its `on_behalf_of`
  claim is the creating user's subject

#### Scenario: On-behalf-of is absent for non-key principals
- **WHEN** the system mints a contract for a human or platform-service principal
- **THEN** the `on_behalf_of` claim is omitted

#### Scenario: Api-key claims are nexus-authored, never key-asserted
- **WHEN** a presented key attempts to assert its own kind, subject, or on-behalf-of
- **THEN** those values are ignored and the contract carries only nexus-resolved values

### Requirement: The signed contract carries the acting workspace's plan
The signed identity contract SHALL convey the acting workspace's plan tier as a nexus-authored
claim, so a box can trust the plan cryptographically rather than reading an unsigned header. The
plan claim SHALL be populated from the same nexus-resolved plan emitted alongside the contract;
it SHALL be omitted when no plan resolves for the acting workspace, so its later population is a
value appearing where one was absent — not a change to the contract's shape.

#### Scenario: Contract conveys the resolved plan
- **WHEN** the identity plane mints a contract for a request whose acting workspace resolves to
  plan `P`
- **THEN** the contract SHALL carry `P` as its plan claim, over the same signature that protects
  the rest of the resolved identity

#### Scenario: Plan claim is omitted when unresolved
- **WHEN** the identity plane mints a contract but no plan resolves for the acting workspace
- **THEN** the contract SHALL omit the plan claim rather than carry a default

#### Scenario: Plan claim is nexus-authored, never credential-asserted
- **WHEN** a presented credential or client hint attempts to assert a plan
- **THEN** the minted contract SHALL carry only the plan nexus resolved for the acting workspace
