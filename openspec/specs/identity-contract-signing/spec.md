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

The identity plane SHALL mint a signed assertion only for a request whose subject was authenticated AND whose acting-workspace membership was resolved. It SHALL NOT mint a token for an anonymous or unauthenticated request. Whether a backend permits anonymous access on a given route is the backend's decision; nexus contributes no signed attestation in the absence of a resolved identity.

#### Scenario: An anonymous request carries no signed assertion

- **WHEN** a request has no authenticated subject or no resolved workspace membership
- **THEN** the identity plane SHALL NOT mint an `x-identity-contract` assertion for it

#### Scenario: An enriched request carries a signed assertion

- **WHEN** a request's subject is authenticated and its acting-workspace membership is resolved on an identity-enriched route
- **THEN** the identity plane SHALL mint and stamp a signed `x-identity-contract` assertion conveying that resolved identity

### Requirement: The signing key is a runtime secret held only by the identity plane

The private signing key SHALL be delivered to the identity plane at runtime as an injected secret referenced by key, never committed to source and never embedded in an image or config file. It SHALL NOT be distributed to any backend. A deployment that exposes the private signing key outside the identity plane, or that ships it as static config, SHALL be treated as a misconfiguration.

#### Scenario: The private key is never distributed to backends

- **WHEN** a deployment is assembled
- **THEN** backends SHALL receive only the public verification material, and the private signing key SHALL be present only within the identity plane as a runtime-injected secret
