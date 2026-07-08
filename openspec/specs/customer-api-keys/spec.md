# customer-api-keys

## Purpose

Give customer automation — scripts, CI/CD, customer backends — a first-class, long-lived
credential (a **Personal Access Token**) that is neither a human OIDC session nor a
core-platform service identity. A PAT acts **on behalf of** its creating human, bounded by
the key's scopes: its effective authority is the creator's **live** workspace memberships
**intersected** with the key's scopes, so a key can never exceed its creator and follows the
creator's revocation. Secrets are stored and verified only as hashes; issuance, expiry,
rotation, and revocation are live and fail-closed; and the audit trail records both the key
and the human behind it. This capability owns the PAT lifecycle and the api-key
authenticator; the signed-contract claims it produces are owned by
`identity-contract-signing`, and its intersected-authority resolution by
`nexus-native-authorization`.

## Requirements

### Requirement: Human-authenticated key issuance
The system SHALL allow only an authenticated human principal to issue a Personal Access Token, and each
issued key SHALL be bound to that creator's identity for the key's entire lifetime.

#### Scenario: Authenticated human issues a key
- **WHEN** an authenticated human requests a new API key with a chosen set of scopes
- **THEN** the system issues a key with a unique key ID bound to the creator's subject
- **AND** returns the secret exactly once, and never again

#### Scenario: Unauthenticated issuance is refused
- **WHEN** a caller that is not an authenticated human requests a new API key
- **THEN** the system refuses issuance and creates no key

#### Scenario: A key may not exceed its creator
- **WHEN** a key is requested with scopes broader than the creator's own authority
- **THEN** the issued key's effective authority is bounded by the creator's authority at use time

### Requirement: Secret storage and verification
The system SHALL store key secrets only in a hashed form and SHALL verify a presented key by hashing,
never by comparing or persisting a plaintext secret.

#### Scenario: Secret is never persisted in plaintext
- **WHEN** a key is issued
- **THEN** only a hash of the secret is persisted, and the plaintext exists only in the one-time response

#### Scenario: Presented key is verified by hash
- **WHEN** a request presents a key secret
- **THEN** the system verifies it against the stored hash and admits the caller only on a match

### Requirement: Expiry, rotation, and revocation are live
The system SHALL treat a key as usable only while it is unexpired and its status is active, and a change
to that state SHALL take effect promptly (within seconds), consistent with membership liveness.

#### Scenario: Expired key is rejected
- **WHEN** a request presents a key past its expiration
- **THEN** the caller resolves to no authority and is rejected

#### Scenario: Revoked key is rejected promptly
- **WHEN** a key is revoked
- **THEN** subsequent requests presenting that key are rejected within seconds

#### Scenario: Rotation supersedes without widening
- **WHEN** a key is rotated
- **THEN** a new secret supersedes the old one under a preserved lineage, with authority no broader than
  the rotated key

### Requirement: On-behalf-of audit binding
The system SHALL record, for every request authenticated by a key, both the key ID and the creating
user, so that actions are attributable to the human behind the automation.

#### Scenario: Audit records both principals
- **WHEN** a request is authenticated by an API key
- **THEN** the emitted identity records the key ID as the subject and the creating user as the
  on-behalf-of principal
