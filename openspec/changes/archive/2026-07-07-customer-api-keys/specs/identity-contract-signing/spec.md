## ADDED Requirements

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
