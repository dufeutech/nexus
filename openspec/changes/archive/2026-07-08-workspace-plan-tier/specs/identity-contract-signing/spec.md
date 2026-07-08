## ADDED Requirements

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
