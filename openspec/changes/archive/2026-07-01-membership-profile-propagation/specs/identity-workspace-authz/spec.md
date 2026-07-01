## ADDED Requirements

### Requirement: home_org is informational and never an authorization input

The identity plane SHALL treat any `home_org` value on the subject's profile as
informational, denormalized context only (the subject's home organization); it MUST NOT
influence membership resolution or the emitted acting scope in any way. Authorization into
a workspace SHALL depend solely on the subject's membership of that workspace, and the
retired `x-user-org` authorization signal SHALL NOT be reintroduced by way of `home_org`.

#### Scenario: home_org does not grant a workspace
- **WHEN** a subject has a `home_org` set but no valid membership of the resolved
  `workspace_id`
- **THEN** the identity plane SHALL fail closed for that workspace exactly as for any
  non-member; `home_org` SHALL have no effect on the outcome

#### Scenario: home_org does not alter the emitted acting scope
- **WHEN** a subject is authorized into a workspace by a valid membership and also has a
  `home_org` set
- **THEN** the emitted `x-workspace-id`/`x-user-type`/`x-user-role` SHALL be derived only
  from the matched membership, and `home_org` SHALL NOT be emitted as an authoritative
  authorization header
