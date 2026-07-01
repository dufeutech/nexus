# identity-workspace-authz

## Purpose

The identity plane's authorization contract: given a verified subject and a resolved
workspace, it authorizes the subject's typed relationship to that workspace and emits
the authoritative acting scope for the backend.

## Requirements

### Requirement: The acting workspace is authorized against membership, live

The identity plane SHALL, for an authenticated subject `sub` and a resolved
`workspace_id`, look up the subject's membership of that workspace from the
nexus-owned store and emit an **authoritative** `x-workspace-id` only when a valid
membership exists. The lookup SHALL reflect the live store (a revoked or changed
membership takes effect within seconds, like suspension), NOT a value carried in the
authentication token.

#### Scenario: Member is authorized into the workspace
- **WHEN** `sub` has a valid membership of the resolved `workspace_id`
- **THEN** the identity plane SHALL emit `x-workspace-id` (the resolved workspace),
  `x-user-type`, and the workspace-scoped `x-user-role`

#### Scenario: Non-member is refused the workspace (fail-closed)
- **WHEN** `sub` has no valid membership of the resolved `workspace_id`
- **THEN** the identity plane SHALL NOT emit an authoritative `x-workspace-id`
  granting access; the request SHALL be treated as unauthorized for that workspace
  (rejected, or handled by an explicit anonymous/self-signup policy — never silently
  admitted as a member)

#### Scenario: Revocation takes effect without a new token
- **WHEN** a subject's membership is revoked while a valid authentication token is
  still held
- **THEN** the next request SHALL resolve to no membership and be refused, without
  requiring token re-issue

### Requirement: Membership carries a type and a workspace-scoped role

A membership SHALL carry a `type` of `staff` or `customer` and a `role` scoped to
that `(workspace, type)`. The identity plane SHALL emit `x-user-type` and the
role for the matched relationship, NOT a global role. A subject MAY hold different
memberships (types/roles) across different workspaces.

#### Scenario: Same subject, different capacity per workspace
- **WHEN** `sub` is `staff` of workspace A and `customer` of workspace B, and a
  request resolves to workspace B
- **THEN** the identity plane SHALL emit `x-user-type: customer` and B's
  customer-scoped role — not the staff role held in A

### Requirement: The acting workspace is a request-time selection a client cannot forge

The identity plane SHALL treat any client-supplied workspace value as an unauthorized
*hint* only. The authoritative `x-workspace-id` (and `x-user-type`/`x-user-role`)
SHALL be produced by nexus after the membership check; a client-supplied
`x-workspace-id`/`x-requested-workspace`/`x-user-*` SHALL have no effect on the
emitted scope.

#### Scenario: Client hint cannot self-authorize a workspace
- **WHEN** a request carries a client-set `x-workspace-id` (or `x-requested-workspace`)
  for a workspace the subject is not a member of
- **THEN** the emitted authoritative scope SHALL NOT grant that workspace; the client
  value SHALL be discarded before resolution

### Requirement: The identity enrichment is stamped with a versioned contract

The identity plane SHALL stamp every enriched request with an `x-identity-contract`
header carrying the version of the edge→backend identity-header contract it emits
(e.g. `v1`). The backend SHALL require an `x-identity-contract` value it understands
and reject any request whose value is absent or unrecognized. This is the single
coordination gate for the whole `x-workspace-*`/`x-user-*` header family: any drift in
that family's shape (a rename, a removed/added field, a changed meaning) is a version
bump, so a partially-deployed contract change fails closed instead of feeding the
backend headers it silently misreads.

The acting-scope guarantee is PART of the versioned contract, not a separate sentinel:
a well-formed `vN` request SHALL carry the authoritative acting `x-workspace-id`
(and `x-user-type`), so a same-version request missing the acting scope is not a valid
`vN` request and the backend SHALL reject it. There is NO standalone acting-scope
marker header.

`x-identity-contract` is trusted-emitted and therefore MUST be stripped from client
input at the edge (the same C3 rule that makes `x-auth-required`/`x-workspace-id`
unforgeable), so a client can neither forge a version nor bypass the edge and present
its own.

#### Scenario: Backend rejects a stale or absent contract version
- **WHEN** a request reaches the backend with `x-identity-contract` absent, or set to a
  version the backend does not accept (e.g. the edge still emits `v1` after the backend
  moved to require `v2`)
- **THEN** the backend SHALL reject the request rather than interpret the identity
  headers under an assumed shape

#### Scenario: Version bump gates a breaking header rename
- **WHEN** the `x-workspace-*`/`x-user-*` header shape changes (e.g. a field rename) and
  only one side of edge/backend has been rolled out
- **THEN** the contract version emitted by the edge and the version required by the
  backend SHALL NOT match, and the request SHALL fail closed until both sides are
  rolled to the same version

#### Scenario: Client cannot forge or bypass the contract stamp
- **WHEN** an inbound request carries a client-set `x-identity-contract`, or reaches the
  backend without traversing the edge enrichment
- **THEN** the edge SHALL strip any client-supplied value before the trusted stage emits
  the authoritative one, and a request that never traversed the edge SHALL lack the
  header and be rejected by the backend
