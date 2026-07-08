# identity-workspace-authz

## MODIFIED Requirements

### Requirement: The acting workspace is authorized against membership, live

The identity plane SHALL, for an authenticated subject `sub` and a resolved
`workspace_id`, look up the subject's membership of that workspace from the
nexus-owned store and emit an **authoritative** `x-workspace-id` only when a valid
membership exists. The lookup SHALL reflect the live store (a revoked or changed
membership takes effect within seconds, like suspension), NOT a value carried in the
authentication token.

When no valid membership exists, the request SHALL be refused in an **existence-hiding**
manner: the refusal's observable shape (status, body, headers, timing) is governed by the
`identity-existence-hiding` capability — a non-member SHALL NOT be able to distinguish
"forbidden" from "does not exist." The refusal is therefore a `404`-class not-found outcome,
not a distinguishable `403`, except where the subject IS a member but fails a specific route
requirement (role/entitlement/assurance), which remains an honest `403` per that capability.

#### Scenario: Member is authorized into the workspace
- **WHEN** `sub` has a valid membership of the resolved `workspace_id`
- **THEN** the identity plane SHALL emit `x-workspace-id` (the resolved workspace),
  `x-user-type`, and the workspace-scoped `x-user-role`

#### Scenario: Non-member is refused the workspace (fail-closed, existence-hiding)
- **WHEN** `sub` has no valid membership of the resolved `workspace_id`
- **THEN** the identity plane SHALL NOT emit an authoritative `x-workspace-id`
  granting access; the request SHALL be refused with the existence-hiding `404` defined by
  `identity-existence-hiding` (never silently admitted as a member, and never refused with a
  status that reveals the workspace exists), unless an explicit anonymous/self-signup policy
  designates the route exempt from the membership gate

#### Scenario: Revocation takes effect without a new token
- **WHEN** a subject's membership is revoked while a valid authentication token is
  still held
- **THEN** the next request SHALL resolve to no membership and be refused, without
  requiring token re-issue
