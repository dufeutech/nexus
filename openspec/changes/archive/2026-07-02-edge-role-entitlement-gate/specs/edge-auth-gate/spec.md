# edge-auth-gate — delta: role / entitlement / minimum-AAL gate (N4 Phase 2)

## ADDED Requirements

### Requirement: Per-route authorization requirements are resolved with the auth policy

A tenant's per-route auth policy rule MAY additionally carry a required role, a
required entitlement, and a minimum authentication assurance level (any subset,
all optional). The tenant-routing stage SHALL resolve these with the same
longest-prefix match, cache, and invalidation as `auth_required`, and SHALL emit
each one as a trusted policy signal (`x-auth-requires-role`,
`x-auth-requires-entitlement`, `x-auth-min-aal`) only when the resolved rule sets
it. A rule that sets none of them SHALL behave exactly as before this change.

#### Scenario: Requirements ride the resolved rule
- **WHEN** the tenant policy resolves the request path to a rule carrying
  `requires_role = admin`
- **THEN** the tenant-routing stage SHALL emit `x-auth-requires-role: admin`
  alongside `x-auth-required: "true"`, and SHALL NOT emit the entitlement or AAL
  signals the rule does not set

#### Scenario: Phase-1 rules are unchanged
- **WHEN** the resolved rule sets no requirement fields
- **THEN** no requirement signal SHALL be emitted and the gate outcome SHALL be
  identical to the boolean `auth_required` behavior

#### Scenario: Requirement change propagates like any policy change
- **WHEN** a tenant updates a rule's requirement fields
- **THEN** the running policy SHALL converge via the existing invalidation
  mechanism, without restart or a second invalidation path

### Requirement: The edge rejects requests whose enrichment does not satisfy the resolved requirements

An edge authorization step, positioned after credential verification and identity
enrichment, SHALL compare each emitted requirement signal against the injected
enrichment and reject the request with **403** unless ALL resolved requirements
are satisfied:

- required role — satisfied when the required value is among the injected user
  roles;
- required entitlement — satisfied when the required value is among the injected
  user entitlements;
- minimum assurance level — satisfied when the assurance level of the request's
  authentication method is at or above the required minimum, per a single ordered
  mapping of methods to levels defined once at the edge.

The comparison SHALL be fail-closed: a requirement signal present with the
corresponding enrichment absent or unparseable SHALL be rejected (403), never
passed through. A 403 from this step SHALL NOT reach the backend.

#### Scenario: Satisfied requirements pass to the backend
- **WHEN** the resolved rule requires role `admin` and the authenticated user's
  injected roles include `admin`
- **THEN** the request SHALL proceed to the backend unchanged

#### Scenario: Missing role is rejected
- **WHEN** the resolved rule requires role `admin` and the authenticated user's
  injected roles do not include it
- **THEN** the edge SHALL reject the request with 403 and the backend SHALL NOT
  receive it

#### Scenario: Missing entitlement is rejected (plan gate)
- **WHEN** the resolved rule requires entitlement `pro` and the user's injected
  entitlements do not include it
- **THEN** the edge SHALL reject the request with 403

#### Scenario: Insufficient assurance level is rejected
- **WHEN** the resolved rule requires a minimum assurance level above the level
  mapped to the request's authentication method
- **THEN** the edge SHALL reject the request with 403

#### Scenario: Requirement with absent enrichment fails closed
- **WHEN** a requirement signal is present but the corresponding enrichment header
  was not injected (e.g. enrichment skipped or degraded)
- **THEN** the edge SHALL reject the request with 403 rather than pass it through

### Requirement: Authorization requirements imply authentication

A rule that sets any requirement field SHALL be treated as requiring a verified
credential. The policy write surface SHALL reject, at write time, a rule that
combines a requirement field with `auth_required = false`. An unauthenticated
request on a route whose rule carries requirements SHALL receive the
authentication outcome (401), not 403, so the gate never discloses authorization
policy to anonymous callers.

#### Scenario: Inconsistent rule is rejected at write time
- **WHEN** a tenant submits a rule with `requires_entitlement` set and
  `auth_required = false`
- **THEN** the policy write SHALL be rejected with a structured validation error
  and no rule SHALL be stored

#### Scenario: Anonymous caller gets 401, not 403
- **WHEN** a request with no credential targets a route whose rule requires a role
- **THEN** the edge SHALL reject it as unauthenticated (401) exactly as on any
  protected route

## MODIFIED Requirements

### Requirement: The trusted header family is unforgeable by clients

The edge SHALL strip every client-supplied trusted header before its authoritative
value is produced by a trusted stage, so a client cannot self-assert any of them.
This family includes the per-route auth signals (`x-auth-required`,
`x-auth-requires-role`, `x-auth-requires-entitlement`, `x-auth-min-aal`), the
acting-scope headers (`x-workspace-id`, and any `x-requested-workspace` hint is
treated as non-authoritative), the identity headers (`x-user-*`, including
`x-user-type` and `x-user-role`), and the identity-contract stamp
(`x-identity-contract`). A client MAY hint a desired workspace but SHALL NOT be
able to assert the authoritative scope, the contract version, or any per-route
policy signal.

#### Scenario: Client-supplied auth signal is discarded
- **WHEN** an inbound request carries a client-set `x-auth-required` header
- **THEN** the edge SHALL remove it before the tenant-routing stage emits the
  authoritative value, and the client value SHALL have no effect on the gate

#### Scenario: Client-supplied requirement signal is discarded
- **WHEN** an inbound request carries a client-set `x-auth-requires-role`,
  `x-auth-requires-entitlement`, or `x-auth-min-aal` header
- **THEN** the edge SHALL remove it before the tenant-routing stage emits the
  authoritative values, so a client can neither add nor suppress a requirement

#### Scenario: Client-supplied acting-scope is discarded
- **WHEN** an inbound request carries a client-set `x-workspace-id`, `x-user-type`,
  `x-user-role`, or other `x-user-*` header
- **THEN** the edge SHALL remove it before the identity plane resolves membership,
  and only the nexus-produced authoritative values SHALL reach the backend

#### Scenario: Client-supplied contract stamp is discarded
- **WHEN** an inbound request carries a client-set `x-identity-contract` header
- **THEN** the edge SHALL remove it before the identity plane stamps the authoritative
  version, so a client can neither forge a contract version nor mask a bypass of the
  edge enrichment
