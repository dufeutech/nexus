# edge-auth-gate

## MODIFIED Requirements

### Requirement: The trusted header family is unforgeable by clients

The edge SHALL strip every client-supplied trusted header before its authoritative
value is produced by a trusted stage, so a client cannot self-assert any of them.
This family includes the per-route auth signal (`x-auth-required`), the acting-scope
headers (`x-workspace-id`, and any `x-requested-workspace` hint is treated as
non-authoritative), the identity headers (`x-user-*`, including `x-user-type` and
`x-user-role`), and the identity-contract stamp (`x-identity-contract`). A client MAY
hint a desired workspace but SHALL NOT be able to assert the authoritative scope or the
contract version.

#### Scenario: Client-supplied auth signal is discarded
- **WHEN** an inbound request carries a client-set `x-auth-required` header
- **THEN** the edge SHALL remove it before the tenant-routing stage emits the
  authoritative value, and the client value SHALL have no effect on the gate

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
