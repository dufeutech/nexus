## MODIFIED Requirements

### Requirement: The identity enrichment is stamped with a versioned contract

The identity plane SHALL stamp every enriched request with an `x-identity-contract`
header carrying the version of the edge→backend identity-header contract it emits
(e.g. `v1`). On a route designated as identity-enriched, the backend SHALL require an
`x-identity-contract` value it understands and reject any request whose value is absent or
unrecognized. This is the single coordination gate for the whole `x-workspace-*`/`x-user-*`
header family: any drift in that family's shape (a rename, a removed/added field, a changed
meaning) is a version bump, so a partially-deployed contract change fails closed instead of
feeding the backend headers it silently misreads.

The stamp is a **version/drift-coordination signal, NOT an authentication or anti-bypass
boundary.** It is an unsigned, well-known constant that the edge strips-and-re-emits;
therefore its presence SHALL NOT be treated as proof that a request originated at the edge.
The guarantee that a request cannot bypass the edge and present its own scope headers is
provided by `edge-origin-trust` origin enforcement, NOT by this stamp. Specs and design docs
SHALL NOT describe the stamp as detecting or preventing edge bypass.

The acting-scope guarantee is PART of the versioned contract, not a separate sentinel:
a well-formed `vN` request SHALL carry the authoritative acting `x-workspace-id`
(and `x-user-type`), so a same-version request missing the acting scope is not a valid
`vN` request and the backend SHALL reject it. There is NO standalone acting-scope
marker header.

Routes that intentionally skip identity enrichment (public, degradable, or anonymous routes)
are designated **non-enriched** and reach the backend without a stamp by design. This
designation is **fail-closed by default**: a route SHALL be treated as identity-enriched
unless it is *explicitly* designated non-enriched, so a route that is omitted from the
non-enriched designation — a config gap, a typo, or enrichment silently disabled for it —
inherits the enriched "reject an absent stamp" rule rather than being served anonymously.
The "reject an absent stamp" rule therefore applies to every route not explicitly designated
non-enriched; only on an explicitly non-enriched route SHALL the backend treat a request
bearing no identity attribution as anonymous per the route's auth policy, and SHALL NOT
reject it merely for a missing stamp. A request that presents any authoritative identity
attribution (`x-user-*`, or `x-workspace-id` in its acting-scope role — i.e. accompanied by
`x-user-type`) SHALL always be required to carry a valid stamp, on any route. A non-enriched
route that is still tenant-routed MAY carry the routing plane's re-authored `x-workspace-id`
tenant context without a stamp — that value is routing context (trusted-emitted, client copies
stripped), not identity attribution, and grants no acting scope.

`x-identity-contract` is trusted-emitted and therefore MUST be stripped from client
input at the edge (the same C3 rule that makes `x-auth-required`/`x-workspace-id`
unforgeable), so a client cannot forge a version through the edge.

#### Scenario: Backend rejects a stale or absent contract version on an enriched route

- **WHEN** a request reaches the backend on an identity-enriched route with `x-identity-contract`
  absent, or set to a version the backend does not accept (e.g. the edge still emits `v1`
  after the backend moved to require `v2`)
- **THEN** the backend SHALL reject the request rather than interpret the identity
  headers under an assumed shape

#### Scenario: A public (non-enriched) route is not rejected for a missing stamp

- **WHEN** a request reaches the backend on a route where identity enrichment is intentionally
  disabled, carrying no `x-identity-contract` and no `x-user-*` identity attribution (at most
  the routing plane's re-authored `x-workspace-id` tenant context)
- **THEN** the backend SHALL handle it as anonymous per the route's auth policy and SHALL NOT
  reject it solely because the stamp is absent

#### Scenario: An undesignated route fails closed rather than serving anonymously

- **WHEN** a route is neither reached by identity enrichment nor *explicitly* designated
  non-enriched (e.g. it was omitted from the non-enriched list, or enrichment was disabled
  for it by a config error), and a request arrives on it carrying no `x-identity-contract`
- **THEN** the backend SHALL reject the request as it would on any identity-enriched route,
  and SHALL NOT serve it as anonymous, because non-enriched status is granted only by
  explicit designation

#### Scenario: Version bump gates a breaking header rename

- **WHEN** the `x-workspace-*`/`x-user-*` header shape changes (e.g. a field rename) and
  only one side of edge/backend has been rolled out
- **THEN** the contract version emitted by the edge and the version required by the
  backend SHALL NOT match, and the request SHALL fail closed until both sides are
  rolled to the same version

#### Scenario: A client-supplied stamp is stripped at the edge

- **WHEN** an inbound request carries a client-set `x-identity-contract`
- **THEN** the edge SHALL strip the client-supplied value before the trusted stage emits
  the authoritative one, so no client value reaches the backend

#### Scenario: Preventing edge bypass is delegated to origin enforcement

- **WHEN** a party attempts to reach the backend without traversing the edge, presenting its
  own `x-identity-contract` and scope headers
- **THEN** that request SHALL be stopped by `edge-origin-trust` origin enforcement (the
  backend being unreachable off-edge), and the system SHALL NOT rely on the stamp's presence
  or absence to detect the bypass
