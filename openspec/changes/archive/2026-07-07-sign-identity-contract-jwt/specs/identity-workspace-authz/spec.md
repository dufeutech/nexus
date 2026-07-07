## MODIFIED Requirements

### Requirement: The identity enrichment is stamped with a versioned contract

The identity plane SHALL stamp every enriched request with an `x-identity-contract`
header whose value is a **signed assertion** minted by the identity plane (a self-contained,
cryptographically signed token). The assertion SHALL carry the version of the edge→backend
identity-header contract it emits as a claim inside the token (superseding the former
plain-string value such as `v1`). On a route designated as identity-enriched, the backend
SHALL require a **valid** `x-identity-contract` assertion — one whose signature verifies
against the identity plane's published verification keys and whose embedded contract version
it understands — and SHALL reject any request whose assertion is absent, fails verification,
or carries an unrecognized version. This is the single coordination gate for the whole
`x-workspace-*`/`x-user-*` header family: any drift in that family's shape (a rename, a
removed/added field, a changed meaning) is a version bump, so a partially-deployed contract
change fails closed instead of feeding the backend headers it silently misreads.

The assertion is BOTH a version/drift-coordination signal AND a **verifiable proof that the
enrichment was authored by nexus.** Because it is signed with a key only nexus holds, a
backend that verifies it can detect a forged or self-authored value that a plain-string
stamp could not. This verification is **defense-in-depth layered on top of, and does NOT
replace,** `edge-origin-trust` origin enforcement: origin enforcement remains the
deployment's primary anti-bypass control, and a conformant deployment SHALL NOT relax it on
the grounds that the assertion is signed. The signature capability, key publication, and
rotation are owned by the `identity-contract-signing` capability and are not restated here.

The acting-scope guarantee is PART of the versioned contract, not a separate sentinel:
a well-formed assertion SHALL carry the authoritative acting `x-workspace-id`
(and `x-user-type`), so a valid-version assertion missing the acting scope is not a valid
request and the backend SHALL reject it. There is NO standalone acting-scope
marker header.

Routes that intentionally skip identity enrichment (public, degradable, or anonymous routes)
are designated **non-enriched** and reach the backend without an assertion by design. This
designation is **fail-closed by default**: a route SHALL be treated as identity-enriched
unless it is *explicitly* designated non-enriched, so a route that is omitted from the
non-enriched designation — a config gap, a typo, or enrichment silently disabled for it —
inherits the enriched "reject an absent assertion" rule rather than being served anonymously.
The "reject an absent assertion" rule therefore applies to every route not explicitly designated
non-enriched; only on an explicitly non-enriched route SHALL the backend treat a request
bearing no identity attribution as anonymous per the route's auth policy, and SHALL NOT
reject it merely for a missing assertion. A request that presents any authoritative identity
attribution (`x-user-*`, or `x-workspace-id` in its acting-scope role — i.e. accompanied by
`x-user-type`) SHALL always be required to carry a valid assertion, on any route. A non-enriched
route that is still tenant-routed MAY carry the routing plane's re-authored `x-workspace-id`
tenant context without an assertion — that value is routing context (trusted-emitted, client copies
stripped), not identity attribution, and grants no acting scope.

`x-identity-contract` is trusted-emitted and therefore MUST be stripped from client
input at the edge (the same C3 rule that makes `x-auth-required`/`x-workspace-id`
unforgeable), so a client cannot inject its own assertion; and because a client cannot
produce a valid signature, any forged assertion that nonetheless reaches a backend still
fails signature verification.

#### Scenario: Backend rejects an absent, unverifiable, or stale contract on an enriched route

- **WHEN** a request reaches the backend on an identity-enriched route with `x-identity-contract`
  absent, failing signature verification, or carrying a contract version the backend does not
  accept (e.g. the edge still emits version 1 after the backend moved to require version 2)
- **THEN** the backend SHALL reject the request rather than interpret the identity
  headers under an assumed shape

#### Scenario: Backend rejects an assertion whose signature does not verify

- **WHEN** a request reaches the backend on an identity-enriched route carrying an
  `x-identity-contract` value that does not verify against the identity plane's published
  verification keys (tampered, self-authored, or signed by an unknown key)
- **THEN** the backend SHALL reject the request and SHALL NOT treat the conveyed identity
  as authoritative

#### Scenario: A public (non-enriched) route is not rejected for a missing assertion

- **WHEN** a request reaches the backend on a route where identity enrichment is intentionally
  disabled, carrying no `x-identity-contract` and no `x-user-*` identity attribution (at most
  the routing plane's re-authored `x-workspace-id` tenant context)
- **THEN** the backend SHALL handle it as anonymous per the route's auth policy and SHALL NOT
  reject it solely because the assertion is absent

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
- **THEN** the contract version carried in the assertion and the version required by the
  backend SHALL NOT match, and the request SHALL fail closed until both sides are
  rolled to the same version

#### Scenario: A client-supplied assertion is stripped at the edge

- **WHEN** an inbound request carries a client-set `x-identity-contract`
- **THEN** the edge SHALL strip the client-supplied value before the trusted stage emits
  the authoritative one, so no client value reaches the backend

#### Scenario: Preventing edge bypass is delegated to origin enforcement

- **WHEN** a party attempts to reach the backend without traversing the edge, presenting its
  own `x-identity-contract` and scope headers
- **THEN** that request SHALL be stopped by `edge-origin-trust` origin enforcement (the
  backend being unreachable off-edge); a backend that additionally verifies the assertion
  SHALL find the forged value fails signature verification, but the deployment SHALL NOT
  rely on the signature in place of origin enforcement as the primary anti-bypass control
