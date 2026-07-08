## ADDED Requirements

### Requirement: A hostname resolves by exact match first, then a single-label wildcard, else no-tenant

The system SHALL resolve an inbound hostname to a workspace by first attempting an **exact** domain
match and, only on a miss, a **single-label wildcard** match against the hostname's immediate parent
domain; if neither matches, resolution SHALL fail closed as "no tenant" and SHALL NOT fall back to a
default or catch-all workspace. The hostname SHALL be canonicalized (lowercased, trailing dot and
port stripped, non-conforming hosts rejected) before either lookup, so both lookups key off the same
canonical form.

#### Scenario: Exact host resolves
- **WHEN** a request arrives for a hostname that has an exact (non-wildcard) domain row
- **THEN** the system SHALL resolve it to that row's workspace

#### Scenario: Subdomain resolves via its parent's wildcard
- **WHEN** a request arrives for `app.example.com`, there is no exact row for `app.example.com`, and
  a wildcard row exists for the parent `example.com`
- **THEN** the system SHALL resolve `app.example.com` to the wildcard row's workspace

#### Scenario: No match fails closed
- **WHEN** a request arrives for a hostname with neither an exact row nor a matching parent wildcard
  row
- **THEN** the system SHALL refuse to resolve a tenant and SHALL NOT substitute a default workspace

#### Scenario: A non-conforming host is rejected before lookup
- **WHEN** a request arrives whose hostname is empty, contains an empty label, control characters,
  whitespace, or non-ASCII bytes
- **THEN** the system SHALL treat it as no-match and SHALL NOT resolve a tenant

### Requirement: The apex and its wildcard are independent and coexist

The system SHALL treat the apex (an exact row for a registered domain) and the wildcard (a
wildcard row for that same domain, covering its subdomains) as **independent** entries that MAY
both exist for the same domain string, and a wildcard row SHALL NOT match the apex hostname itself.
This aligns with TLS-certificate wildcard semantics (a `*.example.com` certificate does not cover
`example.com`) rather than DNS multi-label wildcard synthesis.

#### Scenario: Apex and wildcard route to their own workspaces
- **WHEN** `example.com` has both an exact row (workspace A) and a wildcard row (workspace B), and
  requests arrive for `example.com` and for `shop.example.com`
- **THEN** the system SHALL resolve `example.com` to workspace A and `shop.example.com` to
  workspace B

#### Scenario: A wildcard alone does not answer the apex
- **WHEN** `example.com` has only a wildcard row (no exact row) and a request arrives for the apex
  `example.com`
- **THEN** the system SHALL NOT resolve the apex via the wildcard, and resolution SHALL fail closed

### Requirement: A more specific match wins over a wildcard

The system SHALL prefer the most specific matching row: an exact row for a hostname SHALL take
precedence over any wildcard row that would otherwise cover that hostname.

#### Scenario: Exact subdomain beats a covering wildcard
- **WHEN** both an exact row for `shop.example.com` (workspace A) and a wildcard row for
  `example.com` (workspace B) exist, and a request arrives for `shop.example.com`
- **THEN** the system SHALL resolve `shop.example.com` to workspace A, not workspace B

### Requirement: Wildcard matching is single-label only

The system SHALL match a wildcard row only against hostnames exactly **one label** below the
wildcard's domain; a wildcard SHALL NOT match hostnames nested two or more labels below it. Coverage
of a deeper subdomain SHALL require its own row (exact, or a wildcard at that deeper parent). This
keeps routing consistent with per-host TLS certificate issuance, which is single-label.

#### Scenario: Wildcard does not match a nested subdomain
- **WHEN** a wildcard row exists for `example.com` and a request arrives for `a.b.example.com` (two
  labels below), with no row for `b.example.com`
- **THEN** the system SHALL NOT resolve `a.b.example.com` via the `example.com` wildcard, and
  resolution SHALL fail closed

#### Scenario: A deeper wildcard covers its own single-label children
- **WHEN** a wildcard row exists for `b.example.com` and a request arrives for `a.b.example.com`
- **THEN** the system SHALL resolve `a.b.example.com` to the `b.example.com` wildcard row's workspace

### Requirement: Routing and cert authorization resolve the identical host set

The system SHALL resolve hostnames for on-demand certificate authorization using the **same**
matching predicate as request routing, so that the set of hostnames the certificate gate authorizes
is exactly the set the router will route. There SHALL be exactly one canonical host matcher; the
certificate-authorization surface SHALL NOT implement its own, divergent host-matching logic.

#### Scenario: The cert gate authorizes exactly what the router routes
- **WHEN** a hostname resolves to a workspace under the routing predicate
- **THEN** the certificate-authorization gate SHALL authorize that hostname; and **WHEN** a hostname
  does not resolve under the routing predicate, the gate SHALL deny it

#### Scenario: A wildcard-covered subdomain is authorized for a certificate
- **WHEN** `shop.example.com` has no exact row but resolves via the `example.com` wildcard row
- **THEN** the certificate-authorization gate SHALL authorize `shop.example.com`, matching the fact
  that the router will route it
