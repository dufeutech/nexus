# edge-trusted-header-strip

## Purpose

Guarantees that the trusted-family header namespace — the headers a box is entitled to
treat as nexus-authored — cannot be forged from client input. The edge default-drops
every client-supplied trusted-family header and admits one only by explicit allowlist,
so completeness never depends on maintaining a denylist of names to remove. A newly
introduced trusted header that nobody has enumerated is dropped by default rather than
passed through to a box.

## Requirements

### Requirement: Client-supplied trusted-family headers are admitted only by explicit allowlist

The edge SHALL default-drop every client-supplied header in the trusted family — the header namespace
a box is entitled to treat as nexus-authored — and SHALL forward such a header from client input only
when it appears on an explicit allowlist of headers a client is permitted to hint. Completeness SHALL
NOT depend on maintaining a denylist of names to remove: a trusted-family header that no one has
enumerated SHALL be dropped by default rather than passed through. The edge remains free to author
trusted headers itself after the strip; this requirement governs only what survives from client input.

#### Scenario: An un-enumerated trusted-family header from a client is dropped

- **WHEN** a client sends a request bearing a trusted-family header that is not on the client-hint
  allowlist (including a newly introduced one nobody has explicitly handled)
- **THEN** the edge SHALL strip it before the request reaches identity enrichment or any box, so the
  box never observes a client-forged value

#### Scenario: An explicitly allowed client hint survives

- **WHEN** a client sends a header that is on the allowlist of permitted client hints
- **THEN** the edge SHALL forward it, so intended client hints continue to work

#### Scenario: A nexus-authored trusted header is unaffected by the strip

- **WHEN** the edge authors a trusted-family header during enrichment after the client-input strip
- **THEN** that nexus-authored value SHALL reach the box unchanged, because the default-drop applies to
  client input, not to values nexus itself sets
