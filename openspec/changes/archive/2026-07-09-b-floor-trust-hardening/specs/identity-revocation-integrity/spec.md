## ADDED Requirements

### Requirement: Revocation-sensitive signals are nexus-authored and unforgeable

The revocation-sensitive signals (`x-user-entitlements`, `x-user-suspended`) SHALL be authenticated as nexus-authored, so a box can reject a value a client or on-path party set or altered rather than trusting it solely because of the network path it arrived on. A party other than nexus SHALL be unable to fabricate a value that a box accepts as authentic. This closes the gap in which the signals that decide *"is this user cut off right now"* rode bare, unsigned trust while less-sensitive identity claims were protected.

#### Scenario: A box accepts a genuine nexus-authored revocation signal

- **WHEN** a box receives an enriched request whose entitlement/suspension signal was authored by nexus
  and carries valid nexus authentication material
- **THEN** the box SHALL accept the signal as authentic and MAY act on it (e.g. deny a suspended user)

#### Scenario: A forged or altered revocation signal is rejected

- **WHEN** a client or on-path party sets or alters `x-user-entitlements` / `x-user-suspended` on a
  request reaching a box
- **THEN** the box SHALL detect that the signal is not nexus-authored and SHALL NOT trust the altered
  value — it SHALL fall back to a safe decision rather than honoring the forged value

### Requirement: Revocation signals remain fresh within a bounded window

The authentication of the revocation-sensitive signals SHALL NOT weaken their freshness: a box SHALL
be able to trust that an accepted entitlement/suspension signal reflects a nexus revocation decision no
older than an explicitly bounded window. The mechanism SHALL NOT introduce a staleness window larger
than that bound, so that a user suspended by nexus stops being honored by boxes within the bound —
preserving the liveness that is the entire reason these signals were left out of the long-lived signed
identity contract.

#### Scenario: A freshly suspended user is cut off within the bound

- **WHEN** nexus marks a user suspended and a box subsequently receives a request for that user
- **THEN** the box SHALL observe the suspension within the bounded freshness window, rather than
  honoring a captured or cached "not suspended" signal past that window

#### Scenario: A captured authenticated signal cannot be replayed indefinitely

- **WHEN** a party captures a previously valid, nexus-authored "entitled / not suspended" signal and
  replays it after the freshness bound has elapsed
- **THEN** the box SHALL treat the replayed signal as stale and SHALL NOT act on it as if current
