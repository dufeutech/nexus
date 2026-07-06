## ADDED Requirements

### Requirement: Credentials are verified against a configured OIDC issuer, not a named vendor

The edge SHALL verify each presented credential against an OIDC issuer and its key
set identified entirely by configuration — the issuer identifier, the key-set
location, and the claim carrying the subject. No identity-provider vendor SHALL be
named in the trust contract; any conformant OIDC provider SHALL be selectable by
supplying this configuration alone, with no change to verification logic.

#### Scenario: Provider is selected by configuration

- **WHEN** an operator points the edge at a different conformant OIDC provider by
  supplying its issuer identifier and key-set location
- **THEN** the edge SHALL verify credentials issued by that provider and reject
  those it did not issue, with no code change and no vendor-specific setting

#### Scenario: Trust contract carries no vendor identity

- **WHEN** the edge's credential-verification configuration is inspected
- **THEN** the provider SHALL be referenced only by neutral configuration keys
  (issuer, key-set location, subject claim), and no requirement SHALL depend on a
  specific provider's name, product, or endpoints

### Requirement: Vendor-neutral configuration is the single source of the trust anchor

The issuer identifier and key-set location used to verify credentials SHALL be
defined once as configuration and referenced wherever verification occurs, so the
same trust anchor governs every verification point and a provider change is made in
exactly one place.

#### Scenario: One change repoints all verification

- **WHEN** the configured issuer or key-set location is changed in its single
  definition
- **THEN** every credential-verification point SHALL adopt the new value without any
  additional per-point edit, and no stale vendor-named anchor SHALL remain

#### Scenario: Verified behavior is unchanged by the neutral naming

- **WHEN** the trust anchor is expressed with vendor-neutral configuration while
  still pointing at the currently deployed provider
- **THEN** the set of credentials accepted and rejected SHALL be identical to the
  behavior before the configuration was made vendor-neutral
