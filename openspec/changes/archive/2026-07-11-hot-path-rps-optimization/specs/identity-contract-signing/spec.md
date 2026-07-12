## ADDED Requirements

### Requirement: A signed contract MAY be reused within a bounded freshness window

The identity plane MAY reuse a previously signed `x-identity-contract` for subsequent requests that convey an **identical resolved identity**, for a bounded reuse window that SHALL be shorter than the contract's own validity, instead of signing a new contract per request. Reuse SHALL NOT weaken any other guarantee of this capability: a reused contract SHALL still be authentic, audience-scoped, issuer-identified, unexpired, and reflect the current resolved identity facts. Because the same signed token may be emitted on more than one request, any per-request uniqueness token it carries (for example a `jti`) SHALL NOT be relied upon by a consumer as a per-request nonce; replay remains defeated by the audience and expiry bounds already required. Reuse SHALL be bounded so that a captured or reused contract is never served after its expiry, never served across a signing-key rotation, and never served once the identity facts it conveys have changed.

#### Scenario: Identical identity reuses one signed contract within the window

- **WHEN** two requests within the reuse window resolve to the same authenticated subject, acting workspace, role/authority, plan, and other contract-determining facts
- **THEN** the identity plane MAY stamp both with the same signed contract, and each stamped contract SHALL still verify as authentic, audience-scoped, and unexpired

#### Scenario: A reused contract is never served past its expiry

- **WHEN** the reuse window would extend use of a contract to a point at or beyond its expiry
- **THEN** the identity plane SHALL mint a fresh contract instead, so no request is ever stamped with an expired or about-to-expire contract

#### Scenario: Changed identity facts are not served a stale contract

- **WHEN** a fact that determines the contract (for example membership, role, plan, suspension, or revocation) changes for a subject
- **THEN** a request for that subject after the change SHALL be stamped with a contract reflecting the new facts, not a reused contract carrying the old facts

#### Scenario: Reuse never crosses a signing-key rotation

- **WHEN** the signing key is rotated
- **THEN** contracts signed by the superseded key SHALL NOT be reused after the cut-over, so every stamped contract is signed by a currently-active key

#### Scenario: A consumer does not depend on per-request contract uniqueness

- **WHEN** a backend receives two enriched requests carrying the same reused contract (identical `jti`/issued-at/expiry)
- **THEN** it SHALL still accept each as authentic on audience and expiry, and SHALL NOT treat the repeated `jti` as a replay or an error
