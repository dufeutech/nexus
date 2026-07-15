# admin-action-audit (delta)

## MODIFIED Requirements

### Requirement: Denied admin access is recorded

The system SHALL record an audit event for every denied request on an admin surface — both a rejected authentication attempt and an authenticated action refused by authorization. An authentication denial SHALL carry the time, surface, source, and the fact that a credential was absent or invalid — without recording the presented credential material. An authorization denial SHALL carry the time, surface, source, the authenticated actor's identity, the attempted action, and the machine-readable decision reason. A failure to record a denial SHALL never convert the denial into an acceptance.

#### Scenario: A failed authentication leaves a trace

- **WHEN** a request with a missing or invalid credential is rejected by an admin surface
- **THEN** a denial event is recorded with time, surface, and source, and the presented credential value appears nowhere in it

#### Scenario: An authorization refusal leaves an attributed trace

- **WHEN** an authenticated actor's action is refused because its grant lacks the required scope
- **THEN** a denial event is recorded with time, surface, source, the actor's identity, the attempted action, and the decision reason

#### Scenario: A failed denial write stays a denial

- **WHEN** recording an authorization denial fails
- **THEN** the request remains refused and the recording failure is surfaced operationally
