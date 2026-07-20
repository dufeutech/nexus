# certificate-issuance-authorization

## Purpose

The contract that gates on-demand certificate issuance behind an explicit authorization decision:
a certificate is obtained for a hostname only if that hostname is approved, the approval is resolved
through the same shared host matcher that request routing uses (owned by `domain-host-resolution`),
and refusals are remembered so a flood of unknown hostnames cannot drive unbounded issuance. This
spec is language-agnostic and states only the observable behavior.

## Requirements

### Requirement: Certificate issuance is gated by an explicit authorization decision

The system SHALL obtain a certificate for a hostname only after an explicit authorization decision
approves that hostname, and SHALL NOT initiate issuance for any hostname the decision does not
approve. The absence of an approval SHALL be treated as a refusal, not as a default-allow.

#### Scenario: Authorized hostname proceeds to issuance
- **WHEN** an issuance is attempted for a hostname the authorization decision approves
- **THEN** the system SHALL proceed to obtain a certificate for that hostname

#### Scenario: Unapproved hostname is refused before any issuance
- **WHEN** live TLS is negotiated for a hostname the authorization decision does not approve
- **THEN** the system SHALL refuse and SHALL NOT initiate any certificate-issuance order for it

### Requirement: The issuance gate resolves the identical host set as request routing

The system SHALL make the issuance authorization decision through the same shared host matcher that
request routing uses (owned by `domain-host-resolution`), so a certificate is authorized for a
hostname if and only if routing would resolve that hostname to a tenant. Issuance authorization and
routing SHALL NOT diverge on which hostnames are recognized.

#### Scenario: A routable hostname is authorized for issuance
- **WHEN** a hostname resolves to a tenant under the shared matcher
- **THEN** issuance for that hostname SHALL be authorized

#### Scenario: A non-routable hostname is refused issuance
- **WHEN** a hostname fails to resolve to any tenant under the shared matcher
- **THEN** issuance for that hostname SHALL be refused, matching routing's fail-closed outcome

### Requirement: Refusals are remembered to bound issuance attempts under load

The system SHALL remember a negative authorization outcome for a bounded interval so that repeated
connections for the same unapproved hostname do not each trigger a fresh issuance attempt, ensuring a
flood of unknown hostnames cannot drive unbounded issuance work or exhaust issuance budget.

#### Scenario: Repeated unknown-hostname connections do not each attempt issuance
- **WHEN** many connections arrive in succession for the same unapproved hostname
- **THEN** the system SHALL serve the remembered refusal without initiating a new issuance attempt
  for each connection

#### Scenario: Unknown-hostname flood cannot exhaust issuance budget
- **WHEN** a large volume of connections arrives for many distinct unapproved hostnames
- **THEN** the number of issuance orders placed SHALL remain bounded and SHALL NOT consume the
  issuance budget reserved for approved hostnames
