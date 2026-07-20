# on-demand-certificate-lifecycle

## Purpose

The end-to-end lifecycle contract for on-demand customer-domain certificates: obtain on first need for
an authorized hostname (no static pre-provisioning), reuse thereafter, renew ahead of expiry without
consuming net-new issuance budget, keep serving already-provisioned hostnames through an issuer
outage, and fail the handshake closed for any hostname without a valid authorized certificate. This
spec is language-agnostic and states only the observable behavior.

## Requirements

### Requirement: A certificate is obtained on first need for an authorized hostname

The system SHALL obtain a valid public TLS certificate for a customer hostname on first need —
when live TLS is first negotiated for an authorized hostname that has no usable stored certificate —
without that hostname having been pre-provisioned in any static certificate list. Once obtained, the
certificate SHALL be reused for subsequent connections rather than re-obtained per connection.

#### Scenario: First connection for an authorized domain obtains then serves
- **WHEN** live TLS is first negotiated for an authorized hostname that has no usable stored
  certificate
- **THEN** the system SHALL obtain a certificate for that hostname and complete the connection with it

#### Scenario: Later connections reuse the stored certificate
- **WHEN** a subsequent connection is negotiated for a hostname whose valid certificate is already
  stored
- **THEN** the system SHALL serve the stored certificate and SHALL NOT initiate a new issuance

### Requirement: Certificates are renewed ahead of expiry without consuming net-new issuance budget

The system SHALL renew each certificate automatically before it expires, and the renewal path SHALL
NOT consume the same finite budget that governs first-time issuance of net-new hostnames, so that
steady-state renewal of a large certificate population cannot be throttled by first-issuance limits.

#### Scenario: A certificate nearing expiry is renewed in advance
- **WHEN** a stored certificate approaches its expiry threshold
- **THEN** the system SHALL obtain a replacement before the certificate expires, with no interruption
  to serving the affected hostname

#### Scenario: Renewal at population scale is not throttled by first-issuance limits
- **WHEN** a large population of certificates renews over time while first-time issuance budget for
  net-new hostnames is near its limit
- **THEN** renewals SHALL continue to complete and SHALL NOT be blocked by the net-new issuance limit

### Requirement: Existing certificates keep serving through an issuing-component outage

The system SHALL continue to serve every hostname that already has a valid stored certificate even
while the issuing component is unavailable; an issuance outage SHALL degrade only the onboarding of
brand-new hostnames, never live traffic for already-provisioned ones.

#### Scenario: Issuer down, existing domain still served
- **WHEN** the issuing component is unavailable and a connection arrives for a hostname with a valid
  stored certificate
- **THEN** the system SHALL complete the TLS connection from the stored certificate

#### Scenario: Issuer down, brand-new domain onboarding defers
- **WHEN** the issuing component is unavailable and a first connection arrives for an authorized
  hostname with no stored certificate
- **THEN** onboarding of that hostname SHALL fail or defer without affecting any already-provisioned
  hostname

### Requirement: A hostname without a valid, authorized certificate fails the handshake closed

The system SHALL refuse the TLS handshake for any hostname that has no valid, authorized certificate
rather than present a default, catch-all, self-signed, or mismatched certificate.

#### Scenario: Unresolvable hostname is not served a fallback certificate
- **WHEN** live TLS is negotiated for a hostname that is not authorized and has no valid stored
  certificate
- **THEN** the system SHALL refuse the handshake and SHALL NOT present a default, catch-all,
  self-signed, or otherwise mismatched certificate
