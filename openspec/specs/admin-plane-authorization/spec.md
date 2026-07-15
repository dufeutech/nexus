# admin-plane-authorization

## Purpose

Authorize every action on the platform's admin surface against the authenticated
actor's **granted scopes** — deny-by-default and fail-closed — so a leaked or
over-broad admin credential's blast radius is bounded by its grant rather than
equaling the whole control plane. Credential administration is a distinguished
privilege (no ordinary grant can mint or destroy credentials), grants are explicit
at provisioning and reviewable afterward, the plane cannot lock itself out of
credential administration, and introducing authorization preserves every caller
that existed at cutover. Composes with `admin-action-audit` (attribution and the
denial ledger) and consumes the platform's L2 decision contract
(`authorization-policy-engine`) at a second enforcement surface.

## Requirements

### Requirement: Every admin action is authorized against the actor's grant, deny-by-default

The system SHALL authorize every admin action after the actor is authenticated and before the action executes, by evaluating the actor's granted scopes against the action's required scope, and SHALL deny any action the actor's grant does not explicitly permit. Authentication and authorization SHALL remain distinct outcomes: a request that fails authentication is rejected as unauthenticated, and an authenticated request without the required grant is rejected as unauthorized, without executing any part of the action.

#### Scenario: A granted action executes

- **WHEN** an authenticated actor whose grant includes an action's required scope invokes that action
- **THEN** the action executes exactly as it would have before grants existed

#### Scenario: An ungranted action is refused before execution

- **WHEN** an authenticated actor whose grant lacks an action's required scope invokes that action
- **THEN** the action is refused as unauthorized, no part of its effect occurs, and the refusal carries a machine-readable reason

#### Scenario: Authentication is still evaluated first

- **WHEN** a request presents a missing or invalid credential
- **THEN** it is rejected as unauthenticated, exactly as before, and no authorization evaluation is observable in the outcome

#### Scenario: Explicitly disabled admin auth bypasses authorization identically

- **WHEN** the admin gate is explicitly disabled at startup (the trusted-network/dev posture)
- **THEN** requests pass through without authorization checks, exactly as they pass authentication, and are attributed to the reserved disabled-auth actor

### Requirement: Authorization is fail-closed

The system SHALL deny an admin action whenever a decision input is missing or unusable: an actor whose grant cannot be resolved, an action with no declared required scope, or a policy set that failed to load or validate SHALL each yield a denial, never a permissive default. A degraded or partial input SHALL never produce a permit that a complete input would not.

#### Scenario: An unresolvable grant denies

- **WHEN** an authenticated actor's grant cannot be resolved at decision time
- **THEN** the action is refused as unauthorized rather than assumed granted

#### Scenario: An action without a declared required scope denies

- **WHEN** an admin action reachable on the gated surface has no declared required scope
- **THEN** invoking it is refused for every actor, regardless of grant

#### Scenario: A failed policy load denies all gated actions

- **WHEN** the policy set fails to load or validate at startup
- **THEN** every gated admin action is denied until a valid policy set is in place, while liveness endpoints outside the gate remain reachable

### Requirement: Credential administration is a distinguished privilege

The system SHALL gate the administration of admin credentials — creating, revoking, and enumerating them — behind a dedicated scope that no other scope includes, so an actor without that scope cannot expand its own grant, create new credentials, or destroy existing ones.

#### Scenario: An ordinary grant cannot mint credentials

- **WHEN** an actor whose grant lacks the credential-administration scope attempts to create a new admin credential
- **THEN** the attempt is refused as unauthorized and no credential comes into existence

#### Scenario: An ordinary grant cannot revoke credentials

- **WHEN** an actor whose grant lacks the credential-administration scope attempts to revoke an existing credential
- **THEN** the attempt is refused as unauthorized and the target credential remains valid

#### Scenario: The credential-administration scope permits credential administration

- **WHEN** an actor whose grant includes the credential-administration scope creates or revokes a credential
- **THEN** the operation succeeds and is recorded with the acting credential's identity

### Requirement: Grants are explicit at provisioning and visible afterward

The system SHALL require an explicit, non-empty scope set when a new admin credential is provisioned — refusing an unscoped request rather than defaulting it — and SHALL make each credential's granted scopes readable to authorized reviewers alongside the credential's identity.

#### Scenario: An unscoped provisioning request is refused

- **WHEN** a credential-provisioning request names no scopes
- **THEN** the request is rejected as invalid and no credential is created

#### Scenario: A credential's grant is reviewable

- **WHEN** an authorized reviewer enumerates admin credentials
- **THEN** each credential's granted scopes are visible with its identity, without exposing any secret material

### Requirement: The last credential administrator cannot be removed

The system SHALL refuse a revocation or grant change that would leave zero active credentials holding the credential-administration scope, so the admin plane cannot lock itself out of credential administration.

#### Scenario: Revoking the final credential administrator is refused

- **WHEN** a revocation targets the only active credential holding the credential-administration scope
- **THEN** the revocation is refused with a reason identifying the lockout hazard, and the credential remains active

### Requirement: Cutover preserves existing callers

The system SHALL grant every credential that exists at cutover the full scope set, so no previously working admin caller is refused by the introduction of authorization; narrowing a grant SHALL only ever be an explicit operator act.

#### Scenario: A pre-existing credential keeps working at cutover

- **WHEN** the authorization gate first activates over credentials provisioned before grants existed
- **THEN** every action those credentials could previously perform still succeeds

#### Scenario: Narrowing takes effect only when performed

- **WHEN** an operator explicitly narrows a credential's grant
- **THEN** subsequent actions outside the narrowed grant are refused, and actions within it continue to succeed
