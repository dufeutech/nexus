## ADDED Requirements

### Requirement: Authorization decisions are computed from declarative policy, deny-by-default

The platform SHALL decide authorization by evaluating a request's principal, action, resource, and context against a set of declarative policies, and SHALL return a decision of permit or deny. The decision SHALL be **deny-by-default**: a request that no policy explicitly permits SHALL be denied. Enforcement surfaces SHALL obtain their authorization outcome from this decision rather than by comparing individual attributes ad hoc.

#### Scenario: An explicitly permitted request is allowed

- **WHEN** a request's (principal, action, resource, context) satisfies a policy that permits it
- **THEN** the decision SHALL be permit and the enforcing surface SHALL allow the request

#### Scenario: A request no policy permits is denied

- **WHEN** a request matches no policy that permits it
- **THEN** the decision SHALL be deny, even if no policy explicitly forbids it (deny-by-default)

#### Scenario: An explicit forbid overrides a permit

- **WHEN** a request is permitted by one policy but forbidden by another
- **THEN** the decision SHALL be deny (a forbid is never overridden by a permit)

### Requirement: The decision is fail-closed on missing or unparseable input

The decision SHALL be fail-closed: when a required decision input (a principal attribute, a resolved requirement, or context) is absent or cannot be parsed, the engine SHALL deny rather than skip the check or assume a permissive default. A degraded or partial input SHALL never produce a permit that a complete input would not.

#### Scenario: A required attribute is absent

- **WHEN** a policy's permit depends on an attribute that is absent from the request's inputs
- **THEN** the decision SHALL be deny, not a pass-through

#### Scenario: An input cannot be parsed

- **WHEN** a decision input is present but malformed/unparseable
- **THEN** the engine SHALL treat it as unsatisfied and deny, never permit on the unparseable value

### Requirement: Each decision carries an auditable reason

The engine SHALL, alongside each permit/deny outcome, produce a machine-readable reason identifying which policy (or the absence of any permitting policy) determined the outcome, so a decision can be audited and explained after the fact. The reason SHALL NOT require re-running the request to reconstruct why it was allowed or denied.

#### Scenario: A deny is explainable

- **WHEN** a request is denied
- **THEN** the decision SHALL carry a reason indicating that no policy permitted it (or which policy forbade it), sufficient to audit the outcome

#### Scenario: A permit identifies its basis

- **WHEN** a request is permitted
- **THEN** the decision SHALL carry a reason identifying the permitting policy

### Requirement: Policy is data, changeable without a code change

Authorization policy SHALL be expressed as data loaded through an adapter, not as compiled-in comparison logic, so that adding, removing, or amending a policy is a change to policy data — not a change to enforcement code. A policy set SHALL be selectable per environment. A malformed policy set SHALL fail closed at load (the surface refuses to serve rather than evaluating against a partial or empty policy set it cannot validate).

#### Scenario: A policy change takes effect as data

- **WHEN** the policy data is amended to permit or deny a case it previously did not
- **THEN** the new decision SHALL take effect from the updated policy data without editing enforcement code

#### Scenario: A malformed policy set fails closed

- **WHEN** the engine is given a policy set that cannot be validated/loaded
- **THEN** the surface SHALL fail closed — refusing to serve authorization-gated requests — rather than evaluating against an unvalidated or empty policy set

### Requirement: The decision is decoupled from the enforcement surface

The authorization decision SHALL be independent of which surface requests it: the same (principal, action, resource, context) SHALL yield the same decision regardless of the calling surface, so enforcement points remain thin adapters that translate a request into a decision query and act on the result. An enforcement surface SHALL NOT embed its own parallel authorization logic that could diverge from the policy decision.

#### Scenario: The same inputs yield the same decision everywhere

- **WHEN** two different enforcement surfaces submit the same (principal, action, resource, context)
- **THEN** the engine SHALL return the same decision to both
