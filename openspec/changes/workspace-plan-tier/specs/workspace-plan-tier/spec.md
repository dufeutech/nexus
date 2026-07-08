## ADDED Requirements

### Requirement: The identity plane emits the acting workspace's plan tier
The identity plane SHALL resolve the plan tier of the **acting workspace** and emit it as a
nexus-authored fact (`x-workspace-plan`) on enriched requests, so a box can drive storage-cap
and feature policy from it. The plan SHALL be sourced from nexus's own authoritative workspace
record — never from a client hint, a token claim, or the presented credential.

#### Scenario: Enriched request carries the acting workspace's plan
- **WHEN** the identity plane enriches an authenticated request whose acting workspace resolves
  to plan `P`
- **THEN** the enriched request SHALL carry `P` as the nexus-authored plan for that workspace

#### Scenario: Plan is nexus-authored, never client-asserted
- **WHEN** a request presents its own asserted plan (a client-supplied `x-workspace-plan` or a
  plan value embedded in the credential)
- **THEN** the asserted value SHALL be ignored and the enriched request SHALL carry only the
  plan nexus resolved for the acting workspace

### Requirement: Plan resolution is live and revocation-consistent
The emitted plan SHALL reflect the **current** plan of the acting workspace. A plan change — an
upgrade or a downgrade — SHALL take effect promptly on subsequent requests without requiring the
subject to re-authenticate or refresh a token, consistent with how the acting scope (membership,
suspension) already resolves.

#### Scenario: A downgrade takes effect promptly
- **WHEN** an acting workspace is downgraded from a higher plan to a lower one
- **THEN** requests enriched after the change SHALL carry the lower plan, without any token
  refresh by the subject

#### Scenario: An upgrade takes effect promptly
- **WHEN** an acting workspace is upgraded to a higher plan
- **THEN** requests enriched after the change SHALL carry the higher plan on subsequent requests

### Requirement: Absent or unresolved plan is a safe not-provisioned state
The identity plane SHALL omit the plan rather than assert a default when the acting workspace's
plan cannot be resolved — the workspace is unknown to the plane, or the plan source is momentarily
unavailable — and a consuming box SHALL treat an absent plan as **not-provisioned**. This fails
closed on provisioning (no tier is granted on uncertainty), not open. A provisioned workspace
always resolves to at least its baseline plan, so absence occurs only on a genuine resolution miss.

#### Scenario: Unresolvable plan is omitted, not defaulted
- **WHEN** the identity plane cannot resolve the acting workspace's plan
- **THEN** it SHALL emit no plan value rather than substitute a default tier

#### Scenario: A box treats an absent plan as not-provisioned
- **WHEN** a box receives an enriched request carrying no plan
- **THEN** the box SHALL treat the workspace as not-provisioned for plan-gated features rather
  than grant any tier
