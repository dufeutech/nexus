# workspace-tenancy

## Purpose

The nexus-owned ownership and addressing model: Accounts own Workspaces, Workspaces
are stable-ID units, domains are many-to-one aliases, and ownership is transferable.

## Requirements

### Requirement: A Workspace is identified by a stable internal ID, never a domain

The system SHALL identify every workspace by a stable internal `workspace_id`. All
tenancy, membership, routing, and customer data SHALL key off that id. A domain name
SHALL NOT be used as the identity of a workspace.

#### Scenario: Multiple domains resolve to one workspace
- **WHEN** several domains are attached to the same workspace and a request arrives
  on any of them
- **THEN** the system SHALL resolve all of them to the same `workspace_id`

#### Scenario: A domain is an alias, not the key
- **WHEN** a domain is removed from or reassigned away from a workspace
- **THEN** the workspace and all data keyed by its `workspace_id` SHALL be unaffected

### Requirement: Workspace and account ids are system-minted and structurally typed

The system SHALL mint every workspace and account identifier itself at creation time;
callers SHALL NOT choose or supply identifiers. A minted identifier SHALL be globally
collision-resistant, time-ordered, and structurally typed by resource kind — workspace
ids carry the `ws_` prefix and account ids the `acct_` prefix — so an id's kind and
origin are evident from the string alone and ids cannot collide with identifiers from
unrelated systems. The minted id SHALL be returned to the caller in the creation
response; callers supply a display name, which SHALL carry no identity or uniqueness
semantics.

#### Scenario: Creating a workspace returns a minted, typed id
- **WHEN** a caller creates a workspace supplying only a display name and configuration
- **THEN** the response SHALL contain a system-minted workspace id bearing the `ws_`
  prefix, and that id SHALL be the workspace's stable identity thereafter

#### Scenario: Caller-supplied ids are not honored
- **WHEN** a creation request attempts to supply its own workspace or account id
- **THEN** the system SHALL reject the request rather than adopt the supplied id

#### Scenario: Id kinds are distinguishable from the value alone
- **WHEN** an operator encounters an id in a log, error, or downstream system
- **THEN** the `ws_` / `acct_` prefix SHALL identify which kind of resource it names
  without consulting nexus

#### Scenario: Display names are not identities
- **WHEN** two workspaces are created with the same display name
- **THEN** both SHALL exist as distinct workspaces with distinct ids

### Requirement: An Account owns Workspaces and is a member container

The system SHALL model ownership as an **Account** that owns one or more workspaces
(`workspace.account_id`). Every account SHALL be a container of members (a solo user
is a one-member account); there SHALL NOT be a structural distinction between
"personal" and "organization" accounts. A user SHALL never be an owner directly —
ownership is always held by an account the user is a member of.

#### Scenario: Solo user gets an owning account on signup
- **WHEN** a new user first authenticates and has no account
- **THEN** the system SHALL provision an account with that user as its `owner`
  member, with no manual "create organization" step

#### Scenario: Adding members does not change the account's kind
- **WHEN** a second (or later) member is added to an account
- **THEN** the account SHALL be governed identically to a one-member account (same
  roles, same ownership semantics) — no conversion event occurs

### Requirement: Workspace ownership is transferable by repointing the account

The system SHALL allow a workspace to be transferred to a different owning account by
changing `workspace.account_id`. The transfer SHALL NOT change the `workspace_id`,
its domains, its customer memberships, or its data. Staff memberships MAY be reset as
part of the transfer.

#### Scenario: Transfer moves ownership without disrupting the workspace
- **WHEN** a workspace is transferred from account A to account B
- **THEN** `workspace.account_id` SHALL become B, and the workspace's id, domains,
  customer memberships, and data SHALL remain intact and routable throughout

### Requirement: Plan lives on the workspace; payer lives on the account

The system SHALL store the workspace's plan/tier on the workspace (so it travels with
a transfer) and the payment/billing relationship on the owning account (so a transfer
switches who is charged).

#### Scenario: Plan travels with a transfer, payer switches
- **WHEN** a workspace on plan P owned by account A is transferred to account B
- **THEN** the workspace SHALL remain on plan P, and the billing/payer of record
  SHALL become account B
