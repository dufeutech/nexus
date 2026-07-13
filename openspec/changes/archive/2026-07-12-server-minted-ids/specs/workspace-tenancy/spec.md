# workspace-tenancy — delta

## ADDED Requirements

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
