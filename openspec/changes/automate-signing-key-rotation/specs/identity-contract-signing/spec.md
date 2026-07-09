## ADDED Requirements

### Requirement: Signing-key rotation is automated, not a manual procedure

Signing-key rotation SHALL be automated: the identity plane's key material lifecycle — generation of a
new key, its publication as verification material, cut-over of signing to it, and retirement of the
previous key after its in-flight tokens have expired — SHALL proceed without a human executing a
step-by-step runbook. The overlap guarantee already required (a new key published before it signs, a
retired key kept published until its tokens expire) SHALL hold under automation, so rotation causes no
in-flight token rejection. A deployment SHALL be able to rotate on a schedule or on demand without
manual editing of key files, identifiers, or published key sets.

#### Scenario: A scheduled rotation completes without manual steps

- **WHEN** a configured rotation interval elapses
- **THEN** the identity plane SHALL generate and publish a new key, begin signing with it, and retire
  the previous key after its tokens expire — with no operator running a manual procedure, and with the
  key identifier kept consistent between the signer and the published verification set automatically

#### Scenario: Rotation preserves the in-flight overlap guarantee

- **WHEN** automated rotation cuts over to a new signing key while tokens signed by the previous key are
  still within their validity window
- **THEN** both keys SHALL remain published and a box SHALL verify tokens signed by either, so no
  in-flight token is rejected during rotation

#### Scenario: On-demand rotation on suspected compromise

- **WHEN** an operator triggers an unscheduled rotation (e.g. suspected key compromise)
- **THEN** the identity plane SHALL perform the same automated publish-cutover-retire sequence
  immediately, without hand-editing key material or the published key set
