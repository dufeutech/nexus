## ADDED Requirements

### Requirement: Enabled signing takes effect in every edge topology

When a deployment enables identity-contract signing, **every** edge through which the identity
plane enriches requests SHALL mint the signed `x-identity-contract` and publish its verification
material — independently of how the plane's components are composed. This SHALL hold both for a
dedicated identity edge and for a co-located edge that runs identity enrichment alongside other
planes on a single data path. A deployment SHALL NOT serve enriched traffic through an edge that
omits the signature, or that fails to expose the published verification material to consumers,
while signing is enabled; such a topology is a misconfiguration, not a silently-unsigned success.
The runtime-secret custody, automated rotation, and break-glass fallback guarantees of this
capability SHALL apply identically across topologies, so no topology is signed by a weaker path
than another.

#### Scenario: A co-located edge honors enabled signing

- **WHEN** a deployment composes identity enrichment together with other planes on one edge and enables signing
- **THEN** that co-located edge SHALL mint the signed `x-identity-contract` and publish its verification material, exactly as a dedicated identity edge would

#### Scenario: No topology serves enriched traffic silently unsigned

- **WHEN** signing is enabled for a deployment but an edge topology is assembled without the signing configuration reaching the component that stamps the contract
- **THEN** the deployment SHALL be treated as a misconfiguration rather than serving enriched requests without the signature — enabling signing SHALL never silently no-op on a supported topology

#### Scenario: Verification material is reachable regardless of topology

- **WHEN** a box needs to verify a contract minted by a co-located edge
- **THEN** it SHALL be able to fetch that edge's published verification material at the same stable, public location it uses for a dedicated identity edge, so verification does not depend on the plane's composition
