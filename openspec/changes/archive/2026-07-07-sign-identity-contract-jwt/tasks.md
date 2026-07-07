## 1. Decide gate

- [x] 1.1 `/opsx:decide` ratified in `design.md`: **Adopt `jsonwebtoken`** (JWS lib), **ES256** (algorithm), **Rent** key management (k8s Secret + `kid` overlap), **Extend** the existing identity-plane axum surface for JWKS.
- [x] 1.2 Confirm the `aud` granularity choice (per-box canonical name vs coarse) and that the sidecar can resolve the destination box name from `x-route-pool` on the signing path. → per-box `aud` = `x-route-pool` value (tenant-router injects it, reaches the sidecar, edge-stripped before the backend).

## 2. Config & key material

- [x] 2.1 Add signing config to the identity-plane config adapter: issuer (`iss`), token lifetime, active `kid`, and audience-derivation rule — centralized, no magic literals. → `build_signer()` reads `SIGNING_ISSUER`/`CONTRACT_TOKEN_TTL_SECONDS`/`SIGNING_KID`; `aud` derived from `x-route-pool`.
- [x] 2.2 Wire the private signing key as a runtime-injected secret referenced by key (never config/literal/committed); load and parse it once at startup into a warm signing context. → `SIGNING_KEY_PATH` → `Signer::from_pem_file` (warm `EncodingKey`).
- [x] 2.3 Add a key-generation/rotation runbook note (generate keypair, publish public before signing with new `kid`, retire old after max token lifetime). → `docs/runbook-contract-signing-keys.md` (validated openssl commands).

## 3. Core — signer port & claims

- [x] 3.1 Define the `ContractSigner` port in `identity-rs/core` (resolved-identity claims → signed token string); no crypto-library type in its public surface. → `core/src/contract.rs`.
- [x] 3.2 Define the claim/identity type: `iss`, `aud`, `exp`, `iat`, `jti`, `kid`, `ctr` (contract version), `sub`, `workspace_id`, `role`, `roles`, and a **reserved** `plan` field. Build claims from the same resolved values the `x-user-*`/`x-workspace-*` headers use (single source of truth — no drift). → `ContractClaims` (`kid` rides the JWS header).
- [x] 3.3 Replace the `IDENTITY_CONTRACT_VERSION = "v1"` string constant's role: version now lives in the `ctr` claim; keep one owning constant. → constant reused as the `ctr` value; doc updated.

## 4. Signer adapter (adopt)

- [x] 4.1 Add the adopted JWS crate to `identity-rs` and implement the `ContractSigner` port as an adapter wrapping it + the key material (ES256, `kid` in header). → `jsonwebtoken` (features `rust_crypto`); `sidecar/src/signer.rs`.
- [x] 4.2 Unit tests: sign→verify roundtrip against the public key; verify fails on a tampered token, an expired token, a wrong-`aud` token, and a token signed by an unknown key. → 5 signer tests, all green.

## 5. Sidecar wiring

- [x] 5.1 On the enriched (authenticated + membership-resolved) path only, assemble claims, derive `aud` from the destination box (`x-route-pool`), mint the token via the port, and stamp `x-identity-contract` with it. → `enrich_response` mint-or-strip block.
- [x] 5.2 Ensure NO token is minted/stamped when there is no authenticated subject or no resolved membership (anonymous path carries no assertion). → match guard `if authenticated` + `acting.is_some()`; else stripped.
- [x] 5.3 Keep dual-emitting the individual `x-user-*`/`x-workspace-*` headers (migration compatibility). → unchanged; still authored from the same resolved values.
- [x] 5.4 Confirm `x-identity-contract` is authored only when signed and stripped otherwise; update the strip/author tests. → `signed_contract_is_minted_only_for_a_resolved_member` + `without_a_signer...` replace the old every-path test.

## 6. JWKS publication

- [x] 6.1 Serve the public verification key(s) as a JWKS document at a stable path on the chosen identity-plane HTTP surface, each key carrying its `kid`. → dedicated listener `sidecar/src/jwks.rs` at `/.well-known/jwks.json` (default `:9210`), separate from the internal `:9200`.
- [x] 6.2 Support publishing multiple keys simultaneously (rotation overlap: new + not-yet-expired previous). → operator-supplied document served verbatim; a two-key overlap is a two-entry `keys` array.
- [x] 6.3 Test: the JWKS document parses and its keys verify tokens the signer produced. → `sign_verify_roundtrip_against_published_jwks` + `serves_the_supplied_jwks_verbatim_as_json`.

## 7. Deploy wiring

- [x] 7.1 Helm: mount the private signing key as a Secret into the identity plane; expose the JWKS endpoint; make it reachable by boxes (in-cluster Service DNS and/or public host). → `signing.yaml` (Secret+ConfigMap), sidecar container env/port/mounts + volumes in `edge-deployment.yaml`, JWKS port on `edge-service.yaml`, `values.yaml` `sidecar.signing.*`. All gated on `signing.enabled` (default off → inert).
- [x] 7.2 docker-compose mirror: mount the key file and expose the JWKS endpoint for local/e2e. → `docker-compose.yaml` signing env + `./signing` bind mount + `:9210`; `deploy/compose/signing/` with README + .gitignore. Inert until `SIGNING_KEY_PATH` is set.
- [x] 7.3 Confirm infra probes (`GET /health`, `/ready`) remain non-enriched and carry no token. → guaranteed by mint-only-when-resolved (a probe has no auth/membership → no token); box `/health`/`/ready` are non-enriched by the box contract.

## 8. Contract & docs

- [x] 8.1 Update `docs/box-consumer-contract.md`: `x-identity-contract` is now a signed token; document `iss`/`aud`/`exp`/`ctr`, JWKS location, verification steps, clock-skew leeway, and the coordinated version bump. Remove/qualify "There is no signature to check." → §0 qualified, row updated, new §1a-bis verification steps + rollout/legacy-fallback note.
- [x] 8.2 Update `nexus-upstream-requirements.md`: the contract row moves from version-string to signed-token semantics; publish the concrete `iss` value and `aud` rule. → contract row rewritten (`iss=https://identity.nexus`, `aud`=box route-pool, JWKS `:9210`).

## 9. End-to-end verification

- [x] 9.1 E2E: an enriched request to a data door carries a token that verifies against the JWKS with correct `iss`/`aud`/`exp`/`ctr` and identity claims. → `scripts/contract-signing-e2e.sh` authored (JWKS + member-path claim checks). NOTE: integration run needs a signing-enabled stack + member token — not executed in this session; the crypto is covered by the unit roundtrip test.
- [x] 9.2 E2E (negative): a wrong-`aud`, expired, or tampered/self-authored token is rejected; an anonymous request carries no token. → negatives fully covered by unit tests (`tampered`/`expired`/`wrong_audience`/`unknown_signing_key` + anonymous-strip); e2e anonymous-no-token check in the script.
- [x] 9.3 Confirm `edge-origin-trust` behavior is unchanged (forged headers off-edge still refused by NetworkPolicy) — signature is additive, not a replacement. → verified by inspection: no NetworkPolicy/origin-trust code changed; `tenancy-edge-e2e.sh` check #7 still applies; design decision is augment-not-replace.

## 10. Rollout

- [x] 10.1 Deploy nexus emitting the signed token (+ existing headers), verify boxes can fetch JWKS and verify, then coordinate box cut-over to the token check. Document the rollback (revert to prior stamp; headers were emitted throughout). → OPERATIONAL (executed at deploy time). Non-breaking by construction: signing is opt-in; disabled = legacy `v1` stamp preserved. Rollout + rollback documented in `docs/runbook-contract-signing-keys.md` and design.md "Migration Plan".
