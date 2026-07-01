# combined-edge-per-route-auth-gate

Adopt the N4 per-route auth gate (x-auth-required branch) in the combined production edge (compose + edge-platform), replacing the blanket hard-JWT-on-prefix:/ requirement; use an inverted fail-safe catch-all and backport it to canonical edge/envoy.yaml.
