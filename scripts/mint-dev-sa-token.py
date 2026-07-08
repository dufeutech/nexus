#!/usr/bin/env python3
"""Mint a DEV core-service ServiceAccount token for the normalized-principal e2e.

This is the COMPOSE-DEV stand-in for a real K8s projected ServiceAccount token
(normalized-principal ADR-6/task 3.3). It signs an ES256 JWT with the dev EC P-256
key whose public half the edge's `service_account` jwt_authn provider verifies against
(the inline `local_jwks` stub in edge/envoy.yaml, kid `test-key-1`). In production the
cluster issues and rotates these; here we mint one so the service path is exercisable
without a cluster.

The claims match the edge provider config:
  iss = https://sa.nexus.local   aud = nexus-edge   kid = test-key-1
  sub = the service id (must match a row in platform.services, seeded by
        postgres-init/20-platform-services.sql)

Usage:
  python3 scripts/mint-dev-sa-token.py \
      [--sub system:serviceaccount:nexus:events-writer] \
      [--key identity-rs/sidecar/src/testdata/test-ec-p256.pem] \
      [--ttl 300]

Prints the compact JWS to stdout (use it as $SVC_TOKEN for service-identity-e2e.sh).

Requires PyJWT + cryptography:  pip install "pyjwt[crypto]"
"""
import argparse
import sys
import time

try:
    import jwt  # PyJWT
except ImportError:
    sys.exit(
        "PyJWT not installed. Run:  pip install 'pyjwt[crypto]'\n"
        "(or mint the token with any JOSE tool using the dev key + these claims:\n"
        "  alg=ES256 kid=test-key-1 iss=https://sa.nexus.local aud=nexus-edge sub=<service-id>)"
    )

DEFAULT_KEY = "identity-rs/sidecar/src/testdata/test-ec-p256.pem"
DEFAULT_SUB = "system:serviceaccount:nexus:events-writer"


def main() -> None:
    ap = argparse.ArgumentParser(description="Mint a dev core-service SA token (ES256).")
    ap.add_argument("--sub", default=DEFAULT_SUB, help="service id (must be an active platform.services row)")
    ap.add_argument("--key", default=DEFAULT_KEY, help="EC P-256 PKCS#8 PEM private key")
    ap.add_argument("--iss", default="https://sa.nexus.local")
    ap.add_argument("--aud", default="nexus-edge")
    ap.add_argument("--kid", default="test-key-1")
    ap.add_argument("--ttl", type=int, default=300, help="token lifetime in seconds")
    args = ap.parse_args()

    with open(args.key, "rb") as fh:
        pem = fh.read()

    now = int(time.time())
    claims = {
        "iss": args.iss,
        "aud": args.aud,
        "sub": args.sub,
        "iat": now,
        "exp": now + args.ttl,
    }
    token = jwt.encode(claims, pem, algorithm="ES256", headers={"kid": args.kid})
    print(token)


if __name__ == "__main__":
    main()
