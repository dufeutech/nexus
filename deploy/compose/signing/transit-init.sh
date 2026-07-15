#!/usr/bin/env sh
# automate-signing-key-rotation: provision the OpenBao Transit key the identity sidecar
# signs the x-identity-contract with (Mode B — the plane EXPORTS key material and signs
# locally, so the key must be `exportable`). Idempotent: safe to re-run.
#
# Prereq: the bundled dev OpenBao is up —
#   docker compose --profile signing up -d openbao
#
# Then run this against it (from deploy/compose/):
#   BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root ./signing/transit-init.sh
#
# ...and point the sidecar at it (in your .env or shell), then restart identity-sidecar:
#   SIGNING_TRANSIT_KEY=identity-contract-signing
#   BAO_ADDR=http://openbao:8200      # the in-network address the sidecar uses
#   BAO_TOKEN=root
set -eu

ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
TOKEN="${BAO_TOKEN:-root}"
MOUNT="${SIGNING_TRANSIT_MOUNT:-transit}"
KEY="${SIGNING_TRANSIT_KEY:-identity-contract-signing}"

# Run the bao CLI inside the running openbao container so no local install is needed.
bao() { docker compose exec -T -e BAO_ADDR="$ADDR" -e BAO_TOKEN="$TOKEN" openbao bao "$@"; }

echo "==> enabling the Transit engine at '$MOUNT/' (ignore 'path is already in use')"
bao secrets enable -path="$MOUNT" transit 2>/dev/null || true

echo "==> creating the exportable ecdsa-p256 key '$KEY' (Mode B local signing)"
# exportable=true  -> the plane can export the signing (private) key to sign locally.
# allow_plaintext_backup is deliberately NOT set (no full-key backup path).
bao write -f "$MOUNT/keys/$KEY" type=ecdsa-p256 exportable=true 2>/dev/null \
  || echo "    (key already exists — leaving it in place)"

echo "==> current key versions:"
bao read "$MOUNT/keys/$KEY"

cat <<EOF

Done. The sidecar will pull versioned keys from '$MOUNT/keys/$KEY', GENERATE the JWKS from
Transit's public keys, and rotate on schedule / on demand.

  - Rotate on demand (e.g. suspected compromise):
      docker compose exec openbao bao write -f "$MOUNT/keys/$KEY/rotate"
    The sidecar adopts the new version on its next poll (SIGNING_KEY_POLL_SECONDS), keeping
    the previous key published for the overlap window so no in-flight token is rejected.
EOF
