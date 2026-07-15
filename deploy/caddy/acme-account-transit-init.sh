#!/usr/bin/env sh
# custom-domains-tls (design D8): custody the long-lived ACME ACCOUNT key in OpenBao
# Transit — consistent with the identity signing-key custody (deploy/compose/signing).
# The account key is a runtime-injected secret, NEVER committed; leaf certs/keys stay
# in Postgres (the hot CertMagic store). Idempotent: safe to re-run.
#
# Why Transit for THIS key: the ACME account key authenticates the platform to the CA
# for every order/renewal across the whole fleet. Mixing it into the Postgres leaf
# store (alongside per-domain certs) would put a long-lived custody secret in the hot
# path; Transit keeps it custodied and exported by-key at boot.
#
# Prereq: the dev OpenBao is up (shared with signing) —
#   docker compose --profile signing up -d openbao
#
# Provision the key (from deploy/compose/):
#   BAO_ADDR=http://127.0.0.1:8200 BAO_TOKEN=root ../caddy/acme-account-transit-init.sh
#
# Then, at front-tier boot, export the account key from Transit into the tmpfs secret
# the Caddy container mounts (never onto disk that outlives the process):
#   ...this script also writes ${ACME_ACCOUNT_KEY_FILE} when RUN_EXPORT=1 is set.
set -eu

ADDR="${BAO_ADDR:-http://127.0.0.1:8200}"
TOKEN="${BAO_TOKEN:-root}"
MOUNT="${ACME_TRANSIT_MOUNT:-transit}"
KEY="${ACME_TRANSIT_KEY:-acme-account-key}"
ACME_ACCOUNT_KEY_FILE="${ACME_ACCOUNT_KEY_FILE:-/run/secrets/acme-account.key}"

# Run the bao CLI inside the running openbao container so no local install is needed.
bao() { docker compose exec -T -e BAO_ADDR="$ADDR" -e BAO_TOKEN="$TOKEN" openbao bao "$@"; }

echo "==> enabling the Transit engine at '$MOUNT/' (ignore 'path is already in use')"
bao secrets enable -path="$MOUNT" transit 2>/dev/null || true

echo "==> creating the exportable ecdsa-p256 ACME account key '$KEY'"
# exportable=true -> the front tier exports the account (private) key at boot so
# CertMagic adopts THIS account instead of registering a fresh one into Postgres.
# allow_plaintext_backup is deliberately NOT set (no full-key backup path).
bao write -f "$MOUNT/keys/$KEY" type=ecdsa-p256 exportable=true 2>/dev/null \
  || echo "    (key already exists — leaving it in place)"

echo "==> current key versions:"
bao read "$MOUNT/keys/$KEY"

# Boot-time export: materialize the account key into the tmpfs secret Caddy mounts.
# Gated behind RUN_EXPORT so `provision` and `inject` are separate, auditable steps.
if [ "${RUN_EXPORT:-0}" = "1" ]; then
  echo "==> exporting account key -> $ACME_ACCOUNT_KEY_FILE (referenced by key, never committed)"
  mkdir -p "$(dirname "$ACME_ACCOUNT_KEY_FILE")"
  # Export the latest version's signing key PEM. The front-tier entrypoint seeds this
  # into CertMagic's ACME account before `caddy run` (see README "ACME account key").
  bao read -field=keys "$MOUNT/export/signing-key/$KEY" > "$ACME_ACCOUNT_KEY_FILE"
  chmod 600 "$ACME_ACCOUNT_KEY_FILE"
fi

cat <<EOF

Done. The ACME account key '$KEY' is custodied in OpenBao Transit ($MOUNT/keys/$KEY).
Leaf certificates and their private keys remain in Postgres (certmagic_data). The
account key is injected by-key at boot (RUN_EXPORT=1) and never written to the image.

  - Rotate the ACME account key (rare; a new CA registration):
      docker compose exec openbao bao write -f "$MOUNT/keys/$KEY/rotate"
    Then re-run with RUN_EXPORT=1 and restart the front tier.
EOF
