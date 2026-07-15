#!/usr/bin/env sh
# Regenerate the SLO recording + multi-window burn-rate (MWMB) alert rules from the
# Sloth specs in this directory (change: slo-burn-rate-policy; design: Adopt Sloth).
#
# Runs the PINNED Sloth release via its official container so the generated rules are
# reproducible and reviewable in the diff. This is the ONE place generation happens
# (task 1.2 / 4.4): run it after editing any *.slo.yaml and COMMIT the output. Never
# hand-edit the generated files — Sloth owns the burn-rate math.
#
#   ./monitoring/slo/generate.sh        # regenerate + commit the result
#
# Requires: docker. Pin bump = edit SLOTH_VERSION, regenerate, review the diff.
set -eu

# On Windows Git-Bash, MSYS rewrites container-side paths (/specs -> C:/...); disable
# that conversion so the paths passed INTO the container stay literal. No-op elsewhere.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"

SLOTH_VERSION="v0.16.0"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$HERE/../prometheus/rules"
mkdir -p "$OUTDIR"

for spec in "$HERE"/*.slo.yaml; do
  base="$(basename "$spec" .slo.yaml)"
  echo "sloth generate: $base"
  docker run --rm \
    -v "$HERE:/specs:ro" \
    -v "$OUTDIR:/out" \
    "ghcr.io/slok/sloth:$SLOTH_VERSION" \
    generate -i "/specs/$(basename "$spec")" -o "/out/$base.rules.yaml"
done

echo "generated $OUTDIR/*.rules.yaml from $HERE/*.slo.yaml (sloth $SLOTH_VERSION)"

# Stage each service's generated rules INTO its Helm chart so the SAME rules ship to
# production, wrapped in a PrometheusRule by templates/prometheusrule-slo.yaml (Helm
# embeds them via .Files.Get — it can't run Sloth at render time). Lab + prod therefore
# evaluate byte-identical rules. Keep this mapping in sync with the specs above.
stage_to_chart() { # <rules-basename> <chart-name>
  dest="$HERE/../../deploy/helm/$2/files/slo"
  mkdir -p "$dest"
  cp "$OUTDIR/$1.rules.yaml" "$dest/$1.rules.yaml"
  echo "staged $1.rules.yaml -> deploy/helm/$2/files/slo/"
}
stage_to_chart tenant-router routing-plane
stage_to_chart identity-sidecar identity-plane
