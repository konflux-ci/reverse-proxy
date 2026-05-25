#!/usr/bin/env bash
#
# Build the reverse-proxy image, load it into a Kind cluster, and apply
# operator overrides so the local image replaces the upstream caddy image.
#
# Prerequisites:
#   - A running Kind cluster (created by konflux-ci's deploy-local.sh)
#   - A checkout of github.com/konflux-ci/konflux-ci next to this repo
#     (or set KONFLUX_CI_DIR)
#
# Usage:
#   ./scripts/test-in-kind.sh
#
# After running, start (or restart) the operator from the konflux-ci checkout:
#   cd <konflux-ci>/operator && make run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMG="${IMG:-localhost/konflux-ci/reverse-proxy:local}"
ORIG_IMG="${ORIG_IMG:-registry.access.redhat.com/hi/caddy}"
KIND_CLUSTER="${KIND_CLUSTER:-konflux}"
KONFLUX_CI_DIR="${KONFLUX_CI_DIR:-${REPO_ROOT}/../konflux-ci}"
log() { echo "==> $*"; }

KONFLUX_CI_DIR="$(cd "${KONFLUX_CI_DIR}" 2>/dev/null && pwd)" || {
    echo "error: konflux-ci directory not found at ${KONFLUX_CI_DIR}"
    echo "Set KONFLUX_CI_DIR to the path of your konflux-ci checkout."
    exit 1
}

OPERATOR_DIR="${KONFLUX_CI_DIR}/operator"
if [[ ! -d "${OPERATOR_DIR}/cmd/overrides" ]]; then
    echo "error: ${OPERATOR_DIR}/cmd/overrides not found."
    echo "Is KONFLUX_CI_DIR pointing to a valid konflux-ci checkout?"
    exit 1
fi

# ── 1. Build and load into Kind ─────────────────────────────────────────────
log "Building and loading image ${IMG} into Kind cluster '${KIND_CLUSTER}'"
make -C "${REPO_ROOT}" kind-load IMG="${IMG}" KIND_CLUSTER="${KIND_CLUSTER}"

# ── 2. Apply overrides ─────────────────────────────────────────────────────
log "Applying operator overrides (${ORIG_IMG} -> ${IMG})"

OVERRIDES_YAML="$(cat <<EOF
- name: ui
  images:
    - orig: "${ORIG_IMG}"
      replacement: "${IMG}"
EOF
)"

cd "${OPERATOR_DIR}"
go run ./cmd/overrides \
    --upstream-dir  ./upstream-kustomizations \
    --manifests-dir ./pkg/manifests \
    --tmp-dir       "${KONFLUX_CI_DIR}/.tmp" \
    --overrides-yaml "${OVERRIDES_YAML}"

log "Done. Restart the operator to pick up the new image:"
log "  cd ${OPERATOR_DIR} && make run"
