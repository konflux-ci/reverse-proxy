#!/usr/bin/env bash
#
# Rebuild the reverse-proxy image, reload it into a Kind cluster, and
# restart the proxy deployment so the new image is picked up immediately.
#
# This is the fast inner-loop companion to test-in-kind.sh.
# Run test-in-kind.sh first to apply operator overrides, then use this
# script for subsequent iterations.
#
# Usage:
#   ./scripts/reload-in-kind.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMG="${IMG:-localhost/konflux-ci/reverse-proxy:local}"
KIND_CLUSTER="${KIND_CLUSTER:-konflux}"
NAMESPACE="${NAMESPACE:-konflux-ui}"
DEPLOYMENT="${DEPLOYMENT:-proxy}"

log() { echo "==> $*"; }

# ── 1. Build and load into Kind ─────────────────────────────────────────────
log "Building and loading image ${IMG} into Kind cluster '${KIND_CLUSTER}'"
make -C "${REPO_ROOT}" kind-load IMG="${IMG}" KIND_CLUSTER="${KIND_CLUSTER}"

# ── 2. Restart the deployment ──────────────────────────────────────────────
log "Restarting deployment/${DEPLOYMENT} in namespace ${NAMESPACE}"
kubectl rollout restart "deployment/${DEPLOYMENT}" -n "${NAMESPACE}"
kubectl rollout status "deployment/${DEPLOYMENT}" -n "${NAMESPACE}" --timeout=120s

log "Done. New image is live."
