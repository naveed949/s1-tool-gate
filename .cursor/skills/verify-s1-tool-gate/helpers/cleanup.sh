#!/usr/bin/env bash
# Remove this run's scratch state (TEST-ONLY key, jwks, instance.json). Never touches evidence.
# The CLI is short-lived, so there is no process to stop.
# Usage: helpers/cleanup.sh
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ -d "${INSTANCE_DIR}" ]]; then
  rm -rf "${INSTANCE_DIR}"
  echo "cleanup: removed ${INSTANCE_DIR} (TEST-ONLY key deleted)"
else
  echo "cleanup: no scratch dir at ${INSTANCE_DIR}"
fi
if [[ -f /tmp/s1-verify-current && "$(cat /tmp/s1-verify-current)" == "${RUN_ID}" ]]; then
  rm -f /tmp/s1-verify-current
fi
echo "cleanup: evidence retained at ${EVIDENCE_DIR}"
