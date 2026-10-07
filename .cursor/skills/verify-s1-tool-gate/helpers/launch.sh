#!/usr/bin/env bash
# Prepare an isolated verification run of the claims gate CLI.
# Usage: helpers/launch.sh
# - ensures ${VENV} has gate-client, gate-enforcement, claims-gate installed editable (installs if missing)
# - creates /tmp/s1-verify-<run-id>/kit with a fresh TEST-ONLY RSA key + jwks.json
# - writes instance.json; prints "ready: claims_gate CLI ok (26 kaia tools)"
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ -f "${INSTANCE_FILE}" ]]; then
  echo "launch: run ${RUN_ID} already prepared at ${INSTANCE_DIR}; run cleanup.sh first" >&2
  exit 1
fi

cd "${REPO_ROOT}"
if [[ ! -x "${PY}" ]]; then
  python3 -m venv "${VENV}"
fi
# Always reinstall editable so the run verifies this checkout (fast when already satisfied).
"${PY}" -m pip install -q -e packages/gate-client -e packages/gate-enforcement -e "packages/claims-gate[dev]" \
  >/dev/null

mkdir -p "${INSTANCE_DIR}" "${EVIDENCE_DIR}"
echo "${RUN_ID}" > /tmp/s1-verify-current
"${PY}" -m claims_gate testkit init --dir "${KIT_DIR}" > "${INSTANCE_DIR}/testkit-init.json"

TOOL_COUNT="$("${PY}" -m claims_gate tools | "${PY}" -c 'import json,sys; print(len(json.load(sys.stdin)["toolScopes"]))')"
cat > "${INSTANCE_FILE}" <<JSON
{
  "runId": "${RUN_ID}",
  "python": "${PY}",
  "kitDir": "${KIT_DIR}",
  "jwks": "${KIT_DIR}/jwks.json",
  "issuer": "${ISSUER}",
  "audience": "${AUDIENCE}",
  "evidenceDir": "${EVIDENCE_DIR}"
}
JSON

echo "RUN_ID=${RUN_ID}"
echo "instance=${INSTANCE_FILE}"
echo "evidence=${EVIDENCE_DIR}"
echo "ready: claims_gate CLI ok (${TOOL_COUNT} kaia tools)"
