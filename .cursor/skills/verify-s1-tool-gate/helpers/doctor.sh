#!/usr/bin/env bash
# Read-only: is this run worth driving? Exit 0 only when every check passes.
# Usage: helpers/doctor.sh
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

fail() { echo "doctor: $*" >&2; exit 1; }
[[ -f "${INSTANCE_FILE}" ]] || fail "missing ${INSTANCE_FILE}; run launch.sh"
[[ -x "${PY}" ]] || fail "no python at ${PY}"
[[ -f "${KIT_DIR}/jwks.json" ]] || fail "missing ${KIT_DIR}/jwks.json"
KEY="${KIT_DIR}/test-signing-key.TEST-ONLY.pem"
[[ -f "${KEY}" ]] || fail "missing TEST-ONLY key"
MODE="$(stat -c %a "${KEY}")"
[[ "${MODE}" == "600" ]] || fail "TEST-ONLY key mode is ${MODE}, expected 600"

cd "${REPO_ROOT}"
LOC="$("${PY}" -c 'import claims_gate, gate_enforcement, os; print(os.path.dirname(claims_gate.__file__))')" \
  || fail "claims_gate / gate_enforcement not importable"
[[ "${LOC}" == "${REPO_ROOT}/packages/claims-gate/src/claims_gate" ]] || fail "claims_gate imported from ${LOC}, not this checkout"

"${PY}" -m claims_gate tools | "${PY}" -c '
import json, sys
t = json.load(sys.stdin)
assert t["source"].endswith("253d6c8:src/auth/scopes.ts"), t["source"]
assert len(t["toolScopes"]) == 26, len(t["toolScopes"])
assert t["walletTools"] == ["generate_wallet"], t["walletTools"]
' || fail "kaia fixture mismatch"

"${PY}" -m claims_gate proxy --help > /dev/null || fail "claims_gate has no proxy subcommand"
"${PY}" -m claims_gate escalations --help > /dev/null || fail "claims_gate has no escalations subcommand"
# live-proxy prerequisites (only that feature needs them; report, do not fail the others).
LIVE="node=$(command -v node >/dev/null && node -v || echo missing) npm=$(command -v npm >/dev/null && npm -v || echo missing) git=$(command -v git >/dev/null && echo ok || echo missing)"
PINNED="$(sed -n 's/^DEFAULT_KAIA_REF = "\([0-9a-f]*\)"/\1/p' packages/claims-gate/e2e/live_kaia.py | cut -c1-7)"
KAIA_SRC="${S1_VERIFY_KAIA_DIR:-${KAIA_MCP_DIR:-pinned-clone@${PINNED}}}"

echo "doctor: healthy"
echo "  run=${RUN_ID}"
echo "  python=${PY}"
echo "  claims_gate=${LOC}"
echo "  jwks=${KIT_DIR}/jwks.json kid=$("${PY}" -c "import json;print(json.load(open('${KIT_DIR}/jwks.json'))['keys'][0]['kid'])")"
echo "  fixture=kaia-mcp@253d6c8 tools=26 wallet=generate_wallet"
echo "  live-proxy: ${LIVE} kaia=${KAIA_SRC}"
