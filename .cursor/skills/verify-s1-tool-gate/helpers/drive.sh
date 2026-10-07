#!/usr/bin/env bash
# Drive one mapped feature of the claims gate CLI the way a partner integration would.
# Usage: helpers/drive.sh <scope-mapping|token-validation|wallet-escalation|kaia-enforcement-demo>
# Writes decision JSON under ${EVIDENCE_DIR}/<feature>/ (never the tokens) and asserts literal outcomes.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

FEATURE="${1:-}"
FEATURES="scope-mapping|token-validation|wallet-escalation|kaia-enforcement-demo"
[[ -n "${FEATURE}" ]] || { echo "Usage: helpers/drive.sh <${FEATURES}>" >&2; exit 2; }
[[ -f "${INSTANCE_FILE}" ]] || { echo "drive: missing ${INSTANCE_FILE}; run launch.sh" >&2; exit 1; }

OUT="${EVIDENCE_DIR}/${FEATURE}"
mkdir -p "${OUT}"
cd "${REPO_ROOT}"
TOKENS=()
FAILS=0

# mint [testkit mint flags...] -> prints a JWT signed by this run's TEST-ONLY key
mint() { "${PY}" -m claims_gate testkit mint --dir "${KIT_DIR}" "$@"; }

# decide <case-name> <tool> <authorization-value-or-empty> <expected-choice> <expected-reasonCode> [decide flags...]
decide() {
  local name="$1" tool="$2" auth="$3" want_choice="$4" want_reason="$5"; shift 5
  local rc=0
  if [[ -n "${auth}" ]]; then
    S1_AUTHORIZATION="${auth}" "${PY}" -m claims_gate decide --jwks "${KIT_DIR}/jwks.json" \
      --issuer "${ISSUER}" --audience "${AUDIENCE}" --tool "${tool}" "$@" > "${OUT}/${name}.json" || rc=$?
  else
    env -u S1_AUTHORIZATION "${PY}" -m claims_gate decide --jwks "${KIT_DIR}/jwks.json" \
      --issuer "${ISSUER}" --audience "${AUDIENCE}" --tool "${tool}" "$@" > "${OUT}/${name}.json" || rc=$?
  fi
  echo "${rc}" > "${OUT}/${name}.exit"
  local got
  got="$("${PY}" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["choice"], d["reasonCode"])' "${OUT}/${name}.json")"
  if [[ "${rc}" == "0" && "${got}" == "${want_choice} ${want_reason}" ]]; then
    echo "  ok   ${name}: ${tool} -> ${got}"
  else
    echo "  FAIL ${name}: ${tool} -> '${got}' (exit ${rc}), expected '${want_choice} ${want_reason}'"
    FAILS=$((FAILS + 1))
  fi
}

case "${FEATURE}" in
  scope-mapping)
    READ="$(mint --scope 'kaia:read')"; TOKENS+=("${READ}")
    ENC="$(mint --scope 'kaia:read kaia:encode')"; TOKENS+=("${ENC}")
    decide read-allow get_kaia_balance "Bearer ${READ}" allow claims_allow
    decide read-allow-contract read_contract "Bearer ${READ}" allow claims_allow
    decide read-denied-encode encode_function_data "Bearer ${READ}" deny claims_insufficient_scope
    decide encode-allow encode_function_data "Bearer ${ENC}" allow claims_allow
    decide unknown-tool transfer_kaia "Bearer ${ENC}" deny claims_unknown_tool
    # Entry point 2: header value from a file (--authorization-file) instead of env.
    AUTHZ_FILE="${INSTANCE_DIR}/authorization.txt"
    ( umask 077; printf 'Bearer %s\n' "${READ}" > "${AUTHZ_FILE}" )
    decide authz-file-allow get_kaia_balance "" allow claims_allow --authorization-file "${AUTHZ_FILE}"
    rm -f "${AUTHZ_FILE}"
    ;;
  token-validation)
    EXPIRED="$(mint --exp-in -5)"; TOKENS+=("${EXPIRED}")
    WRONG_AUD="$(mint --aud other-api)"; TOKENS+=("${WRONG_AUD}")
    WRONG_ISS="$(mint --iss https://evil.test.invalid)"; TOKENS+=("${WRONG_ISS}")
    FORGED="$(mint --untrusted)"; TOKENS+=("${FORGED}")
    NO_SUB="$(mint --sub '')"; TOKENS+=("${NO_SUB}")
    decide unauthenticated get_kaia_balance "" deny claims_unauthenticated
    decide non-bearer get_kaia_balance "Basic dXNlcjpwYXNz" deny claims_unauthenticated
    decide malformed get_kaia_balance "Bearer not-a-jwt" deny claims_invalid_token
    decide expired get_kaia_balance "Bearer ${EXPIRED}" deny claims_expired
    decide wrong-audience get_kaia_balance "Bearer ${WRONG_AUD}" deny claims_audience_mismatch
    decide wrong-issuer get_kaia_balance "Bearer ${WRONG_ISS}" deny claims_issuer_mismatch
    decide forged-signature get_kaia_balance "Bearer ${FORGED}" deny claims_invalid_token
    decide missing-sub get_kaia_balance "Bearer ${NO_SUB}" deny claims_missing_claim
    # Operator misconfiguration: unreadable JWKS is a hard error (exit 2), never a decision.
    rc=0
    S1_AUTHORIZATION="Bearer ${EXPIRED}" "${PY}" -m claims_gate decide --jwks "${INSTANCE_DIR}/no-such-jwks.json" \
      --issuer "${ISSUER}" --audience "${AUDIENCE}" --tool get_kaia_balance \
      > "${OUT}/missing-jwks.stdout" 2> "${OUT}/missing-jwks.stderr" || rc=$?
    echo "${rc}" > "${OUT}/missing-jwks.exit"
    if [[ "${rc}" == "2" && ! -s "${OUT}/missing-jwks.stdout" ]]; then
      echo "  ok   missing-jwks: exit 2, no decision printed"
    else
      echo "  FAIL missing-jwks: exit ${rc}, stdout bytes $(wc -c < "${OUT}/missing-jwks.stdout")"
      FAILS=$((FAILS + 1))
    fi
    ;;
  wallet-escalation)
    WALLET="$(mint --scope 'kaia:read kaia:wallet')"; TOKENS+=("${WALLET}")
    NOWALLET="$(mint --scope 'kaia:read kaia:encode')"; TOKENS+=("${NOWALLET}")
    decide wallet-escalate generate_wallet "Bearer ${WALLET}" escalate claims_wallet_escalate
    decide wallet-no-scope generate_wallet "Bearer ${NOWALLET}" deny claims_insufficient_scope
    decide wallet-default-deny generate_wallet "Bearer ${WALLET}" deny claims_wallet_denied --wallet-default deny
    ;;
  kaia-enforcement-demo)
    rc=0; "${PY}" -m claims_gate demo > "${OUT}/demo-report.json" || rc=$?
    echo "${rc}" > "${OUT}/demo-report.exit"
    rc2=0; "${PY}" -m claims_gate demo --wallet-default deny > "${OUT}/demo-report-wallet-deny.json" || rc2=$?
    echo "${rc2}" > "${OUT}/demo-report-wallet-deny.exit"
    if "${PY}" - "${OUT}" "${rc}" "${rc2}" <<'PY'
import json, sys
out, rc, rc2 = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
r = json.load(open(f"{out}/demo-report.json"))
d = json.load(open(f"{out}/demo-report-wallet-deny.json"))
s = r["summary"]
problems = []
if rc != 0 or rc2 != 0: problems.append(f"exit codes {rc},{rc2}")
if (s["passed"], s["total"]) != (22, 22): problems.append(f"passed {s['passed']}/{s['total']}")
if (s["allow"], s["deny"], s["escalate"]) != (3, 18, 1): problems.append(f"counts {s['allow']},{s['deny']},{s['escalate']}")
if sorted(s["stubCalls"]) != ["encode_function_data", "get_chain_info", "get_kaia_balance"]: problems.append(f"stub calls {s['stubCalls']}")
if s["walletStubCalls"] != 0: problems.append("wallet stub ran")
for c in r["cases"]:
    if c["sideEffect"] != (c["decision"]["choice"] == "allow"): problems.append(f"sideEffect mismatch {c['id']}")
w = next(c for c in d["cases"] if c["id"] == "wallet-escalate")
if (w["decision"]["choice"], w["decision"]["reasonCode"], w["escalated"]) != ("deny", "claims_wallet_denied", False): problems.append("wallet-default deny variant")
if d["summary"]["passed"] != d["summary"]["total"]: problems.append("wallet-deny demo not all passed")
if problems:
    print("  FAIL demo: " + "; ".join(problems)); sys.exit(1)
print(f"  ok   demo: {s['passed']}/{s['total']} golden cases, allow/deny/escalate={s['allow']}/{s['deny']}/{s['escalate']}, stub ran only for {sorted(s['stubCalls'])}, wallet stub calls=0")
print("  ok   demo --wallet-default deny: wallet-escalate -> deny claims_wallet_denied, not escalated")
PY
    then :; else FAILS=$((FAILS + 1)); fi
    ;;
  *)
    echo "drive: unknown feature ${FEATURE} (expected ${FEATURES})" >&2
    exit 2
    ;;
esac

# Tokens must never land in evidence.
for t in "${TOKENS[@]+"${TOKENS[@]}"}"; do
  if grep -rqF -- "${t}" "${OUT}"; then
    echo "  FAIL token-leak: a minted token appears under ${OUT}"
    FAILS=$((FAILS + 1))
  fi
done
echo "  token-leak check: ${#TOKENS[@]} minted token(s) searched under ${OUT}"

echo "${OUT}" > "${EVIDENCE_DIR}/last-feature-path.txt"
if [[ "${FAILS}" -gt 0 ]]; then
  echo "drive ${FEATURE}: ${FAILS} failure(s); evidence at ${OUT}" >&2
  exit 1
fi
echo "drive ${FEATURE}: ok; evidence at ${OUT}"
