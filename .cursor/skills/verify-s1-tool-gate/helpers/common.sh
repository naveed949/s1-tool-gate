#!/usr/bin/env bash
# Shared paths for verify-s1-tool-gate. Sourced by the other helpers; do not run directly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CURRENT_FILE="/tmp/s1-verify-current"

RUN_ID="${S1_VERIFY_RUN_ID:-}"
if [[ -z "${RUN_ID}" && -f "${CURRENT_FILE}" ]]; then
  RUN_ID="$(cat "${CURRENT_FILE}")"
fi
if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="$(date +%Y%m%dT%H%M%S)-$$"
fi

# Scratch state (TEST-ONLY key, jwks, instance.json). Only launch.sh creates it.
INSTANCE_DIR="/tmp/s1-verify-${RUN_ID}"
INSTANCE_FILE="${INSTANCE_DIR}/instance.json"
KIT_DIR="${INSTANCE_DIR}/kit"
# Proof artifacts. Survive cleanup. Gitignored.
EVIDENCE_DIR="${SKILL_DIR}/evidence/${RUN_ID}"
VENV="${S1_VERIFY_VENV:-${REPO_ROOT}/.venv}"
PY="${VENV}/bin/python"

ISSUER="https://idp.test.invalid"
AUDIENCE="kaia-mcp"

# Evidence dir is created by launch.sh and drive.sh only.
export REPO_ROOT SKILL_DIR RUN_ID INSTANCE_DIR INSTANCE_FILE KIT_DIR EVIDENCE_DIR VENV PY ISSUER AUDIENCE
