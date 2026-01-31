#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_egress_denial"
SEED="0xDEADBEEF"
MANIFEST_PATH="${MANIFEST_PATH:-connectors/openai/manifest.toml}"
OPERATION_ID="${OPERATION_ID:-chat}"
DENY_URL="${DENY_URL:-http://127.0.0.1:8080}"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

hash256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256
    return 0
  fi
  echo "Missing required command: sha256sum/shasum/openssl" >&2
  exit 1
}

correlation_id_for_step() {
  local step_number="$1"
  local hex
  hex=$(printf '%s-%s-%s' "${SCRIPT_NAME}" "${SEED}" "${step_number}" | hash256 | awk '{print $1}')
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" >> "${LOG_JSONL}"
}

run_step_expect_failure() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit 1
  fi

  log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
}

step_egress_denied() {
  fcp net explain \
    --url "${DENY_URL}" \
    --manifest-path "${MANIFEST_PATH}" \
    --operation "${OPERATION_ID}" \
    --json > "${OUT_DIR}/egress_denial.json"

  jq -e '.allowed == false' "${OUT_DIR}/egress_denial.json" >/dev/null
  jq -e '.reason_code | length > 0' "${OUT_DIR}/egress_denial.json" >/dev/null
}

require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step_expect_failure "egress_denied" 1 "[\"${OUT_DIR}/egress_denial.json\"]" step_egress_denied

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
