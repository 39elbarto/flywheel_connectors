#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_rate_limit_flow"
SEED="0xDEADBEEF"
ZONE="${ZONE:-z:work}"
CONNECTOR_ID="${CONNECTOR_ID:-fcp.twitter:social:v1}"
OPERATION="${OPERATION:-twitter.get_timeline}"
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

run_step() {
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
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

step_init() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
  fcp-harness health --expect=healthy
}

step_introspect_limits() {
  fcp connector introspect "${CONNECTOR_ID}" --json > "${OUT_DIR}/introspect.json"
  jq -e '.rate_limits.limits | length > 0' "${OUT_DIR}/introspect.json" >/dev/null
  jq -e --arg op "${OPERATION}" '.rate_limits.tool_pool_map[$op] | length > 0' "${OUT_DIR}/introspect.json" >/dev/null
}

step_info_limits() {
  fcp connector info "${CONNECTOR_ID}" --json > "${OUT_DIR}/info.json"
  jq -e '.rate_limits.limits | length > 0' "${OUT_DIR}/info.json" >/dev/null
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR_ID}" \
    --operations="${OPERATION}" \
    --zone="${ZONE}" \
    --ttl=60 \
    --output="${OUT_DIR}/token.cbor"
}

step_rate_limited_invoke() {
  fcp-harness invoke \
    --connector="${CONNECTOR_ID}" \
    --operation="${OPERATION}" \
    --args='{"query":"rate-limit"}' \
    --token="${OUT_DIR}/token.cbor" \
    --expect-failure=FCP-3002 \
    --output="${OUT_DIR}/rate_limit_denial.cbor"
}

step_verify_retry_metadata() {
  fcp explain --receipt="${OUT_DIR}/rate_limit_denial.cbor" --output="${OUT_DIR}/decision.json"
  jq -e '.decision == "deny"' "${OUT_DIR}/decision.json" >/dev/null
  jq -e '.reason_code == "FCP-3002"' "${OUT_DIR}/decision.json" >/dev/null
  jq -e '.retry_after_ms != null' "${OUT_DIR}/decision.json" >/dev/null
}

step_teardown() {
  fcp-harness teardown
}

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "init" 1 "[]" step_init
run_step "introspect_rate_limits" 2 "[\"${OUT_DIR}/introspect.json\"]" step_introspect_limits
run_step "info_rate_limits" 3 "[\"${OUT_DIR}/info.json\"]" step_info_limits
run_step "create_token" 4 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "invoke_rate_limited" 5 "[\"${OUT_DIR}/rate_limit_denial.cbor\"]" step_rate_limited_invoke
run_step "verify_retry_metadata" 6 "[\"${OUT_DIR}/decision.json\"]" step_verify_retry_metadata
run_step "teardown" 7 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
