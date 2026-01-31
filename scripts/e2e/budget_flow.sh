#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_budget_flow"
SEED="0xDEADBEEF"
ZONE="${ZONE:-z:work}"
CONNECTOR="${CONNECTOR:-fcp.test-echo}"
OPERATION="${OPERATION:-echo}"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

BUDGET_LIMIT="${BUDGET_LIMIT:-100}"
BUDGET_WINDOW_SECONDS="${BUDGET_WINDOW_SECONDS:-60}"
TOKENS_BELOW_LIMIT="${TOKENS_BELOW_LIMIT:-80}"
TOKENS_OVER_LIMIT="${TOKENS_OVER_LIMIT:-50}"

EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
STEP_CONTEXT="null"

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

json_or_null() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    printf 'null'
  else
    printf '"%s"' "${value}"
  fi
}

details_json() {
  if [[ -z "${EXPECTED_FAILURE}" && -z "${ACTUAL_FAILURE}" ]]; then
    printf 'null'
    return 0
  fi
  printf '{"expected_failure":%s,"actual_failure":%s}' \
    "$(json_or_null "${EXPECTED_FAILURE}")" \
    "$(json_or_null "${ACTUAL_FAILURE}")"
}

log_step() {
  local step="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id
  local details

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"
  details="$(details_json)"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"context":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${STEP_CONTEXT}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  local expected_failure="$4"
  local context_json="$5"
  shift 5

  local start_ms end_ms duration_ms rc
  EXPECTED_FAILURE="${expected_failure}"
  ACTUAL_FAILURE=""
  STEP_CONTEXT="${context_json}"

  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    if [[ -n "${EXPECTED_FAILURE}" ]]; then
      ACTUAL_FAILURE="${EXPECTED_FAILURE}"
    fi
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    ACTUAL_FAILURE="exit_code_${rc}"
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

budget_policy_json() {
  cat <<POLICY
{"enforcement":"deny","budgets":[{"metric":"tokens","limit":${BUDGET_LIMIT},"window_seconds":${BUDGET_WINDOW_SECONDS}}]}
POLICY
}

usage_metrics_json() {
  local amount="$1"
  cat <<METRICS
[{"kind":"tokens","amount":${amount}}]
METRICS
}

step_init() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
  fcp-harness health --expect=healthy
}

step_install() {
  fcp install "${CONNECTOR}" --zone "${ZONE}"
}

step_set_budget() {
  mkdir -p "${OUT_DIR}"
  budget_policy_json > "${OUT_DIR}/usage_budget.json"
  fcp-harness set-policy \
    --zone "${ZONE}" \
    --usage-budget-file "${OUT_DIR}/usage_budget.json"
}

step_create_token() {
  fcp-harness create-token \
    --connector "${CONNECTOR}" \
    --operations "${OPERATION}" \
    --zone "${ZONE}" \
    --ttl 3600 \
    --output "${OUT_DIR}/token.cbor"
}

step_invoke_within_budget() {
  usage_metrics_json "${TOKENS_BELOW_LIMIT}" > "${OUT_DIR}/usage_metrics_ok.json"
  fcp-harness invoke \
    --connector "${CONNECTOR}" \
    --operation "${OPERATION}" \
    --args '{"message":"budget ok"}' \
    --token "${OUT_DIR}/token.cbor" \
    --usage-metrics-file "${OUT_DIR}/usage_metrics_ok.json" \
    --output "${OUT_DIR}/receipt_ok.cbor"
}

step_invoke_over_budget() {
  usage_metrics_json "${TOKENS_OVER_LIMIT}" > "${OUT_DIR}/usage_metrics_over.json"
  fcp-harness invoke \
    --connector "${CONNECTOR}" \
    --operation "${OPERATION}" \
    --args '{"message":"budget over"}' \
    --token "${OUT_DIR}/token.cbor" \
    --usage-metrics-file "${OUT_DIR}/usage_metrics_over.json" \
    --expect-failure FCP-6004 \
    --output "${OUT_DIR}/budget_denial.cbor"
}

step_verify_budget_denial() {
  fcp explain --receipt "${OUT_DIR}/budget_denial.cbor" --output "${OUT_DIR}/budget_decision.json"
  jq -e '.reason_code == "FCP-6004"' "${OUT_DIR}/budget_decision.json" >/dev/null
}

step_teardown() {
  fcp-harness teardown
}

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

base_context=$(printf '{"zone_id":"%s","connector_id":"%s","operation":"%s"}' "${ZONE}" "${CONNECTOR}" "${OPERATION}")

run_step "init" 1 "[]" "" "${base_context}" step_init
run_step "install_connector" 2 "[]" "" "${base_context}" step_install
run_step "set_budget_policy" 3 "[\"${OUT_DIR}/usage_budget.json\"]" "" "${base_context}" step_set_budget
run_step "create_token" 4 "[\"${OUT_DIR}/token.cbor\"]" "" "${base_context}" step_create_token

context_ok=$(printf '{"zone_id":"%s","connector_id":"%s","operation":"%s","usage_metrics_file":"%s","budget_limit":%s}' \
  "${ZONE}" "${CONNECTOR}" "${OPERATION}" "${OUT_DIR}/usage_metrics_ok.json" "${BUDGET_LIMIT}")
run_step "invoke_within_budget" 5 "[\"${OUT_DIR}/receipt_ok.cbor\",\"${OUT_DIR}/usage_metrics_ok.json\"]" "" "${context_ok}" step_invoke_within_budget

context_over=$(printf '{"zone_id":"%s","connector_id":"%s","operation":"%s","usage_metrics_file":"%s","budget_limit":%s}' \
  "${ZONE}" "${CONNECTOR}" "${OPERATION}" "${OUT_DIR}/usage_metrics_over.json" "${BUDGET_LIMIT}")
run_step "invoke_over_budget" 6 "[\"${OUT_DIR}/budget_denial.cbor\",\"${OUT_DIR}/usage_metrics_over.json\"]" "FCP-6004" "${context_over}" step_invoke_over_budget
run_step "verify_budget_denial" 7 "[\"${OUT_DIR}/budget_decision.json\"]" "" "${context_over}" step_verify_budget_denial
run_step "teardown" 8 "[]" "" "${base_context}" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
