#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="policy_bundle_flow"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
RAW_OUTPUT="${RAW_OUTPUT:-${OUT_DIR}/${SCRIPT_NAME}.raw.log}"
DETAIL_JSONL="${DETAIL_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.details.jsonl}"

EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
STEP_CONTEXT="null"

if [[ -n "${CARGO_CMD:-}" ]]; then
  read -r -a CARGO_CMD_ARR <<< "${CARGO_CMD}"
elif command -v rch >/dev/null 2>&1; then
  CARGO_CMD_ARR=(env TMPDIR=/tmp rch exec -- env FCP_POLICY_BUNDLE_E2E_PRINT_JSONL=1 CARGO_TARGET_DIR=.target-policy-bundle-flow cargo)
else
  CARGO_CMD_ARR=(cargo)
fi

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
  hex=$(printf '%s-%s' "${SCRIPT_NAME}" "${step_number}" | hash256 | awk '{print $1}')
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
  if [[ -z "${EXPECTED_FAILURE}" && -z "${ACTUAL_FAILURE}" && "${STEP_CONTEXT}" == "null" ]]; then
    printf 'null'
    return 0
  fi
  printf '{"expected_failure":%s,"actual_failure":%s,"context":%s}' \
    "$(json_or_null "${EXPECTED_FAILURE}")" \
    "$(json_or_null "${ACTUAL_FAILURE}")" \
    "${STEP_CONTEXT}"
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
  printf '{"timestamp":"%s","log_version":"v2","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
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
    log_step "${step}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    ACTUAL_FAILURE="exit_code_${rc}"
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit "${rc}"
  fi
}

step_prepare() {
  mkdir -p "${OUT_DIR}"
  : > "${LOG_JSONL}"
  : > "${RAW_OUTPUT}"
  : > "${DETAIL_JSONL}"
}

step_run_bundle_flow_test() {
  (
    cd "${REPO_ROOT}"
    FCP_POLICY_BUNDLE_E2E_PRINT_JSONL=1 \
      "${CARGO_CMD_ARR[@]}" test -p fcp-cli --test policy_e2e_test \
      e2e_policy_bundle_apply_and_rollback_flow -- --nocapture
  ) 2>&1 | tee "${RAW_OUTPUT}"
  awk '/^\{.*"test_name":"e2e_policy_bundle_apply_and_rollback_flow"/ { print }' "${RAW_OUTPUT}" > "${DETAIL_JSONL}"
  [[ -s "${DETAIL_JSONL}" ]]
  cat "${DETAIL_JSONL}" >> "${LOG_JSONL}"
}

step_verify_bundle_flow_logs() {
  local required_stages=(
    create_before_bundle
    create_after_bundle
    bundle_diff
    bundle_preview
    simulate_before_apply
    apply_before_bundle
    apply_after_bundle
    simulate_after_apply
    rollback_to_before_bundle
    simulate_after_rollback
  )
  local stage
  for stage in "${required_stages[@]}"; do
    grep -q "\"stage\":\"${stage}\"" "${DETAIL_JSONL}"
  done
  grep -q '"reason_codes"' "${DETAIL_JSONL}"
  grep -q '"bundle_id":"bundle-after"' "${DETAIL_JSONL}"
  grep -q '"bundle_id":"bundle-before"' "${DETAIL_JSONL}"
}

require_cmd cargo
require_cmd awk
if command -v rch >/dev/null 2>&1 && [[ " ${CARGO_CMD_ARR[*]} " == *" rch "* ]]; then
  require_cmd rch
fi

run_step "prepare_output" 1 \
  "[\"${LOG_JSONL}\",\"${RAW_OUTPUT}\",\"${DETAIL_JSONL}\"]" \
  "" \
  "{\"repo_root\":\"${REPO_ROOT}\"}" \
  step_prepare

run_step "run_policy_bundle_flow_test" 2 \
  "[\"${RAW_OUTPUT}\",\"${DETAIL_JSONL}\"]" \
  "" \
  "{\"test_name\":\"e2e_policy_bundle_apply_and_rollback_flow\",\"cargo_command\":\"${CARGO_CMD_ARR[*]}\"}" \
  step_run_bundle_flow_test

run_step "verify_policy_bundle_logs" 3 \
  "[\"${DETAIL_JSONL}\",\"${LOG_JSONL}\"]" \
  "" \
  "{\"required_stages\":10}" \
  step_verify_bundle_flow_logs
