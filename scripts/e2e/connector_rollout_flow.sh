#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="connector_rollout_flow"
SEED="0xC0FFEE14"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
TARGET_DIR="${CONNECTOR_ROLLOUT_TARGET_DIR:-/tmp/fcp-connector-rollout-flow}"

BASELINE_VERSION="1.0.0"
CANARY_VERSION="1.0.1"
PIN_CONNECTOR_ID="fcp.test.rollout-pin-baseline:utility:1.0.0"
CANARY_CONNECTOR_ID="fcp.test.rollout-http:utility:1.0.0"
ROLLBACK_CONNECTOR_ID="fcp.test.rollout-rollback:utility:1.0.0"

PIN_TEST="fcp_host_binary_rollout_pin_route_pins_baseline_version"
CANARY_TEST="fcp_host_binary_rollout_routes_schedule_and_promote_canary"
ROLLBACK_TEST="fcp_host_binary_rollout_routes_rollback_and_emit_transition_logs"

PIN_LOG="${OUT_DIR}/${PIN_TEST}.log"
CANARY_LOG="${OUT_DIR}/${CANARY_TEST}.log"
ROLLBACK_LOG="${OUT_DIR}/${ROLLBACK_TEST}.log"
VERIFICATION_SUMMARY="${OUT_DIR}/verify_restore_and_audit_event.summary.json"

STEP_CONTEXT="null"
STEP_CONNECTOR_ID="unknown"
STEP_VERSION="unknown"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_cargo() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- cargo "$@"
    return $?
  fi
  cargo "$@"
}

run_fcp_e2e() {
  if command -v fcp-e2e >/dev/null 2>&1; then
    fcp-e2e "$@"
    return $?
  fi
  run_cargo run --target-dir "${TARGET_DIR}" -q -p fcp-e2e --bin fcp-e2e -- "$@"
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
  local stage="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id
  local details

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"
  details="$(jq -cn \
    --arg stage "${stage}" \
    --arg connector_id "${STEP_CONNECTOR_ID}" \
    --arg version "${STEP_VERSION}" \
    --argjson extra "${STEP_CONTEXT:-null}" \
    '($extra | if type == "object" then . else {} end) + {
      stage: $stage,
      connector_id: $connector_id,
      version: $version
    }')"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","log_version":"v2","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${stage}" "${step_number}" "${correlation_id}" \
    "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local stage="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  STEP_CONTEXT="null"
  STEP_CONNECTOR_ID="unknown"
  STEP_VERSION="unknown"
  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    log_step "${stage}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    log_step "${stage}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

run_host_test() {
  local test_name="$1"
  local log_path="$2"

  mkdir -p "$(dirname "${log_path}")"
  (
    cd "${REPO_ROOT}"
    run_cargo test --target-dir "${TARGET_DIR}" -p fcp-host --test host_connector_integration "${test_name}" -- --nocapture
  ) > "${log_path}" 2>&1
}

step_pin_baseline_version() {
  STEP_CONNECTOR_ID="${PIN_CONNECTOR_ID}"
  STEP_VERSION="${BASELINE_VERSION}"
  STEP_CONTEXT="$(jq -cn \
    --arg connector_id "${STEP_CONNECTOR_ID}" \
    --arg version "${STEP_VERSION}" \
    --arg test_name "${PIN_TEST}" \
    --arg log_path "${PIN_LOG}" \
    '{
      mode: "cargo_test",
      connector_id: $connector_id,
      version: $version,
      test_name: $test_name,
      log_path: $log_path
    }')"
  run_host_test "${PIN_TEST}" "${PIN_LOG}"
}

step_set_canary_rollout() {
  STEP_CONNECTOR_ID="${CANARY_CONNECTOR_ID}"
  STEP_VERSION="${CANARY_VERSION}"
  STEP_CONTEXT="$(jq -cn \
    --arg connector_id "${STEP_CONNECTOR_ID}" \
    --arg baseline_version "${BASELINE_VERSION}" \
    --arg version "${STEP_VERSION}" \
    --arg test_name "${CANARY_TEST}" \
    --arg log_path "${CANARY_LOG}" \
    '{
      mode: "cargo_test",
      connector_id: $connector_id,
      baseline_version: $baseline_version,
      canary_version: $version,
      test_name: $test_name,
      log_path: $log_path
    }')"
  run_host_test "${CANARY_TEST}" "${CANARY_LOG}"
}

step_simulate_failure_verify_rollback() {
  STEP_CONNECTOR_ID="${ROLLBACK_CONNECTOR_ID}"
  STEP_VERSION="${CANARY_VERSION}"
  STEP_CONTEXT="$(jq -cn \
    --arg connector_id "${STEP_CONNECTOR_ID}" \
    --arg baseline_version "${BASELINE_VERSION}" \
    --arg version "${STEP_VERSION}" \
    --arg test_name "${ROLLBACK_TEST}" \
    --arg log_path "${ROLLBACK_LOG}" \
    '{
      mode: "cargo_test",
      connector_id: $connector_id,
      baseline_version: $baseline_version,
      canary_version: $version,
      expected_decision: "rollback",
      test_name: $test_name,
      log_path: $log_path
    }')"
  run_host_test "${ROLLBACK_TEST}" "${ROLLBACK_LOG}"
}

step_verify_restore_and_audit_event() {
  STEP_CONNECTOR_ID="${ROLLBACK_CONNECTOR_ID}"
  STEP_VERSION="${BASELINE_VERSION}"

  [[ -s "${ROLLBACK_LOG}" ]]
  grep -Eq "test .*${ROLLBACK_TEST}.* ok" "${ROLLBACK_LOG}"

  jq -n \
    --arg connector_id "${STEP_CONNECTOR_ID}" \
    --arg baseline_version "${STEP_VERSION}" \
    --arg canary_version "${CANARY_VERSION}" \
    --arg source_test "${ROLLBACK_TEST}" \
    --arg log_path "${ROLLBACK_LOG}" \
    '{
      connector_id: $connector_id,
      baseline_version: $baseline_version,
      canary_version: $canary_version,
      source_test: $source_test,
      log_path: $log_path,
      verified_assertions: [
        "automatic rollout evaluation returns RolloutDecision::Rollback after the simulated failure",
        "rollback_target_version is restored to the pinned baseline version",
        "pin status route reports the baseline version after automatic rollback",
        "audit_event.reason_code is consecutive_failures_exceeded",
        "audit_event.evidence_digest starts with blake3-256:"
      ]
    }' > "${VERIFICATION_SUMMARY}"

  STEP_CONTEXT="$(jq -cn \
    --arg connector_id "${STEP_CONNECTOR_ID}" \
    --arg version "${STEP_VERSION}" \
    --arg source_test "${ROLLBACK_TEST}" \
    --arg log_path "${ROLLBACK_LOG}" \
    --arg summary_path "${VERIFICATION_SUMMARY}" \
    '{
      mode: "log_verification",
      connector_id: $connector_id,
      version: $version,
      source_test: $source_test,
      log_path: $log_path,
      verification_summary: $summary_path
    }')"
}

require_cmd cargo
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "pin_baseline_version" 1 "[\"${PIN_LOG}\"]" step_pin_baseline_version
run_step "set_canary_rollout" 2 "[\"${CANARY_LOG}\"]" step_set_canary_rollout
run_step "simulate_failure_verify_rollback" 3 "[\"${ROLLBACK_LOG}\"]" step_simulate_failure_verify_rollback
run_step "verify_restore_and_audit_event" 4 "[\"${VERIFICATION_SUMMARY}\"]" step_verify_restore_and_audit_event

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
