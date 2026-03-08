#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="denial_path"
SEED="0xDEADBEEF"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
TARGET_DIR="${DENIAL_PATH_TARGET_DIR:-/tmp/fcp-denial-path-flow}"

PREFLIGHT_DENY_TEST="budget_engine_with_policies_preflight_integration"
PREFLIGHT_DENY_INTEGRATION="no_mock_integration"
DEFAULT_DENY_LOG_TEST="logs_denied_invoke"
DECISION_RECEIPT_TEST="compliance_checks_simulate_and_decision_receipt"
EXPLAIN_HINT_TEST="load_receipt_from_json_error_response_preserves_recovery_hint"
REVOKED_RECEIPT_TEST="load_demo_deny_revoked_receipt"
ZONE_RECEIPT_TEST="load_demo_deny_zone_violation_receipt"
EXPIRED_RECEIPT_TEST="decision_receipt_with_explanation"

PREFLIGHT_DENY_LOG="${OUT_DIR}/${PREFLIGHT_DENY_TEST}.log"
DEFAULT_DENY_LOG="${OUT_DIR}/${DEFAULT_DENY_LOG_TEST}.log"
DECISION_RECEIPT_LOG="${OUT_DIR}/${DECISION_RECEIPT_TEST}.log"
EXPLAIN_HINT_LOG="${OUT_DIR}/${EXPLAIN_HINT_TEST}.log"
REVOKED_RECEIPT_LOG="${OUT_DIR}/${REVOKED_RECEIPT_TEST}.log"
ZONE_RECEIPT_LOG="${OUT_DIR}/${ZONE_RECEIPT_TEST}.log"
EXPIRED_RECEIPT_LOG="${OUT_DIR}/${EXPIRED_RECEIPT_TEST}.log"
VERIFICATION_SUMMARY="${OUT_DIR}/denial_path_contract_summary.json"

STEP_CONTEXT="null"
STEP_MODULE="unknown"
STEP_TEST="unknown"

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
  details="$(jq -cn \
    --arg module "${STEP_MODULE}" \
    --arg test_name "${STEP_TEST}" \
    --arg seed "${SEED}" \
    --argjson extra "${STEP_CONTEXT:-null}" \
    '($extra | if type == "object" then . else {} end) + {
      module: $module,
      test_name: $test_name,
      seed: $seed
    }')"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","log_version":"v2","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" \
    "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  STEP_CONTEXT="null"
  STEP_MODULE="unknown"
  STEP_TEST="unknown"

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

run_exact_lib_test() {
  local package="$1"
  local test_name="$2"
  local log_path="$3"

  mkdir -p "$(dirname "${log_path}")"
  (
    cd "${REPO_ROOT}"
    run_cargo test --target-dir "${TARGET_DIR}" -p "${package}" "${test_name}" --lib -- --nocapture
  ) > "${log_path}" 2>&1
}

run_exact_integration_test() {
  local package="$1"
  local integration_test="$2"
  local test_name="$3"
  local log_path="$4"

  mkdir -p "$(dirname "${log_path}")"
  (
    cd "${REPO_ROOT}"
    run_cargo test --target-dir "${TARGET_DIR}" -p "${package}" --test "${integration_test}" "${test_name}" -- --exact --nocapture
  ) > "${log_path}" 2>&1
}

run_exact_bin_test() {
  local package="$1"
  local bin_name="$2"
  local test_name="$3"
  local log_path="$4"

  mkdir -p "$(dirname "${log_path}")"
  (
    cd "${REPO_ROOT}"
    run_cargo test --target-dir "${TARGET_DIR}" -p "${package}" --bin "${bin_name}" "${test_name}" -- --nocapture
  ) > "${log_path}" 2>&1
}

step_verify_preflight_deny_policy() {
  STEP_MODULE="fcp-host::discovery"
  STEP_TEST="${PREFLIGHT_DENY_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-host" \
    --arg integration_test "${PREFLIGHT_DENY_INTEGRATION}" \
    --arg test_name "${PREFLIGHT_DENY_TEST}" \
    --arg log_path "${PREFLIGHT_DENY_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      target: "integration",
      integration_test: $integration_test,
      assertions: [
        "budget-backed preflight denies requests in the deny-enforcement zone",
        "warn-enforcement zones remain allowed, proving the deny result is policy-driven"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_integration_test \
    "fcp-host" \
    "${PREFLIGHT_DENY_INTEGRATION}" \
    "${PREFLIGHT_DENY_TEST}" \
    "${PREFLIGHT_DENY_LOG}"
}

step_verify_default_deny_with_decision_receipt_id() {
  STEP_MODULE="fcp-e2e::connector_suite"
  STEP_TEST="${DEFAULT_DENY_LOG_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-e2e" \
    --arg test_name "${DEFAULT_DENY_LOG_TEST}" \
    --arg log_path "${DEFAULT_DENY_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      target: "lib",
      assertions: [
        "default-deny invoke logs a deny decision with stable reason code FCP-3001",
        "denial log contains a decision_receipt_id for explainability"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_lib_test "fcp-e2e" "${DEFAULT_DENY_LOG_TEST}" "${DEFAULT_DENY_LOG}"
}

step_verify_compliance_denial_details() {
  STEP_MODULE="fcp-e2e::compliance"
  STEP_TEST="${DECISION_RECEIPT_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-e2e" \
    --arg test_name "${DECISION_RECEIPT_TEST}" \
    --arg log_path "${DECISION_RECEIPT_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      target: "lib",
      assertions: [
        "compliance harness records expected denial details for simulate + invoke",
        "decision receipt is required and produced for denied compliance flow"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_lib_test "fcp-e2e" "${DECISION_RECEIPT_TEST}" "${DECISION_RECEIPT_LOG}"
}

step_verify_explain_denial_reports() {
  STEP_MODULE="fcp-cli::explain"
  STEP_TEST="${EXPLAIN_HINT_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg explain_hint_log "${EXPLAIN_HINT_LOG}" \
    --arg revoked_log "${REVOKED_RECEIPT_LOG}" \
    --arg zone_log "${ZONE_RECEIPT_LOG}" \
    '{
      mode: "cargo_test",
      package: "fcp-cli",
      target: "bin:fcp",
      assertions: [
        "fcp explain decodes denied error responses from receipt files",
        "explain report preserves stable deny reason codes and recovery hints",
        "revoked-token and zone-violation deny receipts remain explainable"
      ],
      logs: [
        $explain_hint_log,
        $revoked_log,
        $zone_log
      ],
      test_name: "explain denial suite"
    }')"
  run_exact_bin_test "fcp-cli" "fcp" "${EXPLAIN_HINT_TEST}" "${EXPLAIN_HINT_LOG}"
  run_exact_bin_test "fcp-cli" "fcp" "${REVOKED_RECEIPT_TEST}" "${REVOKED_RECEIPT_LOG}"
  run_exact_bin_test "fcp-cli" "fcp" "${ZONE_RECEIPT_TEST}" "${ZONE_RECEIPT_LOG}"
}

step_verify_expired_receipt_explanation() {
  STEP_MODULE="fcp-core::audit"
  STEP_TEST="${EXPIRED_RECEIPT_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-core" \
    --arg test_name "${EXPIRED_RECEIPT_TEST}" \
    --arg log_path "${EXPIRED_RECEIPT_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      target: "lib",
      assertions: [
        "expired capability receipts retain the FCP-4020 reason code",
        "expired capability receipts preserve a human-readable explanation"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_lib_test "fcp-core" "${EXPIRED_RECEIPT_TEST}" "${EXPIRED_RECEIPT_LOG}"
}

step_emit_contract_summary() {
  STEP_MODULE="denial_path.contract"
  STEP_TEST="denial_path_contract_summary"

  [[ -s "${PREFLIGHT_DENY_LOG}" ]]
  [[ -s "${DEFAULT_DENY_LOG}" ]]
  [[ -s "${DECISION_RECEIPT_LOG}" ]]
  [[ -s "${EXPLAIN_HINT_LOG}" ]]
  [[ -s "${REVOKED_RECEIPT_LOG}" ]]
  [[ -s "${ZONE_RECEIPT_LOG}" ]]
  [[ -s "${EXPIRED_RECEIPT_LOG}" ]]

  grep -Eq "test result: ok\\." "${PREFLIGHT_DENY_LOG}"
  grep -Eq "test result: ok\\." "${DEFAULT_DENY_LOG}"
  grep -Eq "test result: ok\\." "${DECISION_RECEIPT_LOG}"
  grep -Eq "test result: ok\\." "${EXPLAIN_HINT_LOG}"
  grep -Eq "test result: ok\\." "${REVOKED_RECEIPT_LOG}"
  grep -Eq "test result: ok\\." "${ZONE_RECEIPT_LOG}"
  grep -Eq "test result: ok\\." "${EXPIRED_RECEIPT_LOG}"

  jq -n \
    --arg preflight_test "${PREFLIGHT_DENY_TEST}" \
    --arg deny_log_test "${DEFAULT_DENY_LOG_TEST}" \
    --arg decision_receipt_test "${DECISION_RECEIPT_TEST}" \
    --arg explain_hint_test "${EXPLAIN_HINT_TEST}" \
    --arg revoked_receipt_test "${REVOKED_RECEIPT_TEST}" \
    --arg zone_receipt_test "${ZONE_RECEIPT_TEST}" \
    --arg expired_receipt_test "${EXPIRED_RECEIPT_TEST}" \
    --arg preflight_log "${PREFLIGHT_DENY_LOG}" \
    --arg deny_log "${DEFAULT_DENY_LOG}" \
    --arg decision_receipt_log "${DECISION_RECEIPT_LOG}" \
    --arg explain_hint_log "${EXPLAIN_HINT_LOG}" \
    --arg revoked_receipt_log "${REVOKED_RECEIPT_LOG}" \
    --arg zone_receipt_log "${ZONE_RECEIPT_LOG}" \
    --arg expired_receipt_log "${EXPIRED_RECEIPT_LOG}" \
    '{
      contract_id: "contract.capability_denial_decision_receipt",
      scenario: "denial_path",
      verified_assertions: [
        "host discovery preflight denies requests when policy denies access",
        "default-deny invoke flow emits stable deny reason codes and decision receipt identifiers",
        "compliance denial flow records simulate details alongside denied invoke behavior",
        "fcp explain preserves denial reason codes, explanations, and recovery hints from receipt files",
        "revoked-token, expired-token, and zone-violation denial receipts remain explainable"
      ],
      source_tests: [
        {
          package: "fcp-host",
          target: "integration",
          integration_test: "no_mock_integration",
          test_name: $preflight_test,
          log_path: $preflight_log
        },
        {
          package: "fcp-e2e",
          target: "lib",
          test_name: $deny_log_test,
          log_path: $deny_log
        },
        {
          package: "fcp-e2e",
          target: "lib",
          test_name: $decision_receipt_test,
          log_path: $decision_receipt_log
        },
        {
          package: "fcp-cli",
          target: "bin:fcp",
          test_name: $explain_hint_test,
          log_path: $explain_hint_log
        },
        {
          package: "fcp-cli",
          target: "bin:fcp",
          test_name: $revoked_receipt_test,
          log_path: $revoked_receipt_log
        },
        {
          package: "fcp-cli",
          target: "bin:fcp",
          test_name: $zone_receipt_test,
          log_path: $zone_receipt_log
        },
        {
          package: "fcp-core",
          target: "lib",
          test_name: $expired_receipt_test,
          log_path: $expired_receipt_log
        }
      ]
    }' > "${VERIFICATION_SUMMARY}"

  STEP_CONTEXT="$(jq -cn \
    --arg summary_path "${VERIFICATION_SUMMARY}" \
    '{
      mode: "summary",
      verification_summary: $summary_path
    }')"
}

require_cmd cargo
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "verify_preflight_deny_policy" 1 "[\"${PREFLIGHT_DENY_LOG}\"]" step_verify_preflight_deny_policy
run_step "verify_default_deny_with_decision_receipt_id" 2 "[\"${DEFAULT_DENY_LOG}\"]" step_verify_default_deny_with_decision_receipt_id
run_step "verify_compliance_denial_details" 3 "[\"${DECISION_RECEIPT_LOG}\"]" step_verify_compliance_denial_details
run_step "verify_explain_denial_reports" 4 "[\"${EXPLAIN_HINT_LOG}\",\"${REVOKED_RECEIPT_LOG}\",\"${ZONE_RECEIPT_LOG}\"]" step_verify_explain_denial_reports
run_step "verify_expired_receipt_explanation" 5 "[\"${EXPIRED_RECEIPT_LOG}\"]" step_verify_expired_receipt_explanation
run_step "emit_contract_summary" 6 "[\"${VERIFICATION_SUMMARY}\"]" step_emit_contract_summary

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
