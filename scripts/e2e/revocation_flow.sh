#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="revocation_flow"
SEED="0xDEADBEEF"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
TARGET_DIR="${REVOCATION_FLOW_TARGET_DIR:-/tmp/fcp-revocation-flow}"

CAPABILITY_FLOW_TEST="logs_capability_revocation_flow"
ISSUER_FLOW_TEST="logs_issuer_revocation_flow"
CAPABILITY_PROPAGATION_TEST="scenario_capability_revocation"
ISSUER_PROPAGATION_TEST="scenario_issuer_key_revocation"
EXPLAIN_REVOKED_TEST="load_demo_deny_revoked_receipt"

CAPABILITY_FLOW_LOG="${OUT_DIR}/${CAPABILITY_FLOW_TEST}.log"
ISSUER_FLOW_LOG="${OUT_DIR}/${ISSUER_FLOW_TEST}.log"
CAPABILITY_PROPAGATION_LOG="${OUT_DIR}/${CAPABILITY_PROPAGATION_TEST}.log"
ISSUER_PROPAGATION_LOG="${OUT_DIR}/${ISSUER_PROPAGATION_TEST}.log"
EXPLAIN_REVOKED_LOG="${OUT_DIR}/${EXPLAIN_REVOKED_TEST}.log"
VERIFICATION_SUMMARY="${OUT_DIR}/revocation_flow_contract_summary.json"

STEP_CONTEXT="null"
STEP_MODULE="unknown"
STEP_TEST="unknown"

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

step_verify_capability_token_revocation_flow() {
  STEP_MODULE="fcp-e2e::connector_suite"
  STEP_TEST="${CAPABILITY_FLOW_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-e2e" \
    --arg test_name "${CAPABILITY_FLOW_TEST}" \
    --arg log_path "${CAPABILITY_FLOW_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      target: "lib",
      assertions: [
        "issue -> use -> revoke -> denial succeeds deterministically for a capability token",
        "denied invoke reports stable reason code FCP-2201",
        "decision receipt evidence references the revocation object"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_lib_test "fcp-e2e" "${CAPABILITY_FLOW_TEST}" "${CAPABILITY_FLOW_LOG}"
}

step_verify_issuer_key_revocation_flow() {
  STEP_MODULE="fcp-e2e::connector_suite"
  STEP_TEST="${ISSUER_FLOW_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-e2e" \
    --arg test_name "${ISSUER_FLOW_TEST}" \
    --arg log_path "${ISSUER_FLOW_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      target: "lib",
      assertions: [
        "issue -> use -> revoke issuer -> denial succeeds deterministically",
        "denied invoke reports stable reason code FCP-2202",
        "audit linkage records issuer_key as the revoked target type"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_lib_test "fcp-e2e" "${ISSUER_FLOW_TEST}" "${ISSUER_FLOW_LOG}"
}

step_verify_capability_revocation_propagation() {
  STEP_MODULE="fcp-conformance::integration_scenarios"
  STEP_TEST="${CAPABILITY_PROPAGATION_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-conformance" \
    --arg integration_test "integration_scenarios" \
    --arg test_name "${CAPABILITY_PROPAGATION_TEST}" \
    --arg log_path "${CAPABILITY_PROPAGATION_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      integration_test: $integration_test,
      assertions: [
        "mesh admission rejects a previously-authenticated peer after revocation",
        "revocation enforcement is reflected in structured scenario logs"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_integration_test "fcp-conformance" "integration_scenarios" "${CAPABILITY_PROPAGATION_TEST}" "${CAPABILITY_PROPAGATION_LOG}"
}

step_verify_issuer_revocation_propagation() {
  STEP_MODULE="fcp-conformance::integration_scenarios"
  STEP_TEST="${ISSUER_PROPAGATION_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-conformance" \
    --arg integration_test "integration_scenarios" \
    --arg test_name "${ISSUER_PROPAGATION_TEST}" \
    --arg log_path "${ISSUER_PROPAGATION_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      integration_test: $integration_test,
      assertions: [
        "peer registrations are removed after issuer revocation",
        "issuer revocation shows up in structured scenario logs"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_integration_test "fcp-conformance" "integration_scenarios" "${ISSUER_PROPAGATION_TEST}" "${ISSUER_PROPAGATION_LOG}"
}

step_verify_explain_revoked_receipt() {
  STEP_MODULE="fcp-cli::explain"
  STEP_TEST="${EXPLAIN_REVOKED_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-cli" \
    --arg test_name "${EXPLAIN_REVOKED_TEST}" \
    --arg log_path "${EXPLAIN_REVOKED_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      target: "bin:fcp",
      assertions: [
        "revoked decision receipts remain explainable through the CLI demo path",
        "explain output preserves a stable revoked-token reason code"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_bin_test "fcp-cli" "fcp" "${EXPLAIN_REVOKED_TEST}" "${EXPLAIN_REVOKED_LOG}"
}

step_emit_contract_summary() {
  STEP_MODULE="revocation_flow.contract"
  STEP_TEST="revocation_flow_contract_summary"

  [[ -s "${CAPABILITY_FLOW_LOG}" ]]
  [[ -s "${ISSUER_FLOW_LOG}" ]]
  [[ -s "${CAPABILITY_PROPAGATION_LOG}" ]]
  [[ -s "${ISSUER_PROPAGATION_LOG}" ]]
  [[ -s "${EXPLAIN_REVOKED_LOG}" ]]

  grep -Eq "test result: ok\\." "${CAPABILITY_FLOW_LOG}"
  grep -Eq "test result: ok\\." "${ISSUER_FLOW_LOG}"
  grep -Eq "test result: ok\\." "${CAPABILITY_PROPAGATION_LOG}"
  grep -Eq "test result: ok\\." "${ISSUER_PROPAGATION_LOG}"
  grep -Eq "test result: ok\\." "${EXPLAIN_REVOKED_LOG}"

  jq -n \
    --arg capability_flow_test "${CAPABILITY_FLOW_TEST}" \
    --arg issuer_flow_test "${ISSUER_FLOW_TEST}" \
    --arg capability_prop_test "${CAPABILITY_PROPAGATION_TEST}" \
    --arg issuer_prop_test "${ISSUER_PROPAGATION_TEST}" \
    --arg explain_revoked_test "${EXPLAIN_REVOKED_TEST}" \
    --arg capability_flow_log "${CAPABILITY_FLOW_LOG}" \
    --arg issuer_flow_log "${ISSUER_FLOW_LOG}" \
    --arg capability_prop_log "${CAPABILITY_PROPAGATION_LOG}" \
    --arg issuer_prop_log "${ISSUER_PROPAGATION_LOG}" \
    --arg explain_revoked_log "${EXPLAIN_REVOKED_LOG}" \
    '{
      contract_id: "contract.revocation_flow",
      scenario: "revocation_flow",
      verified_assertions: [
        "capability-token revocation converts a previously-successful invoke into a denied invoke with reason code FCP-2201",
        "issuer-key revocation converts a previously-successful invoke into a denied invoke with reason code FCP-2202",
        "decision receipt evidence references the revocation object and audit linkage is preserved",
        "revocation propagation is exercised in the deterministic multi-node conformance harness",
        "revoked receipts remain explainable through the CLI explain surface"
      ],
      source_tests: [
        {
          package: "fcp-e2e",
          target: "lib",
          test_name: $capability_flow_test,
          log_path: $capability_flow_log
        },
        {
          package: "fcp-e2e",
          target: "lib",
          test_name: $issuer_flow_test,
          log_path: $issuer_flow_log
        },
        {
          package: "fcp-conformance",
          target: "integration:integration_scenarios",
          test_name: $capability_prop_test,
          log_path: $capability_prop_log
        },
        {
          package: "fcp-conformance",
          target: "integration:integration_scenarios",
          test_name: $issuer_prop_test,
          log_path: $issuer_prop_log
        },
        {
          package: "fcp-cli",
          target: "bin:fcp",
          test_name: $explain_revoked_test,
          log_path: $explain_revoked_log
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

run_step "verify_capability_token_revocation_flow" 1 "[\"${CAPABILITY_FLOW_LOG}\"]" step_verify_capability_token_revocation_flow
run_step "verify_issuer_key_revocation_flow" 2 "[\"${ISSUER_FLOW_LOG}\"]" step_verify_issuer_key_revocation_flow
run_step "verify_capability_revocation_propagation" 3 "[\"${CAPABILITY_PROPAGATION_LOG}\"]" step_verify_capability_revocation_propagation
run_step "verify_issuer_revocation_propagation" 4 "[\"${ISSUER_PROPAGATION_LOG}\"]" step_verify_issuer_revocation_propagation
run_step "verify_explain_revoked_receipt" 5 "[\"${EXPLAIN_REVOKED_LOG}\"]" step_verify_explain_revoked_receipt
run_step "emit_contract_summary" 6 "[\"${VERIFICATION_SUMMARY}\"]" step_emit_contract_summary

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
