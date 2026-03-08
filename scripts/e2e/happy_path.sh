#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="happy_path"
SEED="0xDEADBEEF"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
TARGET_DIR="${HAPPY_PATH_TARGET_DIR:-/tmp/fcp-happy-path-flow}"

SUPPLY_CHAIN_TEST="verify_happy_path_produces_allow_with_evidence"
DISCOVERY_TEST="fcp_host_binary_exposes_discovery_routes"
ENDPOINT_LOG_TEST="fcp_host_binary_emits_structured_endpoint_logs"
AUDIT_TEST="e2e_full_audit_workflow"

SUPPLY_CHAIN_LOG="${OUT_DIR}/${SUPPLY_CHAIN_TEST}.log"
DISCOVERY_LOG="${OUT_DIR}/${DISCOVERY_TEST}.log"
ENDPOINT_LOG="${OUT_DIR}/${ENDPOINT_LOG_TEST}.log"
AUDIT_LOG="${OUT_DIR}/${AUDIT_TEST}.log"
VERIFICATION_SUMMARY="${OUT_DIR}/happy_path_contract_summary.json"

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

run_exact_test() {
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

step_verify_install_and_supply_chain() {
  STEP_MODULE="fcp-host::supply_chain_integration"
  STEP_TEST="${SUPPLY_CHAIN_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-host" \
    --arg integration_test "supply_chain_integration" \
    --arg test_name "${SUPPLY_CHAIN_TEST}" \
    --arg log_path "${SUPPLY_CHAIN_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      integration_test: $integration_test,
      assertions: [
        "verification gate allows a valid connector artifact",
        "evidence bundle is populated and deterministic",
        "audit event contains a blake3 evidence digest"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_test "fcp-host" "supply_chain_integration" "${SUPPLY_CHAIN_TEST}" "${SUPPLY_CHAIN_LOG}"
}

step_verify_discovery_preflight_invoke_receipt() {
  STEP_MODULE="fcp-host::host_connector_integration"
  STEP_TEST="${DISCOVERY_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-host" \
    --arg integration_test "host_connector_integration" \
    --arg test_name "${DISCOVERY_TEST}" \
    --arg log_path "${DISCOVERY_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      integration_test: $integration_test,
      assertions: [
        "live host discovery and introspection routes return healthy connector metadata",
        "preflight allows the request for the expected operation",
        "invoke returns Ok with a receipt_id and the echoed hello payload"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_test "fcp-host" "host_connector_integration" "${DISCOVERY_TEST}" "${DISCOVERY_LOG}"
}

step_verify_structured_endpoint_logs() {
  STEP_MODULE="fcp-host::host_connector_integration"
  STEP_TEST="${ENDPOINT_LOG_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-host" \
    --arg integration_test "host_connector_integration" \
    --arg test_name "${ENDPOINT_LOG_TEST}" \
    --arg log_path "${ENDPOINT_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      integration_test: $integration_test,
      assertions: [
        "structured endpoint logs include discover/introspect/preflight/invoke events",
        "invoke_response log records a successful status for the happy-path connector",
        "doctor and health responses are emitted for the same live host session"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_test "fcp-host" "host_connector_integration" "${ENDPOINT_LOG_TEST}" "${ENDPOINT_LOG}"
}

step_verify_audit_workflow() {
  STEP_MODULE="fcp-cli::audit_e2e_test"
  STEP_TEST="${AUDIT_TEST}"
  STEP_CONTEXT="$(jq -cn \
    --arg package "fcp-cli" \
    --arg integration_test "audit_e2e_test" \
    --arg test_name "${AUDIT_TEST}" \
    --arg log_path "${AUDIT_LOG}" \
    '{
      mode: "cargo_test",
      package: $package,
      integration_test: $integration_test,
      assertions: [
        "audit chain verify returns ok for a realistic chain",
        "timeline rendering succeeds after verification",
        "full audit workflow remains machine-parseable"
      ],
      log_path: $log_path,
      test_name: $test_name
    }')"
  run_exact_test "fcp-cli" "audit_e2e_test" "${AUDIT_TEST}" "${AUDIT_LOG}"
}

step_emit_contract_summary() {
  STEP_MODULE="happy_path.contract"
  STEP_TEST="happy_path_contract_summary"

  [[ -s "${SUPPLY_CHAIN_LOG}" ]]
  [[ -s "${DISCOVERY_LOG}" ]]
  [[ -s "${ENDPOINT_LOG}" ]]
  [[ -s "${AUDIT_LOG}" ]]

  grep -Eq "test result: ok\\." "${SUPPLY_CHAIN_LOG}"
  grep -Eq "test result: ok\\." "${DISCOVERY_LOG}"
  grep -Eq "test result: ok\\." "${ENDPOINT_LOG}"
  grep -Eq "test result: ok\\." "${AUDIT_LOG}"

  jq -n \
    --arg supply_chain_test "${SUPPLY_CHAIN_TEST}" \
    --arg discovery_test "${DISCOVERY_TEST}" \
    --arg endpoint_log_test "${ENDPOINT_LOG_TEST}" \
    --arg audit_test "${AUDIT_TEST}" \
    --arg supply_chain_log "${SUPPLY_CHAIN_LOG}" \
    --arg discovery_log "${DISCOVERY_LOG}" \
    --arg endpoint_log "${ENDPOINT_LOG}" \
    --arg audit_log "${AUDIT_LOG}" \
    '{
      contract_id: "contract.install_invoke_receipt_audit",
      scenario: "happy_path",
      verified_assertions: [
        "install verification accepts a valid connector artifact and emits evidence",
        "live host routes perform discovery, preflight, invoke, and receipt emission on the happy path",
        "structured endpoint logs capture discover/introspect/preflight/invoke success events",
        "audit verification and timeline rendering succeed for a realistic audit chain"
      ],
      source_tests: [
        {
          package: "fcp-host",
          integration_test: "supply_chain_integration",
          test_name: $supply_chain_test,
          log_path: $supply_chain_log
        },
        {
          package: "fcp-host",
          integration_test: "host_connector_integration",
          test_name: $discovery_test,
          log_path: $discovery_log
        },
        {
          package: "fcp-host",
          integration_test: "host_connector_integration",
          test_name: $endpoint_log_test,
          log_path: $endpoint_log
        },
        {
          package: "fcp-cli",
          integration_test: "audit_e2e_test",
          test_name: $audit_test,
          log_path: $audit_log
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

run_step "verify_install_and_supply_chain" 1 "[\"${SUPPLY_CHAIN_LOG}\"]" step_verify_install_and_supply_chain
run_step "verify_discovery_preflight_invoke_receipt" 2 "[\"${DISCOVERY_LOG}\"]" step_verify_discovery_preflight_invoke_receipt
run_step "verify_structured_endpoint_logs" 3 "[\"${ENDPOINT_LOG}\"]" step_verify_structured_endpoint_logs
run_step "verify_audit_workflow" 4 "[\"${AUDIT_LOG}\"]" step_verify_audit_workflow
run_step "emit_contract_summary" 5 "[\"${VERIFICATION_SUMMARY}\"]" step_emit_contract_summary

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
