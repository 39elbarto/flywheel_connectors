#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_raptorq_adversarial_decode_stress"
SEED="0xADV3RSAR1"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
STEP_CONTEXT="null"

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
  run_cargo run -q -p fcp-e2e --bin fcp-e2e -- "$@"
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
  details="null"
  if [[ -n "${STEP_CONTEXT}" && "${STEP_CONTEXT}" != "null" && "${STEP_CONTEXT}" != "{}" ]]; then
    details="${STEP_CONTEXT}"
  fi

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","log_version":"v2","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${step}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${details}" >> "${LOG_JSONL}"
}

run_step() {
  local step="$1"
  local step_number="$2"
  local artifacts_json="$3"
  shift 3

  local start_ms end_ms duration_ms rc
  STEP_CONTEXT="null"
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

capture_json_metrics() {
  local source_log="$1"
  local metrics_jsonl="$2"
  grep -E '^\{.*\}$' "${source_log}" > "${metrics_jsonl}" || true
  if [[ ! -s "${metrics_jsonl}" ]]; then
    echo "No JSON metrics emitted by command output: ${source_log}" >&2
    exit 1
  fi
}

metric_for_test() {
  local metrics_jsonl="$1"
  local test_name="$2"
  local jq_expr="$3"
  jq -r --arg test_name "${test_name}" "select(.test_name == \$test_name) | ${jq_expr}" "${metrics_jsonl}" | head -n1
}

step_prepare_output() {
  mkdir -p "${OUT_DIR}"
  : > "${LOG_JSONL}"
}

# Step 2: Corrupted symbols must never yield false-positive reconstruction
step_adversarial_corrupted_symbols() {
  local execution_log="${OUT_DIR}/adversarial_corrupted.execution.log"
  local metrics_jsonl="${OUT_DIR}/adversarial_corrupted.metrics.jsonl"
  local decode_budget_ms

  run_cargo test -p fcp-store --test store_repair_integration adversarial_corrupted_symbols_reject_valid_reconstruction -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  decode_budget_ms="$(metric_for_test "${metrics_jsonl}" "adversarial_corrupted_symbols_reject_valid_reconstruction" '.details.decode_budget_ms // empty')"

  [[ -n "${decode_budget_ms}" ]] || {
    echo "Missing decode budget metric for corrupted symbols in ${metrics_jsonl}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"adversarial_corrupted","decode_budget_ms":%s,"outcome":"no_false_positive_reconstruction"}' \
    "${decode_budget_ms}")"
}

# Step 3: Reordered + duplicate symbols must still reconstruct correctly
step_adversarial_reordered_duplicates() {
  local execution_log="${OUT_DIR}/adversarial_reordered.execution.log"
  local metrics_jsonl="${OUT_DIR}/adversarial_reordered.metrics.jsonl"
  local decode_budget_ms received_unique

  run_cargo test -p fcp-store --test store_repair_integration adversarial_reordered_duplicate_symbols_reconstruct -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  decode_budget_ms="$(metric_for_test "${metrics_jsonl}" "adversarial_reordered_duplicate_symbols_reconstruct" '.details.decode_budget_ms // empty')"
  received_unique="$(metric_for_test "${metrics_jsonl}" "adversarial_reordered_duplicate_symbols_reconstruct" '.details.received_unique // 0')"

  [[ -n "${decode_budget_ms}" ]] || {
    echo "Missing decode budget metric for reordered symbols in ${metrics_jsonl}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"adversarial_reordered","decode_budget_ms":%s,"received_unique_symbols":%s,"outcome":"reconstruction_despite_reorder"}' \
    "${decode_budget_ms}" "${received_unique}")"
}

# Step 4: Decode admission controller enforces concurrency + resource limits
step_decode_admission_limits() {
  local execution_log="${OUT_DIR}/decode_admission.execution.log"

  run_cargo test -p fcp-raptorq admission_controller -- --nocapture > "${execution_log}" 2>&1

  local pass_count
  pass_count=$(grep -c "test .* ok" "${execution_log}" || true)

  (( pass_count >= 3 )) || {
    echo "Expected at least 3 admission controller tests to pass, got ${pass_count}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"decode_admission","tests_passed":%s,"outcome":"concurrency_limits_enforced"}' \
    "${pass_count}")"
}

# Step 5: Decode permit enforces symbol count + memory budget + timeout
step_decode_permit_bounds() {
  local execution_log="${OUT_DIR}/decode_permit_bounds.execution.log"

  run_cargo test -p fcp-raptorq permit_ -- --nocapture > "${execution_log}" 2>&1

  local pass_count
  pass_count=$(grep -c "test .* ok" "${execution_log}" || true)

  (( pass_count >= 4 )) || {
    echo "Expected at least 4 permit boundary tests to pass, got ${pass_count}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"decode_permit","tests_passed":%s,"outcome":"symbol_memory_timeout_bounds_enforced"}' \
    "${pass_count}")"
}

# Step 6: Mesh-level admission enforces byte + symbol + decode capacity budgets
step_mesh_admission_enforcement() {
  local execution_log="${OUT_DIR}/mesh_admission.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration test_rate_limiting -- --nocapture > "${execution_log}" 2>&1
  run_cargo test -p fcp-mesh --test mesh_integration test_decode_capacity_enforcement -- --nocapture >> "${execution_log}" 2>&1

  local pass_count
  pass_count=$(grep -c "test .* ok" "${execution_log}" || true)

  (( pass_count >= 2 )) || {
    echo "Expected at least 2 mesh admission tests to pass, got ${pass_count}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"mesh_admission","tests_passed":%s,"outcome":"byte_symbol_decode_budgets_enforced"}' \
    "${pass_count}")"
}

# Step 7: Context-aware decode respects cancellation and deadline pressure
step_decode_context_pressure() {
  local execution_log="${OUT_DIR}/decode_context_pressure.execution.log"

  run_cargo test -p fcp-raptorq decode_with_context -- --nocapture > "${execution_log}" 2>&1

  local pass_count
  pass_count=$(grep -c "test .* ok" "${execution_log}" || true)

  (( pass_count >= 3 )) || {
    echo "Expected at least 3 context-aware decode tests to pass, got ${pass_count}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"decode_context","tests_passed":%s,"outcome":"cancellation_deadline_admission_enforced"}' \
    "${pass_count}")"
}

require_cmd cargo
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "prepare_output" 1 "[]" step_prepare_output
run_step \
  "adversarial_corrupted_symbols" \
  2 \
  "[\"${OUT_DIR}/adversarial_corrupted.execution.log\",\"${OUT_DIR}/adversarial_corrupted.metrics.jsonl\"]" \
  step_adversarial_corrupted_symbols
run_step \
  "adversarial_reordered_duplicates" \
  3 \
  "[\"${OUT_DIR}/adversarial_reordered.execution.log\",\"${OUT_DIR}/adversarial_reordered.metrics.jsonl\"]" \
  step_adversarial_reordered_duplicates
run_step \
  "decode_admission_limits" \
  4 \
  "[\"${OUT_DIR}/decode_admission.execution.log\"]" \
  step_decode_admission_limits
run_step \
  "decode_permit_bounds" \
  5 \
  "[\"${OUT_DIR}/decode_permit_bounds.execution.log\"]" \
  step_decode_permit_bounds
run_step \
  "mesh_admission_enforcement" \
  6 \
  "[\"${OUT_DIR}/mesh_admission.execution.log\"]" \
  step_mesh_admission_enforcement
run_step \
  "decode_context_pressure" \
  7 \
  "[\"${OUT_DIR}/decode_context_pressure.execution.log\"]" \
  step_decode_context_pressure

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
