#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_raptorq_partial_symbol_recovery"
SEED="0xF0UNTAIN"
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

# Step 2: Validate partial symbol loss correctly degrades coverage
step_partial_loss_degrades_coverage() {
  local execution_log="${OUT_DIR}/partial_loss_degrades_coverage.execution.log"
  local metrics_jsonl="${OUT_DIR}/partial_loss_degrades_coverage.metrics.jsonl"
  local coverage_before_bps coverage_after_bps symbol_count

  run_cargo test -p fcp-store --test store_repair_integration partial_loss_degrades_coverage -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  coverage_before_bps="$(metric_for_test "${metrics_jsonl}" "partial_loss_degrades_coverage" '.details.coverage_before_bps // empty')"
  coverage_after_bps="$(metric_for_test "${metrics_jsonl}" "partial_loss_degrades_coverage" '.details.coverage_after_bps // empty')"
  symbol_count="$(metric_for_test "${metrics_jsonl}" "partial_loss_degrades_coverage" '.symbol_count // 0')"

  [[ -n "${coverage_before_bps}" && -n "${coverage_after_bps}" ]] || {
    echo "Missing coverage metrics in ${metrics_jsonl}" >&2
    exit 1
  }
  (( coverage_after_bps < coverage_before_bps )) || {
    echo "Expected degraded coverage, got before=${coverage_before_bps} after=${coverage_after_bps}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"partial_loss","coverage_before_bps":%s,"coverage_after_bps":%s,"symbol_count":%s}' \
    "${coverage_before_bps}" "${coverage_after_bps}" "${symbol_count}")"
}

# Step 3: Validate partial loss + repair achieves full reconstruction
step_partial_loss_repair_reconstruct() {
  local execution_log="${OUT_DIR}/partial_loss_repair_reconstruct.execution.log"
  local metrics_jsonl="${OUT_DIR}/partial_loss_repair_reconstruct.metrics.jsonl"

  run_cargo test -p fcp-store --test store_repair_integration partial_loss_repair_reconstruct -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  # Verify test passed (grep for ok marker)
  grep -q "partial_loss_repair_reconstruct ... ok" "${execution_log}" || {
    echo "partial_loss_repair_reconstruct did not pass in ${execution_log}" >&2
    exit 1
  }

  STEP_CONTEXT='{"category":"partial_loss_repair","outcome":"reconstruction_succeeded"}'
}

# Step 4: Validate fountain code property — repair symbols alone can reconstruct
step_reconstruct_from_repair_only() {
  local execution_log="${OUT_DIR}/reconstruct_from_repair_symbols_only.execution.log"
  local metrics_jsonl="${OUT_DIR}/reconstruct_from_repair_symbols_only.metrics.jsonl"

  run_cargo test -p fcp-store --test store_repair_integration reconstruct_from_repair_symbols_only -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  grep -q "reconstruct_from_repair_symbols_only ... ok" "${execution_log}" || {
    echo "Fountain code property test did not pass in ${execution_log}" >&2
    exit 1
  }

  STEP_CONTEXT='{"category":"fountain_code_property","outcome":"repair_only_reconstruction_succeeded"}'
}

# Step 5: Validate repair controller drives convergence from degraded state
step_repair_convergence() {
  local execution_log="${OUT_DIR}/repair_convergence.execution.log"
  local metrics_jsonl="${OUT_DIR}/repair_convergence.metrics.jsonl"
  local coverage_bps repairs_succeeded initial_queue_depth final_queue_depth

  run_cargo test -p fcp-store --test store_repair_integration repair_controller_drives_convergence -- --nocapture > "${execution_log}" 2>&1
  capture_json_metrics "${execution_log}" "${metrics_jsonl}"

  coverage_bps="$(metric_for_test "${metrics_jsonl}" "repair_controller_drives_convergence" '.coverage_bps // empty')"
  repairs_succeeded="$(metric_for_test "${metrics_jsonl}" "repair_controller_drives_convergence" '.details.repairs_succeeded // 0')"
  initial_queue_depth="$(metric_for_test "${metrics_jsonl}" "repair_controller_drives_convergence" '.details.initial_queue_depth // 0')"
  final_queue_depth="$(metric_for_test "${metrics_jsonl}" "repair_controller_drives_convergence" '.details.final_queue_depth // 0')"

  [[ -n "${coverage_bps}" ]] || {
    echo "Missing convergence coverage metrics in ${metrics_jsonl}" >&2
    exit 1
  }
  (( coverage_bps >= 10000 )) || {
    echo "Expected restored coverage >= 10000bps, got ${coverage_bps}" >&2
    exit 1
  }
  (( repairs_succeeded >= 1 )) || {
    echo "Expected at least one successful repair, got ${repairs_succeeded}" >&2
    exit 1
  }

  STEP_CONTEXT="$(printf '{"category":"repair_convergence","coverage_restored_bps":%s,"repairs_succeeded":%s,"initial_queue_depth":%s,"final_queue_depth":%s}' \
    "${coverage_bps}" "${repairs_succeeded}" "${initial_queue_depth}" "${final_queue_depth}")"
}

# Step 6: Validate encode/decode full roundtrip in fcp-raptorq crate
step_encode_decode_roundtrip() {
  local execution_log="${OUT_DIR}/encode_decode_roundtrip.execution.log"

  run_cargo test -p fcp-raptorq encode_decode_roundtrip -- --nocapture > "${execution_log}" 2>&1
  grep -q "encode_decode_roundtrip ... ok" "${execution_log}" || {
    echo "Encode/decode roundtrip did not pass in ${execution_log}" >&2
    exit 1
  }

  STEP_CONTEXT='{"category":"roundtrip","outcome":"encode_decode_verified"}'
}

require_cmd cargo
require_cmd jq

mkdir -p "${OUT_DIR}"

run_step "prepare_output" 1 "[]" step_prepare_output
run_step \
  "partial_loss_degrades_coverage" \
  2 \
  "[\"${OUT_DIR}/partial_loss_degrades_coverage.execution.log\",\"${OUT_DIR}/partial_loss_degrades_coverage.metrics.jsonl\"]" \
  step_partial_loss_degrades_coverage
run_step \
  "partial_loss_repair_reconstruct" \
  3 \
  "[\"${OUT_DIR}/partial_loss_repair_reconstruct.execution.log\",\"${OUT_DIR}/partial_loss_repair_reconstruct.metrics.jsonl\"]" \
  step_partial_loss_repair_reconstruct
run_step \
  "reconstruct_from_repair_only" \
  4 \
  "[\"${OUT_DIR}/reconstruct_from_repair_symbols_only.execution.log\",\"${OUT_DIR}/reconstruct_from_repair_symbols_only.metrics.jsonl\"]" \
  step_reconstruct_from_repair_only
run_step \
  "repair_convergence" \
  5 \
  "[\"${OUT_DIR}/repair_convergence.execution.log\",\"${OUT_DIR}/repair_convergence.metrics.jsonl\"]" \
  step_repair_convergence
run_step \
  "encode_decode_roundtrip" \
  6 \
  "[\"${OUT_DIR}/encode_decode_roundtrip.execution.log\"]" \
  step_encode_decode_roundtrip

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
