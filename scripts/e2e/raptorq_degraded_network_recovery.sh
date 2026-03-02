#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_raptorq_degraded_network_recovery"
SEED="0xD3GRAD3D"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"

EXPECTED_FAILURE=""
ACTUAL_FAILURE=""
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

json_or_null() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    printf 'null'
  else
    printf '"%s"' "${value}"
  fi
}

details_json() {
  local has_failure=0
  local has_context=0

  if [[ -n "${EXPECTED_FAILURE}" || -n "${ACTUAL_FAILURE}" ]]; then
    has_failure=1
  fi
  if [[ -n "${STEP_CONTEXT}" && "${STEP_CONTEXT}" != "null" && "${STEP_CONTEXT}" != "{}" ]]; then
    has_context=1
  fi

  if [[ ${has_failure} -eq 0 && ${has_context} -eq 0 ]]; then
    printf 'null'
    return 0
  fi

  if [[ ${has_failure} -eq 1 && ${has_context} -eq 1 ]]; then
    printf '{"expected_failure":%s,"actual_failure":%s,"context":%s}' \
      "$(json_or_null "${EXPECTED_FAILURE}")" \
      "$(json_or_null "${ACTUAL_FAILURE}")" \
      "${STEP_CONTEXT}"
    return 0
  fi

  if [[ ${has_failure} -eq 1 ]]; then
    printf '{"expected_failure":%s,"actual_failure":%s}' \
      "$(json_or_null "${EXPECTED_FAILURE}")" \
      "$(json_or_null "${ACTUAL_FAILURE}")"
    return 0
  fi

  printf '{"context":%s}' "${STEP_CONTEXT}"
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

step_prepare() {
  mkdir -p "${OUT_DIR}"
  : > "${LOG_JSONL}"
}

# Step 2: Degraded control plane roundtrip (FCPS fallback)
step_degraded_control_plane() {
  local execution_log="${OUT_DIR}/degraded_control_plane.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_degraded_control_plane_roundtrip -- --nocapture > "${execution_log}" 2>&1
  grep -q "meshnode_degraded_control_plane_roundtrip ... ok" "${execution_log}" || {
    echo "Degraded control plane roundtrip did not pass in ${execution_log}" >&2
    exit 1
  }
  STEP_CONTEXT='{"category":"degraded_control_plane","transport":"CONTROL_PLANE_fallback"}'
}

# Step 3: Decode status feedback stops unnecessary transfer
step_decode_status_stops_transfer() {
  local execution_log="${OUT_DIR}/decode_status_feedback.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_decode_status_stops_transfer -- --nocapture > "${execution_log}" 2>&1
  grep -q "meshnode_decode_status_stops_transfer ... ok" "${execution_log}" || {
    echo "Decode status feedback did not pass in ${execution_log}" >&2
    exit 1
  }
  STEP_CONTEXT='{"category":"decode_status_feedback","outcome":"transfer_stopped_on_complete"}'
}

# Step 4: Symbol acknowledgment terminates transfer early
step_symbol_ack_stops_transfer() {
  local execution_log="${OUT_DIR}/symbol_ack_stops.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_symbol_ack_stops_transfer -- --nocapture > "${execution_log}" 2>&1
  grep -q "meshnode_symbol_ack_stops_transfer ... ok" "${execution_log}" || {
    echo "Symbol ack stops transfer did not pass in ${execution_log}" >&2
    exit 1
  }
  STEP_CONTEXT='{"category":"symbol_ack","outcome":"early_termination_on_ack"}'
}

# Step 5: Quarantined objects are not gossiped or served
step_quarantine_enforcement() {
  local execution_log="${OUT_DIR}/quarantine_enforcement.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_quarantined -- --nocapture > "${execution_log}" 2>&1

  local pass_count
  pass_count=$(grep -c "test .* ok" "${execution_log}" || true)

  (( pass_count >= 2 )) || {
    echo "Expected at least 2 quarantine tests to pass, got ${pass_count}" >&2
    exit 1
  }
  STEP_CONTEXT="$(printf '{"category":"quarantine","tests_passed":%s,"outcome":"quarantined_objects_isolated"}' \
    "${pass_count}")"
}

# Step 6: Symbol request with missing hints (degraded availability)
step_symbol_request_degraded() {
  local execution_log="${OUT_DIR}/symbol_request_degraded.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_symbol_request_missing_object -- --nocapture > "${execution_log}" 2>&1
  run_cargo test -p fcp-mesh --test mesh_integration meshnode_symbol_request_no_symbols -- --nocapture >> "${execution_log}" 2>&1
  run_cargo test -p fcp-mesh --test mesh_integration meshnode_symbol_request_ignores_unavailable_hints -- --nocapture >> "${execution_log}" 2>&1

  local pass_count
  pass_count=$(grep -c "test .* ok" "${execution_log}" || true)

  (( pass_count >= 3 )) || {
    echo "Expected at least 3 degraded symbol request tests to pass, got ${pass_count}" >&2
    exit 1
  }
  STEP_CONTEXT="$(printf '{"category":"symbol_request_degraded","tests_passed":%s,"outcome":"graceful_degradation_validated"}' \
    "${pass_count}")"
}

# Step 7: Gossip partition prune and rejoin
step_gossip_partition_recovery() {
  local execution_log="${OUT_DIR}/gossip_partition.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration test_gossip_partition_prune_and_rejoin -- --nocapture > "${execution_log}" 2>&1
  grep -q "test_gossip_partition_prune_and_rejoin ... ok" "${execution_log}" || {
    echo "Gossip partition recovery did not pass in ${execution_log}" >&2
    exit 1
  }
  STEP_CONTEXT='{"category":"gossip_partition","outcome":"partition_prune_rejoin_validated"}'
}

# Step 8: Unauthenticated bounds enforcement under degradation
step_unauthenticated_bounds() {
  local execution_log="${OUT_DIR}/unauthenticated_bounds.execution.log"

  run_cargo test -p fcp-mesh --test mesh_integration meshnode_unauthenticated_bounds_enforced -- --nocapture > "${execution_log}" 2>&1
  grep -q "meshnode_unauthenticated_bounds_enforced ... ok" "${execution_log}" || {
    echo "Unauthenticated bounds test did not pass in ${execution_log}" >&2
    exit 1
  }
  STEP_CONTEXT='{"category":"unauthenticated_bounds","outcome":"degraded_access_limits_enforced"}'
}

require_cmd cargo

run_step "prepare_output" 1 "[]" "" "{}" step_prepare
run_step \
  "degraded_control_plane" \
  2 \
  "[\"${OUT_DIR}/degraded_control_plane.execution.log\"]" \
  "" \
  '{"purpose":"fcps_fallback_validation"}' \
  step_degraded_control_plane
run_step \
  "decode_status_stops_transfer" \
  3 \
  "[\"${OUT_DIR}/decode_status_feedback.execution.log\"]" \
  "" \
  '{"purpose":"bandwidth_conservation"}' \
  step_decode_status_stops_transfer
run_step \
  "symbol_ack_stops_transfer" \
  4 \
  "[\"${OUT_DIR}/symbol_ack_stops.execution.log\"]" \
  "" \
  '{"purpose":"early_termination_on_completion"}' \
  step_symbol_ack_stops_transfer
run_step \
  "quarantine_enforcement" \
  5 \
  "[\"${OUT_DIR}/quarantine_enforcement.execution.log\"]" \
  "" \
  '{"purpose":"compromised_object_isolation"}' \
  step_quarantine_enforcement
run_step \
  "symbol_request_degraded" \
  6 \
  "[\"${OUT_DIR}/symbol_request_degraded.execution.log\"]" \
  "" \
  '{"purpose":"graceful_degradation_under_missing_data"}' \
  step_symbol_request_degraded
run_step \
  "gossip_partition_recovery" \
  7 \
  "[\"${OUT_DIR}/gossip_partition.execution.log\"]" \
  "" \
  '{"purpose":"network_partition_recovery"}' \
  step_gossip_partition_recovery
run_step \
  "unauthenticated_bounds" \
  8 \
  "[\"${OUT_DIR}/unauthenticated_bounds.execution.log\"]" \
  "" \
  '{"purpose":"degraded_access_budget_enforcement"}' \
  step_unauthenticated_bounds

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
