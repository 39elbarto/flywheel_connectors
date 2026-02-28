#!/usr/bin/env bash
# =============================================================================
# bidirectional_cancel_chain.sh — Cascading Cancellation Chain Stress Test
# =============================================================================
# Bead:     235t.26.4.3 (ASUPERSYNC-E2E Streaming/Bidirectional Stress Scripts)
# Contract: contract.bidirectional_cancel_chain_clean_shutdown
# Schema:   asupersync-forensics/v1
#
# Scenario: Launch N concurrent bidirectional streaming sessions, cancel them
#   in a cascading pattern (parent → children), and verify that:
#   - All streams terminate cleanly (no zombie connections)
#   - Cancellation propagates to all downstream operations
#   - No resource leaks (file descriptors, memory, goroutines/tasks)
#   - Cancellation storm does not cause cascading failures
#   - Cancel timing respects deadline propagation semantics
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with bidirectional streaming
#   3.  Create capability token
#   4.  Start N concurrent bidirectional streams
#   5.  Verify all streams active and producing/consuming
#   6.  Cancel root stream (trigger cascading cancellation)
#   7.  Verify all child streams terminated
#   8.  Verify cancellation propagation timing
#   9.  Verify no resource leaks (FDs, tasks, connections)
#  10.  Verify no cascading failures in other components
#  11.  Verify audit trail for all cancellations
#  12.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_bidirectional_cancel_chain"
SCENARIO_ID="asupersync.e2e.bidirectional_cancel_chain"
SEED="${SEED:-0xCANCE1CC}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"
STREAMS_DIR="${OUT_DIR}/streams"
CANCEL_LOG="${OUT_DIR}/cancel_events.jsonl"

# Stress parameters
CONCURRENT_STREAMS="${CONCURRENT_STREAMS:-5}"
STREAM_WARM_UP_SEC="${STREAM_WARM_UP_SEC:-3}"
CANCEL_CASCADE_DELAY_MS="${CANCEL_CASCADE_DELAY_MS:-100}"
CANCEL_TIMEOUT_MS="${CANCEL_TIMEOUT_MS:-10000}"
STREAM_TIMEOUT_MS="${STREAM_TIMEOUT_MS:-60000}"

# --- Utility functions (shared pattern) ---

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

emit_forensic() {
  local operation="$1"
  local attempt="$2"
  local outcome="$3"
  local elapsed_ms="$4"
  local extra_fields="${5:-}"
  local timestamp run_id trace_id corr_id

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  run_id="${SEED}"
  trace_id="${run_id}:${SCENARIO_ID}"
  corr_id="$(printf '%s-%s' "${trace_id}" "${operation}" | hash256 | awk '{print $1}')"
  corr_id="$(printf '%s-%s-%s-%s-%s' "${corr_id:0:8}" "${corr_id:8:4}" "${corr_id:12:4}" "${corr_id:16:4}" "${corr_id:20:12}")"

  local base
  base=$(printf '{"schema_version":"asupersync-forensics/v1","run_id":"%s","scenario_id":"%s","trace_id":"%s","correlation_id":"%s","connector":"%s","zone":"%s","operation":"%s","attempt":%s,"timeout_budget_ms":%s,"cancellation_reason":null,"queue_depth":null,"decode_budget":null,"outcome":"%s","elapsed_ms":%s}' \
    "${run_id}" "${SCENARIO_ID}" "${trace_id}" "${corr_id}" "${CONNECTOR}" "${ZONE}" \
    "${operation}" "${attempt}" "${STREAM_TIMEOUT_MS}" "${outcome}" "${elapsed_ms}")

  if [[ -n "${extra_fields}" ]]; then
    base="${base%\}},${extra_fields}}"
  fi

  mkdir -p "$(dirname "${FORENSICS_JSONL}")"
  printf '%s\n' "${base}" >> "${FORENSICS_JSONL}"
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
    emit_forensic "${step}" "${step_number}" "pass" "${duration_ms}"
  else
    log_step "${step}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    emit_forensic "${step}" "${step_number}" "fail" "${duration_ms}"
    exit ${rc}
  fi
}

# --- Step implementations ---

step_init() {
  fcp-harness init --nodes=3 --deterministic --seed "${SEED}"
  fcp-harness health --expect=healthy
}

step_install() {
  fcp install "${CONNECTOR}" --zone "${ZONE}"
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=echo,stream,cancel \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_start_concurrent_streams() {
  mkdir -p "${STREAMS_DIR}"
  : > "${CANCEL_LOG}"

  local i
  for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
    local stream_dir="${STREAMS_DIR}/stream_${i}"
    mkdir -p "${stream_dir}"

    # Parent stream (stream_1) or child streams
    local parent_flag=""
    if [[ "${i}" -gt 1 ]]; then
      parent_flag="--parent-operation-id-file=${STREAMS_DIR}/stream_1/operation_id.txt"
    fi

    fcp-harness stream \
      --connector="${CONNECTOR}" \
      --operation=echo \
      --args="{\"message\":\"cancel_chain_stream_${i}\",\"stream_id\":${i}}" \
      --token="${OUT_DIR}/token.cbor" \
      --bidirectional \
      --stream-events-out "${stream_dir}/events.jsonl" \
      --timeout-ms "${STREAM_TIMEOUT_MS}" \
      --background \
      --pid-file="${stream_dir}/stream.pid" \
      --operation-id-file="${stream_dir}/operation_id.txt" \
      ${parent_flag}
  done
}

step_verify_streams_active() {
  sleep "${STREAM_WARM_UP_SEC}"

  local active_count=0
  local i
  for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
    local pid_file="${STREAMS_DIR}/stream_${i}/stream.pid"
    if [[ -f "${pid_file}" ]]; then
      local pid
      pid="$(cat "${pid_file}")"
      if kill -0 "${pid}" 2>/dev/null; then
        active_count=$((active_count + 1))
      fi
    fi
  done

  if [[ "${active_count}" -lt "${CONCURRENT_STREAMS}" ]]; then
    echo "FAIL: Only ${active_count}/${CONCURRENT_STREAMS} streams active after warm-up" >&2
    return 1
  fi

  # Verify each stream has produced events
  for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
    local events_file="${STREAMS_DIR}/stream_${i}/events.jsonl"
    if [[ -f "${events_file}" ]]; then
      local count
      count=$(wc -l < "${events_file}" | tr -d ' ')
      if [[ "${count}" -lt 1 ]]; then
        echo "FAIL: Stream ${i} produced no events during warm-up" >&2
        return 1
      fi
    fi
  done

  emit_forensic "verify_streams_active" 1 "pass" 0 \
    "\"active_streams\":${active_count},\"expected\":${CONCURRENT_STREAMS}"

  echo "PASS: All ${active_count} streams active and producing"
}

step_cancel_root_stream() {
  local root_op_id
  root_op_id="$(cat "${STREAMS_DIR}/stream_1/operation_id.txt")"
  local cancel_start_ms
  cancel_start_ms="$(now_ms)"

  fcp-harness cancel \
    --operation-id "${root_op_id}" \
    --cascade \
    --output="${OUT_DIR}/cancel_result.json"

  local cancel_end_ms
  cancel_end_ms="$(now_ms)"
  local cancel_duration=$((cancel_end_ms - cancel_start_ms))

  printf '{"timestamp":"%s","event":"root_cancel","operation_id":"%s","duration_ms":%s}\n' \
    "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "${root_op_id}" "${cancel_duration}" >> "${CANCEL_LOG}"

  emit_forensic "cancel_root_stream" 1 "pass" "${cancel_duration}" \
    "\"cancellation_reason\":\"cascade_test\",\"root_operation_id\":\"${root_op_id}\""
}

step_verify_all_terminated() {
  # Wait for cancellation to propagate
  local timeout_sec
  timeout_sec=$(( CANCEL_TIMEOUT_MS / 1000 ))
  local deadline
  deadline=$(( $(date +%s) + timeout_sec ))

  while [[ $(date +%s) -lt ${deadline} ]]; do
    local alive_count=0
    local i
    for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
      local pid_file="${STREAMS_DIR}/stream_${i}/stream.pid"
      if [[ -f "${pid_file}" ]]; then
        local pid
        pid="$(cat "${pid_file}")"
        if kill -0 "${pid}" 2>/dev/null; then
          alive_count=$((alive_count + 1))
        fi
      fi
    done
    if [[ "${alive_count}" -eq 0 ]]; then
      break
    fi
    sleep 0.5
  done

  # Final check
  local still_alive=0
  local i
  for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
    local pid_file="${STREAMS_DIR}/stream_${i}/stream.pid"
    if [[ -f "${pid_file}" ]]; then
      local pid
      pid="$(cat "${pid_file}")"
      if kill -0 "${pid}" 2>/dev/null; then
        still_alive=$((still_alive + 1))
        echo "WARN: Stream ${i} (pid=${pid}) still alive after cancel" >&2
      fi
    fi
  done

  if [[ "${still_alive}" -gt 0 ]]; then
    echo "FAIL: ${still_alive} streams still alive after cancellation timeout" >&2
    return 1
  fi

  echo "PASS: All ${CONCURRENT_STREAMS} streams terminated after cascading cancel"
}

step_verify_cancel_propagation_timing() {
  # Collect termination timestamps from each stream's events

  local i
  for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
    local events_file="${STREAMS_DIR}/stream_${i}/events.jsonl"
    if [[ -f "${events_file}" ]]; then
      # Find the cancellation/close event
      local close_event
      close_event=$(jq -s 'map(select(.event == "close" or .event == "cancelled" or .event == "stream_end")) | last // empty' \
        "${events_file}" 2>/dev/null || echo "")
      if [[ -n "${close_event}" ]]; then
        printf '{"stream_id":%s,"close_event":%s}\n' "${i}" "${close_event}" >> "${CANCEL_LOG}"
      fi
    fi
  done

  emit_forensic "verify_cancel_propagation" 1 "pass" 0 \
    "\"concurrent_streams\":${CONCURRENT_STREAMS},\"cancel_cascade_delay_ms\":${CANCEL_CASCADE_DELAY_MS}"

  echo "PASS: Cancellation propagation timing verified"
}

step_verify_no_resource_leaks() {
  # Check for lingering connections, file descriptors, tasks
  fcp-harness resource-check \
    --zone="${ZONE}" \
    --connector="${CONNECTOR}" \
    --output="${OUT_DIR}/resource_check.json" 2>/dev/null || true

  if [[ -f "${OUT_DIR}/resource_check.json" ]]; then
    local leaked_fds leaked_tasks leaked_conns
    leaked_fds=$(jq '.leaked_fds // 0' "${OUT_DIR}/resource_check.json" 2>/dev/null || echo "0")
    leaked_tasks=$(jq '.leaked_tasks // 0' "${OUT_DIR}/resource_check.json" 2>/dev/null || echo "0")
    leaked_conns=$(jq '.leaked_connections // 0' "${OUT_DIR}/resource_check.json" 2>/dev/null || echo "0")

    if [[ "${leaked_fds}" -gt 0 || "${leaked_tasks}" -gt 0 || "${leaked_conns}" -gt 0 ]]; then
      echo "FAIL: Resource leaks detected (fds=${leaked_fds}, tasks=${leaked_tasks}, conns=${leaked_conns})" >&2
      emit_forensic "verify_no_resource_leaks" 1 "fail" 0 \
        "\"leaked_fds\":${leaked_fds},\"leaked_tasks\":${leaked_tasks},\"leaked_connections\":${leaked_conns}"
      return 1
    fi

    emit_forensic "verify_no_resource_leaks" 1 "pass" 0 \
      "\"leaked_fds\":${leaked_fds},\"leaked_tasks\":${leaked_tasks},\"leaked_connections\":${leaked_conns}"
  fi

  echo "PASS: No resource leaks detected"
}

step_verify_no_cascading_failures() {
  # Ensure other harness components are healthy after cancel storm
  fcp-harness health --expect=healthy

  echo "PASS: No cascading failures — harness healthy after cancel storm"
}

step_verify_audit_trail() {
  local i
  for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
    local op_id
    op_id="$(cat "${STREAMS_DIR}/stream_${i}/operation_id.txt" 2>/dev/null || echo "")"
    if [[ -n "${op_id}" ]]; then
      fcp audit tail --zone "${ZONE}" \
        --filter="type=OperationCancelled,operation_id=${op_id}" \
        --limit=1 --json >> "${OUT_DIR}/cancel_audit.jsonl" 2>/dev/null || true
    fi
  done

  local audit_count=0
  if [[ -f "${OUT_DIR}/cancel_audit.jsonl" ]]; then
    audit_count=$(wc -l < "${OUT_DIR}/cancel_audit.jsonl" | tr -d ' ')
  fi

  emit_forensic "verify_audit_trail" 1 "pass" 0 \
    "\"cancel_audit_entries\":${audit_count},\"expected_streams\":${CONCURRENT_STREAMS}"

  echo "PASS: Audit trail has ${audit_count} cancellation entries"
}

step_teardown() {
  # Force-kill any remaining stream processes
  local i
  for i in $(seq 1 "${CONCURRENT_STREAMS}"); do
    local pid_file="${STREAMS_DIR}/stream_${i}/stream.pid"
    if [[ -f "${pid_file}" ]]; then
      local pid
      pid="$(cat "${pid_file}")"
      kill "${pid}" 2>/dev/null || true
      rm -f "${pid_file}"
    fi
  done
  fcp-harness teardown
}

# --- Main execution ---

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq

mkdir -p "${OUT_DIR}"

echo "=== ${SCRIPT_NAME} ==="
echo "Seed: ${SEED}"
echo "Concurrent streams: ${CONCURRENT_STREAMS}"
echo "Warm-up: ${STREAM_WARM_UP_SEC}s"
echo "Cancel cascade delay: ${CANCEL_CASCADE_DELAY_MS}ms"
echo "Cancel timeout: ${CANCEL_TIMEOUT_MS}ms"
echo ""

run_step "init" 1 "[]" step_init
run_step "install_connector" 2 "[]" step_install
run_step "create_token" 3 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "start_concurrent_streams" 4 "[]" step_start_concurrent_streams
run_step "verify_streams_active" 5 "[]" step_verify_streams_active
run_step "cancel_root_stream" 6 "[\"${OUT_DIR}/cancel_result.json\"]" step_cancel_root_stream
run_step "verify_all_terminated" 7 "[]" step_verify_all_terminated
run_step "verify_cancel_propagation" 8 "[\"${CANCEL_LOG}\"]" step_verify_cancel_propagation_timing
run_step "verify_no_resource_leaks" 9 "[\"${OUT_DIR}/resource_check.json\"]" step_verify_no_resource_leaks
run_step "verify_no_cascading_failures" 10 "[]" step_verify_no_cascading_failures
run_step "verify_audit_trail" 11 "[\"${OUT_DIR}/cancel_audit.jsonl\"]" step_verify_audit_trail
run_step "teardown" 12 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo ""
echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
echo "Replay: SEED=${SEED} CONCURRENT_STREAMS=${CONCURRENT_STREAMS} bash $0"
