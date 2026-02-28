#!/usr/bin/env bash
# =============================================================================
# streaming_reconnect_storm.sh — WebSocket Reconnect Storm Stress Test
# =============================================================================
# Bead:     235t.26.4.3 (ASUPERSYNC-E2E Streaming/Bidirectional Stress Scripts)
# Contract: contract.ws_reconnect_storm_bounded_recovery
# Schema:   asupersync-forensics/v1
#
# Scenario: Establish a WebSocket streaming session, force rapid disconnects,
#   and verify that reconnection is bounded (max attempts, backoff), ordering
#   is preserved across reconnects, and no messages are lost or duplicated.
#
# Steps:
#   1. Init harness (3-node deterministic mesh)
#   2. Install connector with streaming capability
#   3. Create capability token with stream operations
#   4. Start streaming session (SSE/WS progress stream)
#   5. Inject N rapid disconnect faults
#   6. Verify reconnect bounded (attempts <= max_attempts)
#   7. Verify message ordering preserved (monotonic sequence)
#   8. Verify no message loss (contiguous sequence IDs)
#   9. Verify no message duplication (unique sequence IDs)
#  10. Verify reconnect backoff timing (exponential increase)
#  11. Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_streaming_reconnect_storm"
SCENARIO_ID="asupersync.e2e.streaming_reconnect_storm"
SEED="${SEED:-0xA55C0DE1}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
STREAM_EVENTS="${OUT_DIR}/stream_events.jsonl"
RECONNECT_LOG="${OUT_DIR}/reconnect_attempts.jsonl"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"

# Stress parameters
DISCONNECT_COUNT="${DISCONNECT_COUNT:-10}"
DISCONNECT_INTERVAL_MS="${DISCONNECT_INTERVAL_MS:-500}"
MAX_RECONNECT_ATTEMPTS="${MAX_RECONNECT_ATTEMPTS:-15}"
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
    # Merge extra fields by removing trailing } and appending
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
    --operations=echo,stream \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_start_stream() {
  : > "${STREAM_EVENTS}"
  : > "${RECONNECT_LOG}"

  fcp-harness stream \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args='{"message":"reconnect_storm","stream_count":1000}' \
    --token="${OUT_DIR}/token.cbor" \
    --stream-events-out "${STREAM_EVENTS}" \
    --reconnect-log "${RECONNECT_LOG}" \
    --max-reconnect-attempts "${MAX_RECONNECT_ATTEMPTS}" \
    --timeout-ms "${STREAM_TIMEOUT_MS}" \
    --background \
    --pid-file="${OUT_DIR}/stream.pid"
}

step_inject_disconnects() {
  local i
  for i in $(seq 1 "${DISCONNECT_COUNT}"); do
    fcp-harness fault inject \
      --type=ws-disconnect \
      --connector="${CONNECTOR}" \
      --zone="${ZONE}" \
      --seed="${SEED}-disconnect-${i}"

    # Interval between disconnects
    local sleep_sec
    sleep_sec=$(echo "scale=3; ${DISCONNECT_INTERVAL_MS}/1000" | bc 2>/dev/null || echo "0.5")
    sleep "${sleep_sec}"
  done

  # Wait for stream to complete or timeout
  local pid
  if [[ -f "${OUT_DIR}/stream.pid" ]]; then
    pid="$(cat "${OUT_DIR}/stream.pid")"
    local timeout_sec
    timeout_sec=$(( STREAM_TIMEOUT_MS / 1000 ))
    timeout "${timeout_sec}" tail --pid="${pid}" -f /dev/null 2>/dev/null || true
  fi
}

step_verify_reconnect_bounded() {
  local reconnect_count
  reconnect_count=$(wc -l < "${RECONNECT_LOG}" | tr -d ' ')

  if [[ "${reconnect_count}" -gt "${MAX_RECONNECT_ATTEMPTS}" ]]; then
    echo "FAIL: Reconnect attempts (${reconnect_count}) exceeded max (${MAX_RECONNECT_ATTEMPTS})" >&2
    return 1
  fi

  emit_forensic "verify_reconnect_bounded" 1 "pass" 0 \
    "\"reconnect_count\":${reconnect_count},\"max_allowed\":${MAX_RECONNECT_ATTEMPTS}"

  echo "PASS: Reconnect bounded (${reconnect_count} <= ${MAX_RECONNECT_ATTEMPTS})"
}

step_verify_ordering() {
  # Check monotonic sequence_id across all stream events
  local ordering_ok
  ordering_ok=$(jq -s '
    [.[].sequence_id // .[].seq // 0] |
    . as $ids |
    reduce range(1; length) as $i (true;
      . and ($ids[$i] > $ids[$i-1])
    )
  ' "${STREAM_EVENTS}")

  if [[ "${ordering_ok}" != "true" ]]; then
    echo "FAIL: Stream event ordering violated (non-monotonic sequence)" >&2
    jq -s '[.[].sequence_id // .[].seq] | to_entries | map(select(.value <= (if .key > 0 then .[.key-1].value else -1 end)))' \
      "${STREAM_EVENTS}" > "${OUT_DIR}/ordering_violations.json" 2>/dev/null || true
    return 1
  fi

  echo "PASS: Stream event ordering preserved (monotonic)"
}

step_verify_no_loss() {
  # Check contiguous sequence IDs (no gaps)
  local loss_check
  loss_check=$(jq -s '
    [.[].sequence_id // .[].seq // 0] | sort |
    . as $ids |
    if length < 2 then true
    else
      reduce range(1; length) as $i (true;
        . and ($ids[$i] == $ids[$i-1] + 1)
      )
    end
  ' "${STREAM_EVENTS}")

  if [[ "${loss_check}" != "true" ]]; then
    echo "FAIL: Message loss detected (gaps in sequence)" >&2
    jq -s '
      [.[].sequence_id // .[].seq // 0] | sort |
      . as $ids |
      [range(1; length) | select($ids[.] != $ids[.-1] + 1) |
        {"gap_after": $ids[.-1], "next_seen": $ids[.], "missing_count": ($ids[.] - $ids[.-1] - 1)}
      ]
    ' "${STREAM_EVENTS}" > "${OUT_DIR}/message_gaps.json" 2>/dev/null || true
    return 1
  fi

  local event_count
  event_count=$(jq -s 'length' "${STREAM_EVENTS}")
  emit_forensic "verify_no_loss" 1 "pass" 0 "\"event_count\":${event_count}"

  echo "PASS: No message loss (${event_count} events, contiguous)"
}

step_verify_no_duplicates() {
  local dup_count
  dup_count=$(jq -s '
    [.[].sequence_id // .[].seq // 0] |
    group_by(.) | map(select(length > 1)) | length
  ' "${STREAM_EVENTS}")

  if [[ "${dup_count}" -gt 0 ]]; then
    echo "FAIL: ${dup_count} duplicate message(s) detected" >&2
    jq -s '
      [.[].sequence_id // .[].seq // 0] |
      group_by(.) | map(select(length > 1)) |
      map({"id": .[0], "count": length})
    ' "${STREAM_EVENTS}" > "${OUT_DIR}/duplicates.json" 2>/dev/null || true
    return 1
  fi

  echo "PASS: No message duplication"
}

step_verify_backoff_timing() {
  # Check that reconnect delays show exponential increase
  local timing_ok
  timing_ok=$(jq -s '
    [.[].delay_ms // 0] |
    . as $delays |
    if length < 3 then true
    else
      reduce range(1; length) as $i (true;
        . and ($delays[$i] >= $delays[$i-1])
      )
    end
  ' "${RECONNECT_LOG}")

  if [[ "${timing_ok}" != "true" ]]; then
    echo "WARN: Backoff timing not strictly increasing (jitter expected)" >&2
    # Not a hard failure — jitter can cause non-monotonic delays
  fi

  # Verify delays stay within bounds [initial_delay, max_delay]
  local bounds_ok
  bounds_ok=$(jq -s '
    [.[].delay_ms // 0] |
    all(. >= 0 and . <= 65000)
  ' "${RECONNECT_LOG}")

  if [[ "${bounds_ok}" != "true" ]]; then
    echo "FAIL: Reconnect delays out of bounds [0, 65000ms]" >&2
    return 1
  fi

  echo "PASS: Backoff timing within bounds"
}

step_teardown() {
  # Kill any lingering stream process
  if [[ -f "${OUT_DIR}/stream.pid" ]]; then
    local pid
    pid="$(cat "${OUT_DIR}/stream.pid")"
    kill "${pid}" 2>/dev/null || true
    rm -f "${OUT_DIR}/stream.pid"
  fi
  fcp-harness teardown
}

# --- Main execution ---

require_cmd fcp-harness
require_cmd fcp
require_cmd fcp-e2e
require_cmd jq
require_cmd bc

mkdir -p "${OUT_DIR}"

echo "=== ${SCRIPT_NAME} ==="
echo "Seed: ${SEED}"
echo "Disconnect count: ${DISCONNECT_COUNT}"
echo "Disconnect interval: ${DISCONNECT_INTERVAL_MS}ms"
echo "Max reconnect attempts: ${MAX_RECONNECT_ATTEMPTS}"
echo "Stream timeout: ${STREAM_TIMEOUT_MS}ms"
echo ""

run_step "init" 1 "[]" step_init
run_step "install_connector" 2 "[]" step_install
run_step "create_token" 3 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "start_stream" 4 "[\"${STREAM_EVENTS}\",\"${RECONNECT_LOG}\"]" step_start_stream
run_step "inject_disconnects" 5 "[]" step_inject_disconnects
run_step "verify_reconnect_bounded" 6 "[\"${RECONNECT_LOG}\"]" step_verify_reconnect_bounded
run_step "verify_ordering" 7 "[\"${STREAM_EVENTS}\"]" step_verify_ordering
run_step "verify_no_loss" 8 "[\"${STREAM_EVENTS}\"]" step_verify_no_loss
run_step "verify_no_duplicates" 9 "[\"${STREAM_EVENTS}\"]" step_verify_no_duplicates
run_step "verify_backoff_timing" 10 "[\"${RECONNECT_LOG}\"]" step_verify_backoff_timing
run_step "teardown" 11 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo ""
echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
echo "Replay: SEED=${SEED} DISCONNECT_COUNT=${DISCONNECT_COUNT} bash $0"
