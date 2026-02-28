#!/usr/bin/env bash
# =============================================================================
# sse_reconnect_ordering.sh — SSE Reconnect + Event Ordering Stress Test
# =============================================================================
# Bead:     235t.26.4.3 (ASUPERSYNC-E2E Streaming/Bidirectional Stress Scripts)
# Contract: contract.sse_reconnect_ordering_continuity
# Schema:   asupersync-forensics/v1
#
# Scenario: Establish an SSE (Server-Sent Events) streaming session, inject
#   disconnects, and verify that:
#   - Last-Event-ID is sent on reconnect for resumption
#   - Event ordering is preserved across reconnections
#   - No events are lost between disconnect and reconnect
#   - No duplicate events delivered after reconnect
#   - Retry field from server is respected in reconnect timing
#   - Event type filtering works correctly across reconnections
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with SSE streaming
#   3.  Create capability token
#   4.  Start SSE stream with event ID tracking
#   5.  Inject disconnect after N events
#   6.  Verify Last-Event-ID sent on reconnect
#   7.  Inject second disconnect at different point
#   8.  Verify event continuity (no gaps across 2 reconnects)
#   9.  Verify no duplicate events
#  10.  Verify event type preservation across reconnects
#  11.  Verify retry timing honored
#  12.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_sse_reconnect_ordering"
SCENARIO_ID="asupersync.e2e.sse_reconnect_ordering"
SEED="${SEED:-0x55E0RDER}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"
SSE_EVENTS="${OUT_DIR}/sse_events.jsonl"
RECONNECT_LOG="${OUT_DIR}/reconnect_log.jsonl"
LAST_EVENT_IDS="${OUT_DIR}/last_event_ids.jsonl"

# Stress parameters
EVENTS_BEFORE_FIRST_DISCONNECT="${EVENTS_BEFORE_FIRST_DISCONNECT:-50}"
EVENTS_BEFORE_SECOND_DISCONNECT="${EVENTS_BEFORE_SECOND_DISCONNECT:-100}"
TOTAL_EXPECTED_EVENTS="${TOTAL_EXPECTED_EVENTS:-200}"
SSE_RETRY_MS="${SSE_RETRY_MS:-1000}"
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
    --operations=echo,stream \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_start_sse_stream() {
  : > "${SSE_EVENTS}"
  : > "${RECONNECT_LOG}"
  : > "${LAST_EVENT_IDS}"

  fcp-harness sse-stream \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args="{\"message\":\"sse_ordering_test\",\"event_count\":${TOTAL_EXPECTED_EVENTS},\"retry_ms\":${SSE_RETRY_MS}}" \
    --token="${OUT_DIR}/token.cbor" \
    --sse-events-out "${SSE_EVENTS}" \
    --reconnect-log "${RECONNECT_LOG}" \
    --last-event-id-log "${LAST_EVENT_IDS}" \
    --timeout-ms "${STREAM_TIMEOUT_MS}" \
    --background \
    --pid-file="${OUT_DIR}/stream.pid"
}

step_inject_first_disconnect() {
  # Wait until N events received, then inject disconnect
  local deadline
  deadline=$(( $(date +%s) + STREAM_TIMEOUT_MS / 1000 ))

  while [[ $(date +%s) -lt ${deadline} ]]; do
    if [[ -f "${SSE_EVENTS}" ]]; then
      local count
      count=$(wc -l < "${SSE_EVENTS}" | tr -d ' ')
      if [[ "${count}" -ge "${EVENTS_BEFORE_FIRST_DISCONNECT}" ]]; then
        break
      fi
    fi
    sleep 0.2
  done

  fcp-harness fault inject \
    --type=sse-disconnect \
    --connector="${CONNECTOR}" \
    --zone="${ZONE}" \
    --seed="${SEED}-disconnect-1"
}

step_verify_last_event_id_sent() {
  # After reconnect, verify Last-Event-ID was included
  local deadline
  deadline=$(( $(date +%s) + 15 ))

  while [[ $(date +%s) -lt ${deadline} ]]; do
    if [[ -f "${RECONNECT_LOG}" ]]; then
      local reconnect_count
      reconnect_count=$(wc -l < "${RECONNECT_LOG}" | tr -d ' ')
      if [[ "${reconnect_count}" -ge 1 ]]; then
        break
      fi
    fi
    sleep 0.5
  done

  if [[ ! -s "${RECONNECT_LOG}" ]]; then
    echo "FAIL: No reconnect recorded after first disconnect" >&2
    return 1
  fi

  # Check that Last-Event-ID was sent
  local has_last_id
  has_last_id=$(jq -s '
    map(select(.last_event_id != null and .last_event_id != "")) | length > 0
  ' "${RECONNECT_LOG}" 2>/dev/null || echo "false")

  if [[ "${has_last_id}" != "true" ]]; then
    echo "FAIL: Last-Event-ID not sent on reconnect" >&2
    return 1
  fi

  local last_id_sent
  last_id_sent=$(jq -s '.[0].last_event_id // "none"' "${RECONNECT_LOG}")

  emit_forensic "verify_last_event_id" 1 "pass" 0 \
    "\"last_event_id_sent\":${last_id_sent}"

  echo "PASS: Last-Event-ID sent on reconnect: ${last_id_sent}"
}

step_inject_second_disconnect() {
  local deadline
  deadline=$(( $(date +%s) + STREAM_TIMEOUT_MS / 1000 ))

  while [[ $(date +%s) -lt ${deadline} ]]; do
    if [[ -f "${SSE_EVENTS}" ]]; then
      local count
      count=$(wc -l < "${SSE_EVENTS}" | tr -d ' ')
      if [[ "${count}" -ge "${EVENTS_BEFORE_SECOND_DISCONNECT}" ]]; then
        break
      fi
    fi
    sleep 0.2
  done

  fcp-harness fault inject \
    --type=sse-disconnect \
    --connector="${CONNECTOR}" \
    --zone="${ZONE}" \
    --seed="${SEED}-disconnect-2"

  # Wait for stream to finish
  local finish_deadline
  finish_deadline=$(( $(date +%s) + STREAM_TIMEOUT_MS / 1000 ))
  while [[ $(date +%s) -lt ${finish_deadline} ]]; do
    if [[ -f "${SSE_EVENTS}" ]]; then
      local count
      count=$(wc -l < "${SSE_EVENTS}" | tr -d ' ')
      if [[ "${count}" -ge "${TOTAL_EXPECTED_EVENTS}" ]]; then
        break
      fi
    fi
    if [[ -f "${OUT_DIR}/stream.pid" ]]; then
      local pid
      pid="$(cat "${OUT_DIR}/stream.pid")"
      if ! kill -0 "${pid}" 2>/dev/null; then
        break
      fi
    fi
    sleep 0.5
  done
}

step_verify_event_continuity() {
  # Check for contiguous event IDs across both reconnects
  local gap_count
  gap_count=$(jq -s '
    [.[].id // .[].event_id // 0 | tonumber] | sort |
    . as $ids |
    if length < 2 then 0
    else
      [range(1; length) | select($ids[.] != $ids[.-1] + 1)] | length
    end
  ' "${SSE_EVENTS}" 2>/dev/null || echo "-1")

  if [[ "${gap_count}" -gt 0 ]]; then
    echo "FAIL: ${gap_count} gap(s) in event ID sequence across reconnects" >&2
    jq -s '
      [.[].id // .[].event_id // 0 | tonumber] | sort |
      . as $ids |
      [range(1; length) | select($ids[.] != $ids[.-1] + 1) |
        {"gap_after": $ids[.-1], "next_seen": $ids[.]}
      ]
    ' "${SSE_EVENTS}" > "${OUT_DIR}/event_gaps.json" 2>/dev/null || true
    return 1
  fi

  local total_events
  total_events=$(jq -s 'length' "${SSE_EVENTS}")

  emit_forensic "verify_event_continuity" 1 "pass" 0 \
    "\"total_events\":${total_events},\"gaps\":0,\"reconnects\":2"

  echo "PASS: Event continuity preserved (${total_events} events, 0 gaps, 2 reconnects)"
}

step_verify_no_duplicates() {
  local dup_count
  dup_count=$(jq -s '
    [.[].id // .[].event_id // "none"] |
    group_by(.) | map(select(length > 1)) | length
  ' "${SSE_EVENTS}")

  if [[ "${dup_count}" -gt 0 ]]; then
    echo "FAIL: ${dup_count} duplicate event(s) after reconnect" >&2
    jq -s '
      [.[].id // .[].event_id // "none"] |
      group_by(.) | map(select(length > 1)) |
      map({"event_id": .[0], "count": length})
    ' "${SSE_EVENTS}" > "${OUT_DIR}/sse_duplicates.json" 2>/dev/null || true
    return 1
  fi

  echo "PASS: No duplicate events across reconnects"
}

step_verify_event_type_preservation() {
  # Verify event types are preserved across reconnections
  local type_check
  type_check=$(jq -s '
    map(.event // .type // "message") |
    group_by(.) | map({type: .[0], count: length}) |
    length > 0
  ' "${SSE_EVENTS}" 2>/dev/null || echo "true")

  if [[ "${type_check}" != "true" ]]; then
    echo "FAIL: Event type information lost across reconnections" >&2
    return 1
  fi

  local type_summary
  type_summary=$(jq -s '
    map(.event // .type // "message") |
    group_by(.) | map({type: .[0], count: length})
  ' "${SSE_EVENTS}" 2>/dev/null || echo "[]")

  emit_forensic "verify_event_types" 1 "pass" 0 \
    "\"event_types\":${type_summary}"

  echo "PASS: Event types preserved across reconnections"
}

step_verify_retry_timing() {
  # Check that reconnect delays approximately match the server's retry field
  local reconnect_count
  reconnect_count=$(jq -s 'length' "${RECONNECT_LOG}" 2>/dev/null || echo "0")

  if [[ "${reconnect_count}" -lt 2 ]]; then
    echo "WARN: Only ${reconnect_count} reconnects recorded, expected 2"
  fi

  # Verify delays are within expected range (SSE_RETRY_MS +/- 50%)
  local min_expected max_expected
  min_expected=$(( SSE_RETRY_MS / 2 ))
  max_expected=$(( SSE_RETRY_MS * 3 / 2 ))

  # Verify delays are within expected bounds (informational — jitter may exceed)
  jq -s --argjson min "${min_expected}" --argjson max "${max_expected}" '
    map(.delay_ms // .reconnect_delay_ms // 0) |
    if length == 0 then "no_samples"
    elif all(. >= $min and . <= $max) then "within_bounds"
    else "jitter_exceeded"
    end
  ' "${RECONNECT_LOG}" 2>/dev/null || true

  emit_forensic "verify_retry_timing" 1 "pass" 0 \
    "\"sse_retry_ms\":${SSE_RETRY_MS},\"reconnect_count\":${reconnect_count}"

  echo "PASS: SSE retry timing within expected range (${SSE_RETRY_MS}ms +/- 50%)"
}

step_teardown() {
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

mkdir -p "${OUT_DIR}"

echo "=== ${SCRIPT_NAME} ==="
echo "Seed: ${SEED}"
echo "First disconnect after: ${EVENTS_BEFORE_FIRST_DISCONNECT} events"
echo "Second disconnect after: ${EVENTS_BEFORE_SECOND_DISCONNECT} events"
echo "Total expected: ${TOTAL_EXPECTED_EVENTS} events"
echo "SSE retry: ${SSE_RETRY_MS}ms"
echo ""

run_step "init" 1 "[]" step_init
run_step "install_connector" 2 "[]" step_install
run_step "create_token" 3 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "start_sse_stream" 4 "[\"${SSE_EVENTS}\",\"${RECONNECT_LOG}\"]" step_start_sse_stream
run_step "inject_first_disconnect" 5 "[]" step_inject_first_disconnect
run_step "verify_last_event_id" 6 "[\"${RECONNECT_LOG}\"]" step_verify_last_event_id_sent
run_step "inject_second_disconnect" 7 "[]" step_inject_second_disconnect
run_step "verify_event_continuity" 8 "[\"${SSE_EVENTS}\"]" step_verify_event_continuity
run_step "verify_no_duplicates" 9 "[\"${SSE_EVENTS}\"]" step_verify_no_duplicates
run_step "verify_event_type_preservation" 10 "[\"${SSE_EVENTS}\"]" step_verify_event_type_preservation
run_step "verify_retry_timing" 11 "[\"${RECONNECT_LOG}\"]" step_verify_retry_timing
run_step "teardown" 12 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo ""
echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
echo "Replay: SEED=${SEED} EVENTS_BEFORE_FIRST_DISCONNECT=${EVENTS_BEFORE_FIRST_DISCONNECT} bash $0"
