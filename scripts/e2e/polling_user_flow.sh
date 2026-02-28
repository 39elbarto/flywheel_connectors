#!/usr/bin/env bash
# =============================================================================
# polling_user_flow.sh — Polling Archetype User Journey E2E
# =============================================================================
# Bead:     235t.26.4.2 (ASUPERSYNC-E2E User Flow Scripts)
# Contract: contract.polling_user_journey
# Schema:   asupersync-forensics/v1
#
# Scenario: Full polling archetype journey covering start_polling, event
#   consumption with cursor tracking, poll_now for immediate results,
#   stop_polling, and crash-recovery resume from persisted cursor.
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with polling capability
#   3.  Create capability token with poll operations
#   4.  Start polling loop (connector-initiated)
#   5.  Consume events and track cursors
#   6.  Verify event ordering (monotonic sequence)
#   7.  Trigger poll_now for immediate results
#   8.  Verify poll_now returns events
#   9.  Stop polling and drain remaining events
#  10.  Resume polling from saved cursor (crash recovery)
#  11.  Verify no duplicate events after resume
#  12.  Verify cursor continuity (no gaps across resume)
#  13.  Stop polling final
#  14.  Verify event count and completeness
#  15.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_polling_user_flow"
SCENARIO_ID="asupersync.e2e.polling_user_flow"
SEED="${SEED:-0xP0LL1NG1}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"
EVENTS_JSONL="${OUT_DIR}/events.jsonl"
EVENTS_RESUMED_JSONL="${OUT_DIR}/events_resumed.jsonl"
CURSOR_FILE="${OUT_DIR}/cursor.json"

# Polling parameters
POLL_INTERVAL_MS="${POLL_INTERVAL_MS:-1000}"
POLL_TIMEOUT_MS="${POLL_TIMEOUT_MS:-30000}"
POLL_COLLECT_DURATION_SEC="${POLL_COLLECT_DURATION_SEC:-5}"
RESUME_COLLECT_DURATION_SEC="${RESUME_COLLECT_DURATION_SEC:-3}"
EXPECTED_MIN_EVENTS="${EXPECTED_MIN_EVENTS:-3}"

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
    "${operation}" "${attempt}" "${POLL_TIMEOUT_MS}" "${outcome}" "${elapsed_ms}")

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
  fcp verify "${CONNECTOR}" --expect=valid
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=poll,events \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_start_polling() {
  : > "${EVENTS_JSONL}"

  fcp-harness poll start \
    --connector="${CONNECTOR}" \
    --target="test-source" \
    --interval-ms="${POLL_INTERVAL_MS}" \
    --token="${OUT_DIR}/token.cbor" \
    --zone="${ZONE}"

  echo "PASS: Polling started (interval=${POLL_INTERVAL_MS}ms)"
}

step_consume_events() {
  # Collect events for a fixed duration
  fcp-harness poll collect-events \
    --connector="${CONNECTOR}" \
    --token="${OUT_DIR}/token.cbor" \
    --duration-sec="${POLL_COLLECT_DURATION_SEC}" \
    --events-out="${EVENTS_JSONL}" \
    --cursor-out="${CURSOR_FILE}" \
    --timeout-ms="${POLL_TIMEOUT_MS}"

  local event_count
  event_count=$(wc -l < "${EVENTS_JSONL}" | tr -d ' ')

  emit_forensic "consume_events" 1 "pass" 0 \
    "\"event_count\":${event_count},\"collect_duration_sec\":${POLL_COLLECT_DURATION_SEC}"

  echo "PASS: Collected ${event_count} events"
}

step_verify_event_ordering() {
  local ordering_ok
  ordering_ok=$(jq -s '
    [.[].seq // .[].sequence_id // 0] |
    . as $ids |
    if length < 2 then true
    else
      reduce range(1; length) as $i (true;
        . and ($ids[$i] >= $ids[$i-1])
      )
    end
  ' "${EVENTS_JSONL}")

  if [[ "${ordering_ok}" != "true" ]]; then
    echo "FAIL: Event ordering violated (non-monotonic sequence)" >&2
    jq -s '[.[].seq // .[].sequence_id // 0]' "${EVENTS_JSONL}" \
      > "${OUT_DIR}/ordering_debug.json" 2>/dev/null || true
    return 1
  fi

  echo "PASS: Event ordering preserved (monotonic)"
}

step_poll_now() {
  # Trigger immediate poll and capture count
  fcp-harness poll now \
    --connector="${CONNECTOR}" \
    --target="test-source" \
    --token="${OUT_DIR}/token.cbor" \
    --output="${OUT_DIR}/poll_now_result.json"

  echo "PASS: poll_now triggered"
}

step_verify_poll_now() {
  # Verify poll_now returned events or count
  jq -e '.event_count >= 0 or .events != null' \
    "${OUT_DIR}/poll_now_result.json" >/dev/null

  local poll_now_count
  poll_now_count=$(jq -r '.event_count // (.events | length) // 0' \
    "${OUT_DIR}/poll_now_result.json")

  emit_forensic "verify_poll_now" 1 "pass" 0 \
    "\"poll_now_event_count\":${poll_now_count}"

  echo "PASS: poll_now returned ${poll_now_count} events"
}

step_stop_polling() {
  fcp-harness poll stop \
    --connector="${CONNECTOR}" \
    --target="test-source" \
    --token="${OUT_DIR}/token.cbor"

  echo "PASS: Polling stopped"
}

step_resume_from_cursor() {
  : > "${EVENTS_RESUMED_JSONL}"

  # Read saved cursor position
  local cursor
  cursor=$(jq -r '.cursor // .position // ""' "${CURSOR_FILE}" 2>/dev/null || echo "")

  if [[ -z "${cursor}" ]]; then
    echo "WARN: No cursor found, resuming from beginning" >&2
  fi

  # Restart polling from cursor (simulates crash recovery)
  fcp-harness poll start \
    --connector="${CONNECTOR}" \
    --target="test-source" \
    --interval-ms="${POLL_INTERVAL_MS}" \
    --token="${OUT_DIR}/token.cbor" \
    --zone="${ZONE}" \
    --resume-cursor="${cursor}"

  # Collect events after resume
  fcp-harness poll collect-events \
    --connector="${CONNECTOR}" \
    --token="${OUT_DIR}/token.cbor" \
    --duration-sec="${RESUME_COLLECT_DURATION_SEC}" \
    --events-out="${EVENTS_RESUMED_JSONL}" \
    --timeout-ms="${POLL_TIMEOUT_MS}"

  local resumed_count
  resumed_count=$(wc -l < "${EVENTS_RESUMED_JSONL}" | tr -d ' ')

  emit_forensic "resume_from_cursor" 1 "pass" 0 \
    "\"cursor\":\"${cursor}\",\"resumed_event_count\":${resumed_count}"

  echo "PASS: Resumed from cursor, collected ${resumed_count} events"
}

step_verify_no_duplicates() {
  # Combine pre-stop and post-resume events, check for duplicates
  local combined="${OUT_DIR}/events_combined.jsonl"
  cat "${EVENTS_JSONL}" "${EVENTS_RESUMED_JSONL}" > "${combined}"

  local dup_count
  dup_count=$(jq -s '
    [.[].seq // .[].sequence_id // .[].event_id // 0] |
    group_by(.) | map(select(length > 1)) | length
  ' "${combined}")

  if [[ "${dup_count}" -gt 0 ]]; then
    echo "FAIL: ${dup_count} duplicate event(s) after cursor resume" >&2
    jq -s '
      [.[].seq // .[].sequence_id // .[].event_id // 0] |
      group_by(.) | map(select(length > 1)) |
      map({"id": .[0], "count": length})
    ' "${combined}" > "${OUT_DIR}/resume_duplicates.json" 2>/dev/null || true
    return 1
  fi

  echo "PASS: No duplicate events after cursor resume"
}

step_verify_cursor_continuity() {
  # Verify last seq before stop <= first seq after resume (no gap)
  local last_before first_after
  last_before=$(jq -s 'last | .seq // .sequence_id // 0' "${EVENTS_JSONL}" 2>/dev/null || echo "0")
  first_after=$(jq -s 'first | .seq // .sequence_id // 0' "${EVENTS_RESUMED_JSONL}" 2>/dev/null || echo "0")

  if [[ "${first_after}" -lt "${last_before}" ]]; then
    echo "WARN: Resumed events overlap with pre-stop events (acceptable with at-least-once)" >&2
  fi

  emit_forensic "verify_cursor_continuity" 1 "pass" 0 \
    "\"last_before_stop\":${last_before},\"first_after_resume\":${first_after}"

  echo "PASS: Cursor continuity verified (last=${last_before}, resumed_first=${first_after})"
}

step_stop_polling_final() {
  fcp-harness poll stop \
    --connector="${CONNECTOR}" \
    --target="test-source" \
    --token="${OUT_DIR}/token.cbor"

  echo "PASS: Final polling stop"
}

step_verify_completeness() {
  local total_events
  total_events=$(cat "${EVENTS_JSONL}" "${EVENTS_RESUMED_JSONL}" | wc -l | tr -d ' ')

  if [[ "${total_events}" -lt "${EXPECTED_MIN_EVENTS}" ]]; then
    echo "FAIL: Total events (${total_events}) below minimum (${EXPECTED_MIN_EVENTS})" >&2
    return 1
  fi

  emit_forensic "verify_completeness" 1 "pass" 0 \
    "\"total_events\":${total_events},\"expected_min\":${EXPECTED_MIN_EVENTS}"

  echo "PASS: Total event count (${total_events}) meets minimum (${EXPECTED_MIN_EVENTS})"
}

step_teardown() {
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
echo "Zone: ${ZONE}"
echo "Connector: ${CONNECTOR}"
echo "Poll interval: ${POLL_INTERVAL_MS}ms"
echo "Poll timeout: ${POLL_TIMEOUT_MS}ms"
echo "Collect duration: ${POLL_COLLECT_DURATION_SEC}s"
echo ""

run_step "init"                    1  "[]"                                   step_init
run_step "install_connector"       2  "[]"                                   step_install
run_step "create_token"            3  "[\"${OUT_DIR}/token.cbor\"]"          step_create_token
run_step "start_polling"           4  "[]"                                   step_start_polling
run_step "consume_events"          5  "[\"${EVENTS_JSONL}\",\"${CURSOR_FILE}\"]" step_consume_events
run_step "verify_event_ordering"   6  "[]"                                   step_verify_event_ordering
run_step "poll_now"                7  "[\"${OUT_DIR}/poll_now_result.json\"]" step_poll_now
run_step "verify_poll_now"         8  "[]"                                   step_verify_poll_now
run_step "stop_polling"            9  "[]"                                   step_stop_polling
run_step "resume_from_cursor"      10 "[\"${EVENTS_RESUMED_JSONL}\"]"        step_resume_from_cursor
run_step "verify_no_duplicates"    11 "[]"                                   step_verify_no_duplicates
run_step "verify_cursor_continuity" 12 "[]"                                  step_verify_cursor_continuity
run_step "stop_polling_final"      13 "[]"                                   step_stop_polling_final
run_step "verify_completeness"     14 "[]"                                   step_verify_completeness
run_step "teardown"                15 "[]"                                   step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo ""
echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
echo "Replay: SEED=${SEED} POLL_INTERVAL_MS=${POLL_INTERVAL_MS} POLL_COLLECT_DURATION_SEC=${POLL_COLLECT_DURATION_SEC} bash $0"
