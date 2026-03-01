#!/usr/bin/env bash
# =============================================================================
# polling_cursor_gap_recovery.sh — Polling Cursor Gap Detection + Recovery
# =============================================================================
# Bead:     235t.26.6.2 (ASUPERSYNC-E2E Failure-Recovery Script Library)
# Contract: contract.polling_cursor_gap_detection_recovery
# Schema:   asupersync-forensics/v1
#
# Scenario: Simulate cursor gaps caused by server-side data loss/compaction.
#   Verify that the polling client detects cursor discontinuities, triggers
#   gap-fill recovery, handles irrecoverable gaps gracefully, and maintains
#   forward progress without infinite retry loops.
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with polling capability
#   3.  Create capability token
#   4.  Start polling loop and collect baseline events
#   5.  Inject cursor gap (server-side data compaction)
#   6.  Verify gap detection (logged with diagnostics)
#   7.  Verify gap-fill attempt (recovery request issued)
#   8.  Inject irrecoverable gap (data permanently lost)
#   9.  Verify graceful skip (forward progress after max retries)
#  10.  Verify no infinite retry loop (bounded attempts)
#  11.  Verify event stream resumes after gap skip
#  12.  Verify gap metadata in forensics log
#  13.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_polling_cursor_gap_recovery"
SCENARIO_ID="asupersync.e2e.polling_cursor_gap_recovery"
SEED="${SEED:-0xCUR50RG4}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"
EVENTS_JSONL="${OUT_DIR}/events.jsonl"
GAP_LOG="${OUT_DIR}/gap_detections.jsonl"
RECOVERY_LOG="${OUT_DIR}/gap_recovery.jsonl"

# Parameters
POLL_INTERVAL_MS="${POLL_INTERVAL_MS:-500}"
POLL_TIMEOUT_MS="${POLL_TIMEOUT_MS:-5000}"
BASELINE_COLLECT_SEC="${BASELINE_COLLECT_SEC:-3}"
GAP_SIZE="${GAP_SIZE:-10}"
MAX_GAP_FILL_RETRIES="${MAX_GAP_FILL_RETRIES:-3}"
POST_GAP_COLLECT_SEC="${POST_GAP_COLLECT_SEC:-5}"

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
  local timestamp correlation_id

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
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=poll,poll_now \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_baseline_poll() {
  : > "${EVENTS_JSONL}"
  : > "${GAP_LOG}"
  : > "${RECOVERY_LOG}"

  fcp-harness poll \
    --connector="${CONNECTOR}" \
    --operation=poll \
    --token="${OUT_DIR}/token.cbor" \
    --interval-ms "${POLL_INTERVAL_MS}" \
    --timeout-ms "${POLL_TIMEOUT_MS}" \
    --events-out "${EVENTS_JSONL}" \
    --gap-log "${GAP_LOG}" \
    --recovery-log "${RECOVERY_LOG}" \
    --max-gap-fill-retries "${MAX_GAP_FILL_RETRIES}" \
    --background \
    --pid-file="${OUT_DIR}/poll.pid"

  sleep "${BASELINE_COLLECT_SEC}"
  local count
  count=$(wc -l < "${EVENTS_JSONL}" | tr -d ' ')
  if [[ "${count}" -lt 3 ]]; then
    echo "FAIL: baseline events (${count}) < 3" >&2
    return 1
  fi
}

step_inject_recoverable_gap() {
  fcp-harness fault inject \
    --type=cursor-gap \
    --connector="${CONNECTOR}" \
    --gap-size="${GAP_SIZE}" \
    --recoverable=true \
    --zone="${ZONE}"
}

step_verify_gap_detected() {
  sleep 5
  local detections
  detections=$(wc -l < "${GAP_LOG}" | tr -d ' ')
  if [[ "${detections}" -lt 1 ]]; then
    echo "FAIL: no cursor gap detected" >&2
    return 1
  fi
}

step_verify_gap_fill() {
  local fills
  fills=$(jq -r 'select(.action == "gap_fill") | .cursor_from' "${RECOVERY_LOG}" | wc -l | tr -d ' ')
  if [[ "${fills}" -lt 1 ]]; then
    echo "FAIL: no gap-fill recovery attempt logged" >&2
    return 1
  fi
}

step_inject_irrecoverable_gap() {
  fcp-harness fault inject \
    --type=cursor-gap \
    --connector="${CONNECTOR}" \
    --gap-size="${GAP_SIZE}" \
    --recoverable=false \
    --zone="${ZONE}"
}

step_verify_graceful_skip() {
  sleep 10
  local skips
  skips=$(jq -r 'select(.action == "gap_skip") | .cursor_from' "${RECOVERY_LOG}" | wc -l | tr -d ' ')
  if [[ "${skips}" -lt 1 ]]; then
    echo "FAIL: no graceful gap skip after irrecoverable gap" >&2
    return 1
  fi
}

step_verify_bounded_retries() {
  local max_attempts
  max_attempts=$(jq -r '.retry_attempt // 0' "${RECOVERY_LOG}" | sort -n | tail -1)
  if [[ "${max_attempts}" -gt "${MAX_GAP_FILL_RETRIES}" ]]; then
    echo "FAIL: retries (${max_attempts}) exceeded max (${MAX_GAP_FILL_RETRIES})" >&2
    return 1
  fi
}

step_verify_forward_progress() {
  local pre_skip_count
  pre_skip_count=$(wc -l < "${EVENTS_JSONL}" | tr -d ' ')
  sleep "${POST_GAP_COLLECT_SEC}"
  local post_skip_count
  post_skip_count=$(wc -l < "${EVENTS_JSONL}" | tr -d ' ')
  if [[ "${post_skip_count}" -le "${pre_skip_count}" ]]; then
    echo "FAIL: no forward progress after gap skip" >&2
    return 1
  fi
}

step_verify_gap_metadata() {
  # Verify forensics contain gap information
  local gap_entries
  gap_entries=$(jq -r 'select(.action == "gap_detected" or .action == "gap_fill" or .action == "gap_skip")' "${RECOVERY_LOG}" | wc -l | tr -d ' ')
  if [[ "${gap_entries}" -lt 2 ]]; then
    echo "FAIL: insufficient gap metadata in recovery log" >&2
    return 1
  fi
}

step_teardown() {
  if [[ -f "${OUT_DIR}/poll.pid" ]]; then
    kill "$(cat "${OUT_DIR}/poll.pid")" 2>/dev/null || true
  fi
  fcp-harness teardown
}

# --- Main execution ---

require_cmd jq
require_cmd fcp
require_cmd fcp-harness

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"
: > "${FORENSICS_JSONL}"

echo "=== Polling Cursor Gap Recovery: ${SCENARIO_ID} ==="
echo "Seed: ${SEED}"
echo "Gap size: ${GAP_SIZE}, Max fill retries: ${MAX_GAP_FILL_RETRIES}"
echo ""

run_step "init_harness"              1  '{}' step_init
run_step "install_connector"         2  '{}' step_install
run_step "create_token"              3  '{"token":"token.cbor"}' step_create_token
run_step "baseline_poll"             4  '{"events":"events.jsonl"}' step_baseline_poll
run_step "inject_recoverable_gap"    5  '{"gap_size":'"${GAP_SIZE}"'}' step_inject_recoverable_gap
run_step "verify_gap_detected"       6  '{"gap_log":"gap_detections.jsonl"}' step_verify_gap_detected
run_step "verify_gap_fill"           7  '{"recovery_log":"gap_recovery.jsonl"}' step_verify_gap_fill
run_step "inject_irrecoverable_gap"  8  '{"gap_size":'"${GAP_SIZE}"'}' step_inject_irrecoverable_gap
run_step "verify_graceful_skip"      9  '{}' step_verify_graceful_skip
run_step "verify_bounded_retries"   10  '{}' step_verify_bounded_retries
run_step "verify_forward_progress"  11  '{}' step_verify_forward_progress
run_step "verify_gap_metadata"      12  '{}' step_verify_gap_metadata
run_step "teardown"                 13  '{}' step_teardown

echo ""
echo "=== PASS: ${SCENARIO_ID} ==="
echo "Log:       ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
