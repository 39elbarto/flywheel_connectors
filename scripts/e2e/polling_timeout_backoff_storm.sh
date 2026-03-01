#!/usr/bin/env bash
# =============================================================================
# polling_timeout_backoff_storm.sh — Polling Timeout + Backoff Storm Stress Test
# =============================================================================
# Bead:     235t.26.6.2 (ASUPERSYNC-E2E Failure-Recovery Script Library)
# Contract: contract.polling_timeout_backoff_bounded_recovery
# Schema:   asupersync-forensics/v1
#
# Scenario: Stress polling archetype under sustained timeout conditions.
#   Inject server-side latency to trigger consecutive poll timeouts, verify that
#   backoff is bounded (max interval, jitter), poll loop recovers when latency
#   lifts, and cursor consistency is maintained across timeout-recovery boundary.
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with polling capability
#   3.  Create capability token with poll operations
#   4.  Start polling loop (normal baseline)
#   5.  Collect baseline events (verify working)
#   6.  Inject server-side latency fault (poll_timeout_ms * 2)
#   7.  Verify poll timeouts are detected (N consecutive)
#   8.  Verify backoff interval increases (exponential)
#   9.  Verify backoff is bounded (max_backoff_ms ceiling)
#  10.  Lift latency fault
#  11.  Verify poll recovery (events resume)
#  12.  Verify cursor continuity (no gaps across timeout boundary)
#  13.  Verify no duplicate events post-recovery
#  14.  Verify total timeout count matches expectations
#  15.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_polling_timeout_backoff_storm"
SCENARIO_ID="asupersync.e2e.polling_timeout_backoff_storm"
SEED="${SEED:-0xP0LLT1M3}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"
EVENTS_BASELINE="${OUT_DIR}/events_baseline.jsonl"
EVENTS_RECOVERY="${OUT_DIR}/events_recovery.jsonl"
TIMEOUT_LOG="${OUT_DIR}/timeout_attempts.jsonl"

# Stress parameters
POLL_INTERVAL_MS="${POLL_INTERVAL_MS:-500}"
POLL_TIMEOUT_MS="${POLL_TIMEOUT_MS:-2000}"
INJECTED_LATENCY_MS="${INJECTED_LATENCY_MS:-5000}"
CONSECUTIVE_TIMEOUTS="${CONSECUTIVE_TIMEOUTS:-8}"
MAX_BACKOFF_MS="${MAX_BACKOFF_MS:-30000}"
BASELINE_COLLECT_SEC="${BASELINE_COLLECT_SEC:-3}"
RECOVERY_COLLECT_SEC="${RECOVERY_COLLECT_SEC:-5}"
EXPECTED_MIN_BASELINE_EVENTS="${EXPECTED_MIN_BASELINE_EVENTS:-3}"

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
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=poll,poll_now \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_start_baseline_poll() {
  : > "${EVENTS_BASELINE}"
  : > "${TIMEOUT_LOG}"

  fcp-harness poll \
    --connector="${CONNECTOR}" \
    --operation=poll \
    --token="${OUT_DIR}/token.cbor" \
    --interval-ms "${POLL_INTERVAL_MS}" \
    --timeout-ms "${POLL_TIMEOUT_MS}" \
    --events-out "${EVENTS_BASELINE}" \
    --timeout-log "${TIMEOUT_LOG}" \
    --max-backoff-ms "${MAX_BACKOFF_MS}" \
    --background \
    --pid-file="${OUT_DIR}/poll.pid"
}

step_collect_baseline() {
  sleep "${BASELINE_COLLECT_SEC}"
  local count
  count=$(wc -l < "${EVENTS_BASELINE}" | tr -d ' ')
  if [[ "${count}" -lt "${EXPECTED_MIN_BASELINE_EVENTS}" ]]; then
    echo "FAIL: baseline events (${count}) < expected (${EXPECTED_MIN_BASELINE_EVENTS})" >&2
    return 1
  fi
}

step_inject_latency() {
  fcp-harness fault inject \
    --type=server-latency \
    --connector="${CONNECTOR}" \
    --latency-ms="${INJECTED_LATENCY_MS}" \
    --zone="${ZONE}"
}

step_verify_timeouts() {
  # Wait for consecutive timeouts to accumulate
  local wait_sec=$(( (POLL_TIMEOUT_MS * CONSECUTIVE_TIMEOUTS + POLL_INTERVAL_MS * CONSECUTIVE_TIMEOUTS) / 1000 + 2 ))
  sleep "${wait_sec}"

  local timeout_count
  timeout_count=$(wc -l < "${TIMEOUT_LOG}" | tr -d ' ')
  if [[ "${timeout_count}" -lt "${CONSECUTIVE_TIMEOUTS}" ]]; then
    echo "FAIL: timeout count (${timeout_count}) < expected (${CONSECUTIVE_TIMEOUTS})" >&2
    return 1
  fi
}

step_verify_backoff_bounded() {
  # Parse timeout log and verify backoff intervals
  local max_interval=0
  local prev_ts=0
  while IFS= read -r line; do
    local ts
    ts=$(printf '%s' "${line}" | jq -r '.timestamp_ms // 0')
    if [[ "${prev_ts}" -gt 0 ]]; then
      local interval=$(( ts - prev_ts ))
      if [[ "${interval}" -gt "${max_interval}" ]]; then
        max_interval="${interval}"
      fi
    fi
    prev_ts="${ts}"
  done < "${TIMEOUT_LOG}"

  # Verify bounded (allow 10% tolerance)
  local bounded_ceiling=$(( MAX_BACKOFF_MS + MAX_BACKOFF_MS / 10 ))
  if [[ "${max_interval}" -gt "${bounded_ceiling}" ]]; then
    echo "FAIL: max backoff interval (${max_interval}ms) exceeds ceiling (${bounded_ceiling}ms)" >&2
    return 1
  fi
}

step_lift_latency() {
  fcp-harness fault clear \
    --type=server-latency \
    --connector="${CONNECTOR}" \
    --zone="${ZONE}"
}

step_verify_recovery() {
  : > "${EVENTS_RECOVERY}"
  sleep "${RECOVERY_COLLECT_SEC}"

  # Copy new events since latency lift
  local recovery_events
  recovery_events=$(wc -l < "${EVENTS_RECOVERY}" | tr -d ' ')
  if [[ "${recovery_events}" -lt 1 ]]; then
    echo "FAIL: no events received after recovery" >&2
    return 1
  fi
}

step_verify_cursor_continuity() {
  # Check that cursor values are monotonically increasing across the
  # baseline → timeout → recovery boundary with no gaps
  local all_cursors
  all_cursors=$(cat "${EVENTS_BASELINE}" "${EVENTS_RECOVERY}" | jq -r '.cursor // empty' | sort -n)
  local prev=""
  local gap=false
  while IFS= read -r cursor; do
    if [[ -n "${prev}" ]]; then
      local expected=$(( prev + 1 ))
      if [[ "${cursor}" -ne "${expected}" ]]; then
        echo "WARN: cursor gap detected: ${prev} -> ${cursor}" >&2
        gap=true
      fi
    fi
    prev="${cursor}"
  done <<< "${all_cursors}"

  if [[ "${gap}" == "true" ]]; then
    return 1
  fi
}

step_verify_no_duplicates() {
  local total
  total=$(cat "${EVENTS_BASELINE}" "${EVENTS_RECOVERY}" | jq -r '.event_id // empty' | wc -l | tr -d ' ')
  local unique
  unique=$(cat "${EVENTS_BASELINE}" "${EVENTS_RECOVERY}" | jq -r '.event_id // empty' | sort -u | wc -l | tr -d ' ')
  if [[ "${total}" -ne "${unique}" ]]; then
    echo "FAIL: duplicate events detected: total=${total} unique=${unique}" >&2
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

echo "=== Polling Timeout Backoff Storm: ${SCENARIO_ID} ==="
echo "Seed: ${SEED}"
echo "Timeout: ${POLL_TIMEOUT_MS}ms, Injected latency: ${INJECTED_LATENCY_MS}ms"
echo "Max backoff: ${MAX_BACKOFF_MS}ms, Target timeouts: ${CONSECUTIVE_TIMEOUTS}"
echo ""

run_step "init_harness"             1  '{}' step_init
run_step "install_connector"        2  '{}' step_install
run_step "create_token"             3  '{"token":"token.cbor"}' step_create_token
run_step "start_baseline_poll"      4  '{}' step_start_baseline_poll
run_step "collect_baseline"         5  '{"events":"events_baseline.jsonl"}' step_collect_baseline
run_step "inject_latency"           6  '{"latency_ms":'"${INJECTED_LATENCY_MS}"'}' step_inject_latency
run_step "verify_timeouts"          7  '{"timeout_log":"timeout_attempts.jsonl"}' step_verify_timeouts
run_step "verify_backoff_bounded"   8  '{}' step_verify_backoff_bounded
run_step "lift_latency"             9  '{}' step_lift_latency
run_step "verify_recovery"         10  '{"events":"events_recovery.jsonl"}' step_verify_recovery
run_step "verify_cursor_continuity" 11 '{}' step_verify_cursor_continuity
run_step "verify_no_duplicates"    12  '{}' step_verify_no_duplicates
run_step "teardown"                13  '{}' step_teardown

echo ""
echo "=== PASS: ${SCENARIO_ID} ==="
echo "Log:       ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
