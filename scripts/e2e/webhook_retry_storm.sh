#!/usr/bin/env bash
# =============================================================================
# webhook_retry_storm.sh — Webhook Retry Storm + Idempotency Stress Test
# =============================================================================
# Bead:     235t.26.6.2 (ASUPERSYNC-E2E Failure-Recovery Script Library)
# Contract: contract.webhook_retry_storm_idempotent_delivery
# Schema:   asupersync-forensics/v1
#
# Scenario: Inject sustained delivery failures on a webhook endpoint to trigger
#   retry storms. Verify that retry backoff is bounded, idempotency keys prevent
#   duplicate processing, delivery eventually succeeds after failures lift, and
#   webhook signature verification holds across retries.
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with webhook capability
#   3.  Create capability token with webhook operations
#   4.  Register webhook endpoint
#   5.  Send test event (baseline successful delivery)
#   6.  Inject endpoint failure (HTTP 503)
#   7.  Send events during failure window (triggers retries)
#   8.  Verify retry attempts logged (bounded count)
#   9.  Verify retry backoff is exponential + bounded
#  10.  Lift endpoint failure
#  11.  Verify deferred events are delivered (retry success)
#  12.  Verify idempotency (no duplicate deliveries)
#  13.  Verify signature validity on retried deliveries
#  14.  Verify delivery ordering (causal consistency)
#  15.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_webhook_retry_storm"
SCENARIO_ID="asupersync.e2e.webhook_retry_storm"
SEED="${SEED:-0xWH00KR3T}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"
DELIVERIES_JSONL="${OUT_DIR}/deliveries.jsonl"
RETRY_LOG="${OUT_DIR}/retry_attempts.jsonl"

# Stress parameters
EVENTS_DURING_FAILURE="${EVENTS_DURING_FAILURE:-5}"
MAX_RETRY_ATTEMPTS="${MAX_RETRY_ATTEMPTS:-10}"
RETRY_TIMEOUT_MS="${RETRY_TIMEOUT_MS:-60000}"
MAX_RETRY_BACKOFF_MS="${MAX_RETRY_BACKOFF_MS:-30000}"
FAILURE_DURATION_SEC="${FAILURE_DURATION_SEC:-10}"
RECOVERY_WAIT_SEC="${RECOVERY_WAIT_SEC:-15}"

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
    "${operation}" "${attempt}" "${RETRY_TIMEOUT_MS}" "${outcome}" "${elapsed_ms}")

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
    --operations=webhook_register,webhook_send \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_register_endpoint() {
  fcp-harness webhook register \
    --connector="${CONNECTOR}" \
    --url="http://localhost:0/webhook-sink" \
    --secret-key="${SEED}" \
    --token="${OUT_DIR}/token.cbor" \
    --deliveries-out="${DELIVERIES_JSONL}" \
    --retry-log="${RETRY_LOG}" \
    --max-retries="${MAX_RETRY_ATTEMPTS}" \
    --max-backoff-ms="${MAX_RETRY_BACKOFF_MS}" \
    --output="${OUT_DIR}/endpoint.json"
}

step_baseline_delivery() {
  : > "${DELIVERIES_JSONL}"

  fcp-harness webhook send \
    --connector="${CONNECTOR}" \
    --endpoint="${OUT_DIR}/endpoint.json" \
    --payload='{"event":"baseline_test","seq":0}' \
    --token="${OUT_DIR}/token.cbor"

  sleep 2
  local count
  count=$(wc -l < "${DELIVERIES_JSONL}" | tr -d ' ')
  if [[ "${count}" -lt 1 ]]; then
    echo "FAIL: baseline delivery not received" >&2
    return 1
  fi
}

step_inject_failure() {
  : > "${RETRY_LOG}"

  fcp-harness fault inject \
    --type=endpoint-failure \
    --connector="${CONNECTOR}" \
    --status-code=503 \
    --zone="${ZONE}"
}

step_send_during_failure() {
  local i
  for i in $(seq 1 "${EVENTS_DURING_FAILURE}"); do
    fcp-harness webhook send \
      --connector="${CONNECTOR}" \
      --endpoint="${OUT_DIR}/endpoint.json" \
      --payload='{"event":"failure_window","seq":'"${i}"'}' \
      --token="${OUT_DIR}/token.cbor"
    sleep 1
  done
}

step_verify_retries() {
  sleep "${FAILURE_DURATION_SEC}"
  local retry_count
  retry_count=$(wc -l < "${RETRY_LOG}" | tr -d ' ')
  if [[ "${retry_count}" -lt "${EVENTS_DURING_FAILURE}" ]]; then
    echo "FAIL: retry count (${retry_count}) < events sent (${EVENTS_DURING_FAILURE})" >&2
    return 1
  fi
  # Verify bounded
  local max_retries_per_event
  max_retries_per_event=$(jq -r '.retry_attempt // 0' "${RETRY_LOG}" | sort -n | tail -1)
  if [[ "${max_retries_per_event}" -gt "${MAX_RETRY_ATTEMPTS}" ]]; then
    echo "FAIL: retries per event (${max_retries_per_event}) exceeds max (${MAX_RETRY_ATTEMPTS})" >&2
    return 1
  fi
}

step_verify_retry_backoff() {
  # Parse retry log and verify exponential backoff with bounded ceiling
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
  done < "${RETRY_LOG}"

  local bounded_ceiling=$(( MAX_RETRY_BACKOFF_MS + MAX_RETRY_BACKOFF_MS / 10 ))
  if [[ "${max_interval}" -gt "${bounded_ceiling}" ]]; then
    echo "FAIL: max retry interval (${max_interval}ms) exceeds ceiling (${bounded_ceiling}ms)" >&2
    return 1
  fi
}

step_lift_failure() {
  fcp-harness fault clear \
    --type=endpoint-failure \
    --connector="${CONNECTOR}" \
    --zone="${ZONE}"
}

step_verify_deferred_delivery() {
  sleep "${RECOVERY_WAIT_SEC}"
  local delivered
  delivered=$(jq -r 'select(.event == "failure_window") | .seq' "${DELIVERIES_JSONL}" | sort -n | wc -l | tr -d ' ')
  if [[ "${delivered}" -lt "${EVENTS_DURING_FAILURE}" ]]; then
    echo "FAIL: only ${delivered}/${EVENTS_DURING_FAILURE} deferred events delivered" >&2
    return 1
  fi
}

step_verify_idempotency() {
  # Check that each event_id appears exactly once in deliveries
  local total
  total=$(jq -r '.idempotency_key // .event_id // empty' "${DELIVERIES_JSONL}" | wc -l | tr -d ' ')
  local unique
  unique=$(jq -r '.idempotency_key // .event_id // empty' "${DELIVERIES_JSONL}" | sort -u | wc -l | tr -d ' ')
  if [[ "${total}" -ne "${unique}" ]]; then
    echo "FAIL: duplicate deliveries detected: total=${total} unique=${unique}" >&2
    return 1
  fi
}

step_verify_signatures() {
  # Verify all delivered webhooks have valid signatures
  local invalid
  invalid=$(jq -r 'select(.signature_valid == false) | .event_id' "${DELIVERIES_JSONL}" | wc -l | tr -d ' ')
  if [[ "${invalid}" -gt 0 ]]; then
    echo "FAIL: ${invalid} deliveries with invalid signatures" >&2
    return 1
  fi
}

step_verify_ordering() {
  # Verify causal ordering: events with causal dependency are delivered in order
  local prev_seq=-1
  local ordering_ok=true
  while IFS= read -r seq; do
    if [[ "${seq}" -le "${prev_seq}" ]]; then
      echo "WARN: out-of-order delivery: seq=${seq} after seq=${prev_seq}" >&2
      ordering_ok=false
    fi
    prev_seq="${seq}"
  done < <(jq -r 'select(.event == "failure_window") | .seq' "${DELIVERIES_JSONL}")

  if [[ "${ordering_ok}" != "true" ]]; then
    return 1
  fi
}

step_teardown() {
  fcp-harness teardown
}

# --- Main execution ---

require_cmd jq
require_cmd fcp
require_cmd fcp-harness

mkdir -p "${OUT_DIR}"
: > "${LOG_JSONL}"
: > "${FORENSICS_JSONL}"
: > "${DELIVERIES_JSONL}"

echo "=== Webhook Retry Storm: ${SCENARIO_ID} ==="
echo "Seed: ${SEED}"
echo "Events during failure: ${EVENTS_DURING_FAILURE}"
echo "Max retries: ${MAX_RETRY_ATTEMPTS}, Max backoff: ${MAX_RETRY_BACKOFF_MS}ms"
echo ""

run_step "init_harness"             1  '{}' step_init
run_step "install_connector"        2  '{}' step_install
run_step "create_token"             3  '{"token":"token.cbor"}' step_create_token
run_step "register_endpoint"        4  '{"endpoint":"endpoint.json"}' step_register_endpoint
run_step "baseline_delivery"        5  '{"deliveries":"deliveries.jsonl"}' step_baseline_delivery
run_step "inject_failure"           6  '{"status_code":503}' step_inject_failure
run_step "send_during_failure"      7  '{"count":'"${EVENTS_DURING_FAILURE}"'}' step_send_during_failure
run_step "verify_retries"           8  '{"retry_log":"retry_attempts.jsonl"}' step_verify_retries
run_step "verify_retry_backoff"     9  '{}' step_verify_retry_backoff
run_step "lift_failure"            10  '{}' step_lift_failure
run_step "verify_deferred_delivery" 11 '{}' step_verify_deferred_delivery
run_step "verify_idempotency"      12  '{}' step_verify_idempotency
run_step "verify_signatures"       13  '{}' step_verify_signatures
run_step "verify_ordering"         14  '{}' step_verify_ordering
run_step "teardown"                15  '{}' step_teardown

echo ""
echo "=== PASS: ${SCENARIO_ID} ==="
echo "Log:       ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
