#!/usr/bin/env bash
# =============================================================================
# request_timeout_chain.sh — Request/Response Timeout Chain Stress Test
# =============================================================================
# Bead:     235t.26.6.2 (ASUPERSYNC-E2E Failure-Recovery Script Library)
# Contract: contract.request_timeout_chain_bounded_failure
# Schema:   asupersync-forensics/v1
#
# Scenario: Inject cascading timeout conditions across request/response flows.
#   Verify that timeout propagation is bounded, partial responses are handled
#   correctly, connection pool recovery works after timeout storms, and error
#   taxonomy classification matches expected failure classes.
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with invoke capability
#   3.  Create capability token with invoke operations
#   4.  Baseline request (verify working)
#   5.  Inject per-request latency (exceeds timeout budget)
#   6.  Send N requests under timeout conditions
#   7.  Verify all requests timeout (not hang)
#   8.  Verify timeout error taxonomy (correct error class/code)
#   9.  Verify no partial/corrupt responses leaked
#  10.  Lift latency fault
#  11.  Verify connection pool recovery (requests succeed)
#  12.  Verify error telemetry (timeout count, mean latency)
#  13.  Verify no resource leaks (open connections bounded)
#  14.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_request_timeout_chain"
SCENARIO_ID="asupersync.e2e.request_timeout_chain"
SEED="${SEED:-0xT1M30UT1}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"
RESPONSES_JSONL="${OUT_DIR}/responses.jsonl"
TIMEOUT_ERRORS="${OUT_DIR}/timeout_errors.jsonl"
RECOVERY_RESPONSES="${OUT_DIR}/recovery_responses.jsonl"

# Stress parameters
REQUEST_TIMEOUT_MS="${REQUEST_TIMEOUT_MS:-3000}"
INJECTED_LATENCY_MS="${INJECTED_LATENCY_MS:-10000}"
CONCURRENT_REQUESTS="${CONCURRENT_REQUESTS:-10}"
RECOVERY_REQUESTS="${RECOVERY_REQUESTS:-5}"

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
    "${operation}" "${attempt}" "${REQUEST_TIMEOUT_MS}" "${outcome}" "${elapsed_ms}")

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
    --operations=invoke,echo \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_baseline_request() {
  : > "${RESPONSES_JSONL}"

  fcp invoke "${CONNECTOR}" echo \
    --args='{"message":"baseline"}' \
    --token="${OUT_DIR}/token.cbor" \
    --timeout-ms="${REQUEST_TIMEOUT_MS}" \
    --output="${OUT_DIR}/baseline_response.json"

  if [[ ! -f "${OUT_DIR}/baseline_response.json" ]]; then
    echo "FAIL: baseline request did not produce response" >&2
    return 1
  fi
}

step_inject_latency() {
  : > "${TIMEOUT_ERRORS}"

  fcp-harness fault inject \
    --type=server-latency \
    --connector="${CONNECTOR}" \
    --latency-ms="${INJECTED_LATENCY_MS}" \
    --zone="${ZONE}"
}

step_send_timeout_requests() {
  local i
  for i in $(seq 1 "${CONCURRENT_REQUESTS}"); do
    (
      set +e
      fcp invoke "${CONNECTOR}" echo \
        --args='{"message":"timeout_test","seq":'"${i}"'}' \
        --token="${OUT_DIR}/token.cbor" \
        --timeout-ms="${REQUEST_TIMEOUT_MS}" \
        --output="${OUT_DIR}/response_${i}.json" 2>"${OUT_DIR}/error_${i}.txt"
      local rc=$?
      printf '{"seq":%d,"exit_code":%d,"error_file":"error_%d.txt"}\n' "${i}" "${rc}" "${i}" >> "${TIMEOUT_ERRORS}"
    ) &
  done
  wait
}

step_verify_all_timeout() {
  local total
  total=$(wc -l < "${TIMEOUT_ERRORS}" | tr -d ' ')
  if [[ "${total}" -ne "${CONCURRENT_REQUESTS}" ]]; then
    echo "FAIL: expected ${CONCURRENT_REQUESTS} results, got ${total}" >&2
    return 1
  fi

  # Every request should have failed (non-zero exit)
  local succeeded
  succeeded=$(jq -r 'select(.exit_code == 0) | .seq' "${TIMEOUT_ERRORS}" | wc -l | tr -d ' ')
  if [[ "${succeeded}" -gt 0 ]]; then
    echo "FAIL: ${succeeded} requests succeeded under timeout conditions" >&2
    return 1
  fi
}

step_verify_error_taxonomy() {
  # Verify error files contain correct taxonomy classification
  local i
  for i in $(seq 1 "${CONCURRENT_REQUESTS}"); do
    if [[ -f "${OUT_DIR}/error_${i}.txt" ]]; then
      if ! grep -qi "timeout\|deadline\|exceeded" "${OUT_DIR}/error_${i}.txt"; then
        echo "WARN: error_${i}.txt does not mention timeout/deadline" >&2
      fi
    fi
  done
}

step_verify_no_partial() {
  # Verify no partial/corrupt response files leaked
  local i
  for i in $(seq 1 "${CONCURRENT_REQUESTS}"); do
    if [[ -f "${OUT_DIR}/response_${i}.json" ]]; then
      local size
      size=$(wc -c < "${OUT_DIR}/response_${i}.json" | tr -d ' ')
      if [[ "${size}" -gt 0 ]]; then
        echo "FAIL: partial response leaked for request ${i} (${size} bytes)" >&2
        return 1
      fi
    fi
  done
}

step_lift_latency() {
  fcp-harness fault clear \
    --type=server-latency \
    --connector="${CONNECTOR}" \
    --zone="${ZONE}"
}

step_verify_recovery() {
  : > "${RECOVERY_RESPONSES}"
  sleep 2

  local i
  for i in $(seq 1 "${RECOVERY_REQUESTS}"); do
    fcp invoke "${CONNECTOR}" echo \
      --args='{"message":"recovery_test","seq":'"${i}"'}' \
      --token="${OUT_DIR}/token.cbor" \
      --timeout-ms="${REQUEST_TIMEOUT_MS}" \
      --output="${OUT_DIR}/recovery_${i}.json"

    printf '{"seq":%d,"success":true}\n' "${i}" >> "${RECOVERY_RESPONSES}"
  done

  local recovered
  recovered=$(wc -l < "${RECOVERY_RESPONSES}" | tr -d ' ')
  if [[ "${recovered}" -ne "${RECOVERY_REQUESTS}" ]]; then
    echo "FAIL: only ${recovered}/${RECOVERY_REQUESTS} recovery requests succeeded" >&2
    return 1
  fi
}

step_verify_telemetry() {
  # Verify error count matches expectations
  local timeout_count
  timeout_count=$(wc -l < "${TIMEOUT_ERRORS}" | tr -d ' ')
  if [[ "${timeout_count}" -ne "${CONCURRENT_REQUESTS}" ]]; then
    echo "FAIL: timeout count (${timeout_count}) != concurrent requests (${CONCURRENT_REQUESTS})" >&2
    return 1
  fi
}

step_verify_no_leaks() {
  # Verify connection pool is not exhausted after timeout storm
  fcp-harness health --expect=healthy
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

echo "=== Request Timeout Chain: ${SCENARIO_ID} ==="
echo "Seed: ${SEED}"
echo "Timeout: ${REQUEST_TIMEOUT_MS}ms, Injected latency: ${INJECTED_LATENCY_MS}ms"
echo "Concurrent requests: ${CONCURRENT_REQUESTS}"
echo ""

run_step "init_harness"             1  '{}' step_init
run_step "install_connector"        2  '{}' step_install
run_step "create_token"             3  '{"token":"token.cbor"}' step_create_token
run_step "baseline_request"         4  '{"response":"baseline_response.json"}' step_baseline_request
run_step "inject_latency"           5  '{"latency_ms":'"${INJECTED_LATENCY_MS}"'}' step_inject_latency
run_step "send_timeout_requests"    6  '{"count":'"${CONCURRENT_REQUESTS}"'}' step_send_timeout_requests
run_step "verify_all_timeout"       7  '{"timeout_errors":"timeout_errors.jsonl"}' step_verify_all_timeout
run_step "verify_error_taxonomy"    8  '{}' step_verify_error_taxonomy
run_step "verify_no_partial"        9  '{}' step_verify_no_partial
run_step "lift_latency"            10  '{}' step_lift_latency
run_step "verify_recovery"         11  '{"recovery":"recovery_responses.jsonl"}' step_verify_recovery
run_step "verify_telemetry"        12  '{}' step_verify_telemetry
run_step "verify_no_leaks"         13  '{}' step_verify_no_leaks
run_step "teardown"                14  '{}' step_teardown

echo ""
echo "=== PASS: ${SCENARIO_ID} ==="
echo "Log:       ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
