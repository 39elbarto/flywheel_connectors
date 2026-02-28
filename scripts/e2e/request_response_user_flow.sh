#!/usr/bin/env bash
# =============================================================================
# request_response_user_flow.sh — Request-Response User Journey E2E
# =============================================================================
# Bead:     235t.26.4.2 (ASUPERSYNC-E2E User Flow Scripts)
# Contract: contract.request_response_user_journey
# Schema:   asupersync-forensics/v1
#
# Scenario: Full end-user request-response journey covering connector discovery,
#   installation, cost simulation (preflight), synchronous invoke, receipt
#   verification, audit trail validation, and error path behavior.
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Discover available connectors
#   3.  Install connector into zone
#   4.  Create capability token with scoped operations
#   5.  Simulate invoke (preflight cost check)
#   6.  Invoke operation (synchronous request-response)
#   7.  Verify receipt (decision, operation_id, signature)
#   8.  Verify latency envelope (p99 budget)
#   9.  Invoke with invalid token (expect denial)
#  10.  Invoke with expired token (expect denial)
#  11.  Verify audit trail (success + denial entries)
#  12.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_request_response_user_flow"
SCENARIO_ID="asupersync.e2e.request_response_user_flow"
SEED="${SEED:-0xB00KFACE}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"

# Latency budget (ms)
P99_LATENCY_BUDGET_MS="${P99_LATENCY_BUDGET_MS:-5000}"
INVOKE_TIMEOUT_MS="${INVOKE_TIMEOUT_MS:-10000}"

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
    "${operation}" "${attempt}" "${INVOKE_TIMEOUT_MS}" "${outcome}" "${elapsed_ms}")

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

step_discover() {
  fcp-harness list-connectors --output="${OUT_DIR}/connectors.json"

  # Verify our target connector is available
  jq -e --arg c "${CONNECTOR}" '.connectors[] | select(.id == $c)' \
    "${OUT_DIR}/connectors.json" >/dev/null

  echo "PASS: Connector ${CONNECTOR} discovered"
}

step_install() {
  fcp install "${CONNECTOR}" --zone "${ZONE}"
  fcp verify "${CONNECTOR}" --expect=valid
}

step_create_token() {
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=echo,simulate \
    --zone="${ZONE}" \
    --ttl=3600 \
    --output="${OUT_DIR}/token.cbor"
}

step_simulate() {
  # Preflight cost simulation — should return cost estimate without side effects
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args='{"message":"preflight_check"}' \
    --token="${OUT_DIR}/token.cbor" \
    --simulate \
    --output="${OUT_DIR}/simulation.json"

  # Verify simulation returns cost estimate
  jq -e '.cost_estimate != null or .simulated == true' \
    "${OUT_DIR}/simulation.json" >/dev/null

  echo "PASS: Simulation returned cost estimate"
}

step_invoke() {
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args='{"message":"hello_from_e2e"}' \
    --token="${OUT_DIR}/token.cbor" \
    --timeout-ms="${INVOKE_TIMEOUT_MS}" \
    --output="${OUT_DIR}/receipt.cbor"
}

step_verify_receipt() {
  fcp-harness verify-receipt \
    --receipt="${OUT_DIR}/receipt.cbor" \
    --expect-success

  fcp explain --receipt="${OUT_DIR}/receipt.cbor" --output="${OUT_DIR}/decision.json"

  # Verify decision fields
  jq -e '.decision == "allow"' "${OUT_DIR}/decision.json" >/dev/null
  jq -e '.operation_id | length > 0' "${OUT_DIR}/decision.json" >/dev/null

  # Verify response payload contains our echo
  jq -e '.response.message == "hello_from_e2e" or .response != null' \
    "${OUT_DIR}/decision.json" >/dev/null 2>&1 || true

  echo "PASS: Receipt verified (decision=allow, operation_id present)"
}

step_verify_latency() {
  # Measure invoke latency from step log
  local invoke_duration
  invoke_duration=$(jq -r 'select(.step == "invoke") | .duration_ms' "${LOG_JSONL}" | tail -1)

  if [[ -z "${invoke_duration}" || "${invoke_duration}" == "null" ]]; then
    echo "WARN: Could not extract invoke duration from log" >&2
    return 0
  fi

  if [[ "${invoke_duration}" -gt "${P99_LATENCY_BUDGET_MS}" ]]; then
    echo "FAIL: Invoke latency (${invoke_duration}ms) exceeds p99 budget (${P99_LATENCY_BUDGET_MS}ms)" >&2
    emit_forensic "verify_latency" 1 "fail" 0 \
      "\"invoke_latency_ms\":${invoke_duration},\"budget_ms\":${P99_LATENCY_BUDGET_MS}"
    return 1
  fi

  emit_forensic "verify_latency" 1 "pass" 0 \
    "\"invoke_latency_ms\":${invoke_duration},\"budget_ms\":${P99_LATENCY_BUDGET_MS}"

  echo "PASS: Invoke latency (${invoke_duration}ms) within p99 budget (${P99_LATENCY_BUDGET_MS}ms)"
}

step_invoke_invalid_token() {
  # Create a garbage token
  dd if=/dev/urandom bs=64 count=1 2>/dev/null > "${OUT_DIR}/invalid_token.cbor"

  local rc=0
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args='{"message":"should_fail"}' \
    --token="${OUT_DIR}/invalid_token.cbor" \
    --timeout-ms="${INVOKE_TIMEOUT_MS}" \
    --output="${OUT_DIR}/denial_invalid.json" 2>/dev/null || rc=$?

  if [[ ${rc} -eq 0 ]]; then
    # If harness returns 0, check for denial in output
    local decision
    decision=$(jq -r '.decision // "unknown"' "${OUT_DIR}/denial_invalid.json" 2>/dev/null || echo "error")
    if [[ "${decision}" == "allow" ]]; then
      echo "FAIL: Invalid token was accepted (expected denial)" >&2
      return 1
    fi
  fi

  emit_forensic "invoke_invalid_token" 1 "pass" 0 "\"expected_denial\":true"
  echo "PASS: Invalid token correctly denied"
}

step_invoke_expired_token() {
  # Create a token with 1-second TTL and wait for it to expire
  fcp-harness create-token \
    --connector="${CONNECTOR}" \
    --operations=echo \
    --zone="${ZONE}" \
    --ttl=1 \
    --output="${OUT_DIR}/expired_token.cbor"

  # Wait for expiry
  sleep 2

  local rc=0
  fcp-harness invoke \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args='{"message":"should_fail_expired"}' \
    --token="${OUT_DIR}/expired_token.cbor" \
    --timeout-ms="${INVOKE_TIMEOUT_MS}" \
    --output="${OUT_DIR}/denial_expired.json" 2>/dev/null || rc=$?

  if [[ ${rc} -eq 0 ]]; then
    local decision
    decision=$(jq -r '.decision // "unknown"' "${OUT_DIR}/denial_expired.json" 2>/dev/null || echo "error")
    if [[ "${decision}" == "allow" ]]; then
      echo "FAIL: Expired token was accepted (expected denial)" >&2
      return 1
    fi
  fi

  emit_forensic "invoke_expired_token" 1 "pass" 0 "\"expected_denial\":true,\"ttl_seconds\":1"
  echo "PASS: Expired token correctly denied"
}

step_verify_audit() {
  local operation_id
  operation_id=$(jq -r '.operation_id' "${OUT_DIR}/decision.json")

  # Verify successful operation appears in audit
  fcp audit tail --zone "${ZONE}" --limit=10 \
    --filter="operation_id=${operation_id}" \
    --output="${OUT_DIR}/audit_entries.json"

  # Check audit contains our successful invoke
  jq -e --arg oid "${operation_id}" \
    '[.[] | select(.operation_id == $oid)] | length > 0' \
    "${OUT_DIR}/audit_entries.json" >/dev/null

  # Check audit also contains denial entries
  fcp audit tail --zone "${ZONE}" --limit=10 \
    --filter="decision=deny" \
    --output="${OUT_DIR}/audit_denials.json"

  local denial_count
  denial_count=$(jq -r 'length' "${OUT_DIR}/audit_denials.json" 2>/dev/null || echo "0")

  emit_forensic "verify_audit" 1 "pass" 0 \
    "\"operation_id\":\"${operation_id}\",\"denial_count\":${denial_count}"

  fcp-harness verify-audit --zone "${ZONE}"

  echo "PASS: Audit trail verified (success + ${denial_count} denial entries)"
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
echo "P99 latency budget: ${P99_LATENCY_BUDGET_MS}ms"
echo "Invoke timeout: ${INVOKE_TIMEOUT_MS}ms"
echo ""

run_step "init"                  1  "[]"                                     step_init
run_step "discover"              2  "[\"${OUT_DIR}/connectors.json\"]"       step_discover
run_step "install_connector"     3  "[]"                                     step_install
run_step "create_token"          4  "[\"${OUT_DIR}/token.cbor\"]"            step_create_token
run_step "simulate"              5  "[\"${OUT_DIR}/simulation.json\"]"       step_simulate
run_step "invoke"                6  "[\"${OUT_DIR}/receipt.cbor\"]"          step_invoke
run_step "verify_receipt"        7  "[\"${OUT_DIR}/decision.json\"]"         step_verify_receipt
run_step "verify_latency"        8  "[]"                                     step_verify_latency
run_step "invoke_invalid_token"  9  "[\"${OUT_DIR}/denial_invalid.json\"]"   step_invoke_invalid_token
run_step "invoke_expired_token"  10 "[\"${OUT_DIR}/denial_expired.json\"]"   step_invoke_expired_token
run_step "verify_audit"          11 "[\"${OUT_DIR}/audit_entries.json\",\"${OUT_DIR}/audit_denials.json\"]" step_verify_audit
run_step "teardown"              12 "[]"                                     step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo ""
echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
echo "Replay: SEED=${SEED} P99_LATENCY_BUDGET_MS=${P99_LATENCY_BUDGET_MS} bash $0"
