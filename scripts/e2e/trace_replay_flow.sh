#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_trace_replay_flow"
SCENARIO_ID="asupersync.e2e.trace_replay_flow"
SEED="${SEED:-0x7R4CEREP}"
TRACE_ID="${TRACE_ID:-trace-e2e-replay}"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
FLOW_JSONL="${OUT_DIR}/${SCRIPT_NAME}.trace_flow.jsonl"
MESH_TEST_LOG="${OUT_DIR}/mesh_trace_capture.log"
MESH_STAGE_JSONL="${OUT_DIR}/mesh_trace_capture_events.jsonl"
TRACE_JSON="${OUT_DIR}/captured_trace.json"
TRACE_MISMATCH_JSON="${OUT_DIR}/captured_trace_mismatch.json"
REPLAY_REPORT_JSON="${OUT_DIR}/replay_report.json"
REPLAY_MISMATCH_REPORT_JSON="${OUT_DIR}/replay_report_mismatch.json"

STEP_MISMATCHES=0
STEP_DETAILS="null"
CARGO_CMD="${CARGO_CMD:-rch exec -- cargo}"
read -r -a CARGO_CMD_ARR <<< "${CARGO_CMD}"
CARGO_BIN="${CARGO_CMD_ARR[0]}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_cargo() {
  "${CARGO_CMD_ARR[@]}" "$@"
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
  hex=$(printf '%s-%s-%s-%s' "${SCRIPT_NAME}" "${SCENARIO_ID}" "${SEED}" "${step_number}" | hash256 | awk '{print $1}')
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

log_step() {
  local stage="$1"
  local step_number="$2"
  local result="$3"
  local duration_ms="$4"
  local artifacts_json="$5"
  local timestamp
  local correlation_id

  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  correlation_id="$(correlation_id_for_step "${step_number}")"

  mkdir -p "$(dirname "${LOG_JSONL}")"
  printf '{"timestamp":"%s","log_version":"v2","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":{"stage":"%s","trace_id":"%s","mismatches":%s,"meta":%s}}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${stage}" "${step_number}" "${correlation_id}" "${duration_ms}" "${result}" "${artifacts_json}" "${stage}" "${TRACE_ID}" "${STEP_MISMATCHES}" "${STEP_DETAILS}" >> "${LOG_JSONL}"

  printf '{"timestamp":"%s","stage":"%s","trace_id":"%s","result":"%s","mismatches":%s,"duration_ms":%s}\n' \
    "${timestamp}" "${stage}" "${TRACE_ID}" "${result}" "${STEP_MISMATCHES}" "${duration_ms}" >> "${FLOW_JSONL}"
}

run_step() {
  local stage="$1"
  local step_number="$2"
  local artifacts_json="$3"
  local details_json="$4"
  shift 4

  local start_ms end_ms duration_ms rc
  STEP_MISMATCHES=0
  STEP_DETAILS="${details_json}"

  start_ms="$(now_ms)"
  set +e
  "$@"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    log_step "${stage}" "${step_number}" "pass" "${duration_ms}" "${artifacts_json}"
  else
    log_step "${stage}" "${step_number}" "fail" "${duration_ms}" "${artifacts_json}"
    exit ${rc}
  fi
}

step_prepare() {
  mkdir -p "${OUT_DIR}"
  : > "${LOG_JSONL}"
  : > "${FLOW_JSONL}"
}

step_run_known_decisions() {
  run_cargo test -p fcp-mesh --test mesh_integration meshnode_trace_capture_replay_multinode_staged_logs -- --nocapture | tee "${MESH_TEST_LOG}"
  awk '/^\{/{print}' "${MESH_TEST_LOG}" \
    | jq -c 'select(.test_name == "meshnode_trace_capture_replay_multinode_staged_logs")' \
    > "${MESH_STAGE_JSONL}"

  jq -se 'map(select(.phase == "capture")) | length >= 1' "${MESH_STAGE_JSONL}" >/dev/null
  jq -se 'map(select(.phase == "replay")) | length >= 1' "${MESH_STAGE_JSONL}" >/dev/null
  jq -se 'map(select(.phase == "compare")) | length >= 1' "${MESH_STAGE_JSONL}" >/dev/null

  jq -se '
    map(select(.phase == "capture"))[0].details.admit_decisions >= 1 and
    map(select(.phase == "capture"))[0].details.reject_decisions >= 1
  ' "${MESH_STAGE_JSONL}" >/dev/null

  jq -se '
    map(select(.phase == "compare"))[0].details.session_id_redacted == true
  ' "${MESH_STAGE_JSONL}" >/dev/null

  STEP_MISMATCHES="$(jq -r -s 'map(select(.phase == "replay"))[0].details.mismatched_decisions // 0' "${MESH_STAGE_JSONL}")"
  if [[ "${STEP_MISMATCHES}" -ne 0 ]]; then
    echo "Unexpected replay mismatches in mesh trace stage output: ${STEP_MISMATCHES}" >&2
    return 1
  fi
}

step_capture_trace() {
  jq -n --arg trace_id "${TRACE_ID}" '
    {
      id: $trace_id,
      version: 1,
      started_at: 1706832000000,
      ended_at: 1706832000100,
      capturing_node: "node-e2e",
      events: [
        {
          event_type: "routing",
          timestamp: 1706832000001,
          trace_id: $trace_id,
          source_node: "node-1",
          target_node: "node-2",
          object_id: "obj-1",
          path_type: "direct",
          decision: "routed",
          reason: null
        },
        {
          event_type: "policy",
          timestamp: 1706832000002,
          trace_id: $trace_id,
          zone_id: "z:work",
          operation: "telegram.send_message",
          connector_id: "fcp.telegram",
          decision: "allow",
          reason_code: "CAP_OK",
          evidence: ["obj-1"]
        }
      ],
      redacted: false
    }
  ' > "${TRACE_JSON}"

  jq -e '.id == "'"${TRACE_ID}"'" and (.events | length == 2)' "${TRACE_JSON}" >/dev/null
}

step_replay_trace() {
  run_cargo run -q -p fcp-cli --bin fcp -- \
    trace replay "${TRACE_JSON}" --format json --json > "${REPLAY_REPORT_JSON}"

  jq -e '.source_trace_id == "'"${TRACE_ID}"'"' "${REPLAY_REPORT_JSON}" >/dev/null
  jq -e '.replayed_events == .input_events' "${REPLAY_REPORT_JSON}" >/dev/null

  STEP_MISMATCHES="$(jq -r '.summary.mismatched_events + .summary.mismatched_decisions' "${REPLAY_REPORT_JSON}")"
  if [[ "${STEP_MISMATCHES}" -ne 0 ]]; then
    echo "Expected zero replay mismatches, got ${STEP_MISMATCHES}" >&2
    return 1
  fi
}

step_compare_decisions() {
  jq -e '.summary.expected_decision_counts == .summary.actual_decision_counts' "${REPLAY_REPORT_JSON}" >/dev/null
  jq -e '(.diffs | length) == 0' "${REPLAY_REPORT_JSON}" >/dev/null

  STEP_MISMATCHES="$(jq -r '.summary.mismatched_events + .summary.mismatched_decisions' "${REPLAY_REPORT_JSON}")"
}

step_replay_mutated_trace() {
  jq '.events[1].decision = "deny"' "${TRACE_JSON}" > "${TRACE_MISMATCH_JSON}"

  run_cargo run -q -p fcp-cli --bin fcp -- \
    trace replay "${TRACE_MISMATCH_JSON}" --format json --json > "${REPLAY_MISMATCH_REPORT_JSON}"

  STEP_MISMATCHES="$(jq -r '.summary.mismatched_events + .summary.mismatched_decisions' "${REPLAY_MISMATCH_REPORT_JSON}")"
  if [[ "${STEP_MISMATCHES}" -ne 0 ]]; then
    echo "Mutated trace replay should still be deterministic (expected zero mismatches)" >&2
    return 1
  fi

  jq -e '.source_trace_id == "'"${TRACE_ID}"'"' "${REPLAY_MISMATCH_REPORT_JSON}" >/dev/null
  jq -e '.summary.actual_decision_counts.deny == 1' "${REPLAY_MISMATCH_REPORT_JSON}" >/dev/null
  jq -e '(.diffs | length) == 0' "${REPLAY_MISMATCH_REPORT_JSON}" >/dev/null
}

step_teardown() {
  true
}

require_cmd "${CARGO_BIN}"
require_cmd jq

run_step "prepare" 1 "[]" \
  '{"purpose":"initialize output directories and logs"}' \
  step_prepare
run_step "run_scenario" 2 "[\"${MESH_TEST_LOG}\",\"${MESH_STAGE_JSONL}\"]" \
  '{"purpose":"execute mesh trace capture/replay test with known admit/reject decisions"}' \
  step_run_known_decisions
run_step "capture_trace" 3 "[\"${TRACE_JSON}\"]" \
  '{"purpose":"persist deterministic captured trace object"}' \
  step_capture_trace
run_step "replay_trace" 4 "[\"${REPLAY_REPORT_JSON}\"]" \
  '{"purpose":"replay captured trace and collect replay decision report"}' \
  step_replay_trace
run_step "compare_decisions" 5 "[\"${REPLAY_REPORT_JSON}\"]" \
  '{"purpose":"compare expected vs replayed decisions for parity"}' \
  step_compare_decisions
run_step "replay_mutated_trace" 6 "[\"${TRACE_MISMATCH_JSON}\",\"${REPLAY_MISMATCH_REPORT_JSON}\"]" \
  '{"purpose":"verify deterministic replay over mutated trace input"}' \
  step_replay_mutated_trace
run_step "teardown" 7 "[]" \
  '{"purpose":"no-op teardown"}' \
  step_teardown

run_fcp_e2e --validate-log "${LOG_JSONL}"

echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Replay report: ${REPLAY_REPORT_JSON}"
echo "Mismatch probe report: ${REPLAY_MISMATCH_REPORT_JSON}"
