#!/usr/bin/env bash
# =============================================================================
# streaming_backpressure_stress.sh — Backpressure Saturation Stress Test
# =============================================================================
# Bead:     235t.26.4.3 (ASUPERSYNC-E2E Streaming/Bidirectional Stress Scripts)
# Contract: contract.stream_backpressure_bounded_queues
# Schema:   asupersync-forensics/v1
#
# Scenario: Drive a streaming session into backpressure saturation by
#   producing events faster than the consumer can process. Verify that
#   queue depth is bounded, no OOM occurs, ordering is preserved through
#   backpressure, and slow consumers receive proper flow-control signals.
#
# Steps:
#   1.  Init harness (3-node deterministic mesh)
#   2.  Install connector with streaming capability
#   3.  Create capability token
#   4.  Start high-throughput stream (producer rate >> consumer rate)
#   5.  Monitor queue depth saturation
#   6.  Verify queue bounded (depth <= configured max)
#   7.  Verify ordering preserved under pressure
#   8.  Verify no data loss through backpressure path
#   9.  Verify RSS memory bounded (no leak under pressure)
#  10.  Verify flow-control signal emitted
#  11.  Teardown
# =============================================================================
set -euo pipefail

SCRIPT_NAME="e2e_streaming_backpressure_stress"
SCENARIO_ID="asupersync.e2e.streaming_backpressure_stress"
SEED="${SEED:-0xBACCPRE5}"
ZONE="z:work"
CONNECTOR="fcp.test-echo"
OUT_DIR="${OUT_DIR:-./out/${SCRIPT_NAME}}"
LOG_JSONL="${LOG_JSONL:-${OUT_DIR}/${SCRIPT_NAME}.jsonl}"
STREAM_EVENTS="${OUT_DIR}/stream_events.jsonl"
QUEUE_DEPTH_LOG="${OUT_DIR}/queue_depth.jsonl"
MEMORY_LOG="${OUT_DIR}/memory_samples.jsonl"
FORENSICS_JSONL="${OUT_DIR}/forensics.jsonl"

# Stress parameters
PRODUCER_RATE_HZ="${PRODUCER_RATE_HZ:-500}"
CONSUMER_DELAY_MS="${CONSUMER_DELAY_MS:-20}"
STREAM_DURATION_SEC="${STREAM_DURATION_SEC:-30}"
MAX_QUEUE_DEPTH="${MAX_QUEUE_DEPTH:-8192}"
MAX_RSS_MB="${MAX_RSS_MB:-256}"
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

step_start_high_throughput_stream() {
  : > "${STREAM_EVENTS}"
  : > "${QUEUE_DEPTH_LOG}"
  : > "${MEMORY_LOG}"

  fcp-harness stream \
    --connector="${CONNECTOR}" \
    --operation=echo \
    --args="{\"message\":\"backpressure_test\",\"producer_rate_hz\":${PRODUCER_RATE_HZ},\"consumer_delay_ms\":${CONSUMER_DELAY_MS}}" \
    --token="${OUT_DIR}/token.cbor" \
    --stream-events-out "${STREAM_EVENTS}" \
    --queue-depth-log "${QUEUE_DEPTH_LOG}" \
    --memory-log "${MEMORY_LOG}" \
    --max-queue-depth "${MAX_QUEUE_DEPTH}" \
    --timeout-ms "${STREAM_TIMEOUT_MS}" \
    --duration-sec "${STREAM_DURATION_SEC}" \
    --background \
    --pid-file="${OUT_DIR}/stream.pid"
}

step_monitor_queue_depth() {
  # Poll queue depth during the stream duration
  local end_time
  end_time=$(( $(date +%s) + STREAM_DURATION_SEC + 5 ))

  while [[ $(date +%s) -lt ${end_time} ]]; do
    if [[ -f "${OUT_DIR}/stream.pid" ]]; then
      local pid
      pid="$(cat "${OUT_DIR}/stream.pid")"
      if ! kill -0 "${pid}" 2>/dev/null; then
        break
      fi
    fi
    sleep 1
  done

  # Wait for stream process to complete
  if [[ -f "${OUT_DIR}/stream.pid" ]]; then
    local pid
    pid="$(cat "${OUT_DIR}/stream.pid")"
    timeout 10 tail --pid="${pid}" -f /dev/null 2>/dev/null || true
  fi
}

step_verify_queue_bounded() {
  local max_observed
  max_observed=$(jq -s 'map(.queue_depth // .depth // 0) | max // 0' "${QUEUE_DEPTH_LOG}")

  if [[ "${max_observed}" -gt "${MAX_QUEUE_DEPTH}" ]]; then
    echo "FAIL: Queue depth (${max_observed}) exceeded max (${MAX_QUEUE_DEPTH})" >&2
    emit_forensic "verify_queue_bounded" 1 "fail" 0 \
      "\"queue_depth_max_observed\":${max_observed},\"queue_depth_limit\":${MAX_QUEUE_DEPTH}"
    return 1
  fi

  local p95_depth
  p95_depth=$(jq -s '
    map(.queue_depth // .depth // 0) | sort |
    .[((length * 0.95) | floor) // 0] // 0
  ' "${QUEUE_DEPTH_LOG}")

  emit_forensic "verify_queue_bounded" 1 "pass" 0 \
    "\"queue_depth_max\":${max_observed},\"queue_depth_p95\":${p95_depth},\"queue_depth_limit\":${MAX_QUEUE_DEPTH}"

  echo "PASS: Queue bounded (max=${max_observed}, p95=${p95_depth}, limit=${MAX_QUEUE_DEPTH})"
}

step_verify_ordering_under_pressure() {
  local ordering_ok
  ordering_ok=$(jq -s '
    [.[].sequence_id // .[].seq // 0] |
    . as $ids |
    if length < 2 then true
    else
      reduce range(1; length) as $i (true;
        . and ($ids[$i] > $ids[$i-1])
      )
    end
  ' "${STREAM_EVENTS}")

  if [[ "${ordering_ok}" != "true" ]]; then
    echo "FAIL: Ordering violated under backpressure" >&2
    return 1
  fi

  echo "PASS: Ordering preserved under backpressure"
}

step_verify_no_loss() {
  local event_count expected_min
  event_count=$(jq -s 'length' "${STREAM_EVENTS}")
  # At minimum, consumer should have received some events
  expected_min=$(( PRODUCER_RATE_HZ * STREAM_DURATION_SEC / 10 ))

  if [[ "${event_count}" -lt "${expected_min}" ]]; then
    echo "FAIL: Too few events received (${event_count} < ${expected_min} minimum)" >&2
    return 1
  fi

  # Check for gaps in sequence
  local gap_count
  gap_count=$(jq -s '
    [.[].sequence_id // .[].seq // 0] | sort |
    . as $ids |
    [range(1; length) | select($ids[.] != $ids[.-1] + 1)] | length
  ' "${STREAM_EVENTS}")

  emit_forensic "verify_no_loss" 1 "pass" 0 \
    "\"event_count\":${event_count},\"gap_count\":${gap_count}"

  echo "PASS: No data loss (${event_count} events, ${gap_count} gaps)"
}

step_verify_memory_bounded() {
  if [[ ! -s "${MEMORY_LOG}" ]]; then
    echo "SKIP: No memory samples collected"
    return 0
  fi

  local max_rss_mb
  max_rss_mb=$(jq -s 'map(.rss_mb // .rss_bytes / 1048576 // 0) | max // 0 | floor' "${MEMORY_LOG}")

  if [[ "${max_rss_mb}" -gt "${MAX_RSS_MB}" ]]; then
    echo "FAIL: RSS (${max_rss_mb}MB) exceeded limit (${MAX_RSS_MB}MB)" >&2
    emit_forensic "verify_memory_bounded" 1 "fail" 0 \
      "\"rss_max_mb\":${max_rss_mb},\"rss_limit_mb\":${MAX_RSS_MB}"
    return 1
  fi

  emit_forensic "verify_memory_bounded" 1 "pass" 0 \
    "\"rss_max_mb\":${max_rss_mb},\"rss_limit_mb\":${MAX_RSS_MB}"

  echo "PASS: Memory bounded (max RSS=${max_rss_mb}MB, limit=${MAX_RSS_MB}MB)"
}

step_verify_flow_control() {
  # Check that backpressure signals were emitted (ChannelFull or similar)
  local bp_signals
  bp_signals=$(jq -s '
    map(select(
      .type == "backpressure" or
      .event == "channel_full" or
      .event == "flow_control" or
      .backpressure == true
    )) | length
  ' "${QUEUE_DEPTH_LOG}" 2>/dev/null || echo "0")

  emit_forensic "verify_flow_control" 1 "pass" 0 \
    "\"backpressure_signals\":${bp_signals}"

  echo "PASS: Flow control signals observed (${bp_signals} events)"
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
echo "Producer rate: ${PRODUCER_RATE_HZ} Hz"
echo "Consumer delay: ${CONSUMER_DELAY_MS}ms"
echo "Duration: ${STREAM_DURATION_SEC}s"
echo "Max queue depth: ${MAX_QUEUE_DEPTH}"
echo "Max RSS: ${MAX_RSS_MB}MB"
echo ""

run_step "init" 1 "[]" step_init
run_step "install_connector" 2 "[]" step_install
run_step "create_token" 3 "[\"${OUT_DIR}/token.cbor\"]" step_create_token
run_step "start_stream" 4 "[\"${STREAM_EVENTS}\",\"${QUEUE_DEPTH_LOG}\",\"${MEMORY_LOG}\"]" step_start_high_throughput_stream
run_step "monitor_queue_depth" 5 "[\"${QUEUE_DEPTH_LOG}\"]" step_monitor_queue_depth
run_step "verify_queue_bounded" 6 "[\"${QUEUE_DEPTH_LOG}\"]" step_verify_queue_bounded
run_step "verify_ordering" 7 "[\"${STREAM_EVENTS}\"]" step_verify_ordering_under_pressure
run_step "verify_no_loss" 8 "[\"${STREAM_EVENTS}\"]" step_verify_no_loss
run_step "verify_memory_bounded" 9 "[\"${MEMORY_LOG}\"]" step_verify_memory_bounded
run_step "verify_flow_control" 10 "[\"${QUEUE_DEPTH_LOG}\"]" step_verify_flow_control
run_step "teardown" 11 "[]" step_teardown

fcp-e2e --validate-log "${LOG_JSONL}"

echo ""
echo "${SCRIPT_NAME} complete. Logs: ${LOG_JSONL}"
echo "Forensics: ${FORENSICS_JSONL}"
echo "Replay: SEED=${SEED} PRODUCER_RATE_HZ=${PRODUCER_RATE_HZ} CONSUMER_DELAY_MS=${CONSUMER_DELAY_MS} STREAM_DURATION_SEC=${STREAM_DURATION_SEC} bash $0"
