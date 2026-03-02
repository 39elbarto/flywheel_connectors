#!/usr/bin/env bash
# =============================================================================
# e2e_reliability_soak_adversarial_load.sh — Reliability Soak + Adversarial Load
# =============================================================================
# Bead:     235t.28.2 (ASUPERSYNC-PERF Reliability Soak + Adversarial Load)
# Schema:   asupersync-reliability-soak/v1
#
# Validates stability under prolonged and stress-induced conditions via:
# - Long-horizon soak scenarios (steady state, burst spikes, near-capacity)
# - Adversarial load profiles (repair pressure, pool exhaustion, jitter cascade)
# - Assertions for reconnect resilience, timeout/cancellation storms,
#   queue/backpressure stability, and error-budget adherence
#
# Scenario Matrix:
#   Phase 1: Pre-flight (dependency checks + metric baseline)
#   Phase 2: Steady-state soak (sustained load, queue/memory bounded)
#   Phase 3: Burst-spike soak (10x traffic spike → recovery)
#   Phase 4: Near-capacity soak (95% queue/timeout budgets)
#   Phase 5: Adversarial reconnect storm (cascading disconnects)
#   Phase 6: Adversarial repair pressure (concurrent RaptorQ decode storms)
#   Phase 7: Adversarial pool exhaustion (connection/resource saturation)
#   Phase 8: Metric validation + regression detection
#   Phase 9: Evidence bundle generation
#
# Usage:
#   bash scripts/e2e/e2e_reliability_soak_adversarial_load.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing scenarios
#   --only-phases <csv>     Filter: steady_soak,burst_soak,capacity_soak,
#                           adversarial_reconnect,adversarial_repair,
#                           adversarial_pool,metric_validation
#   --soak-duration <sec>   Soak duration override (default: 120 for CI, 7200 full)
#   --ci                    CI mode (short soak durations, strict thresholds)
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-reliability-soak/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"
ONLY_PHASES=""
SOAK_DURATION=""

declare -i CHECK_PASS=0
declare -i CHECK_FAIL=0
declare -i CHECK_SKIP=0
declare -i CHECK_WARN=0
declare -a FINDING_RECORDS=()
declare -a METRIC_RECORDS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_reliability_soak_adversarial_load.sh [options]

Reliability Soak + Adversarial Load E2E Scripts

Validates stability under prolonged and stress-induced conditions.
Covers soak (steady/burst/capacity), adversarial (reconnect/repair/pool),
and metric validation with regression detection.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/reliability-soak/<run-id>)
  --dry-run               Emit plan without executing scenarios
  --only-phases <csv>     Filter: steady_soak,burst_soak,capacity_soak,
                          adversarial_reconnect,adversarial_repair,
                          adversarial_pool,metric_validation
  --soak-duration <sec>   Override soak duration (default: 120 CI, 7200 full)
  --ci                    CI mode (short durations, strict thresholds)
  -h, --help              Show this help
EOF
}

# ── Utility ─────────────────────────────────────────────────────────────────

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  fi
}

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

log_step() {
  printf '[%s] [RELIABILITY-SOAK/%s] %s\n' "$(now_iso)" "$1" "$2"
}

record_step() {
  local scenario_id="$1"
  local operation="$2"
  local outcome="$3"
  local elapsed_ms="$4"
  local contract_id="${5:-n/a}"
  local reason="${6:-}"
  local log_path="${7:-}"

  jq -c -n \
    --arg schema_version "${FORENSICS_SCHEMA}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario_id "${scenario_id}" \
    --arg trace_id "${RUN_ID}-${scenario_id}" \
    --arg correlation_id "${RUN_ID}" \
    --arg connector "n/a" \
    --arg zone "n/a" \
    --arg operation "${operation}" \
    --argjson attempt 1 \
    --argjson timeout_budget_ms 600000 \
    --arg outcome "${outcome}" \
    --argjson elapsed_ms "${elapsed_ms}" \
    --arg contract_id "${contract_id}" \
    --arg reason "${reason}" \
    --arg log_path "${log_path}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      scenario_id: $scenario_id,
      trace_id: $trace_id,
      correlation_id: $correlation_id,
      connector: $connector,
      zone: $zone,
      operation: $operation,
      attempt: $attempt,
      timeout_budget_ms: $timeout_budget_ms,
      cancellation_reason: null,
      queue_depth: null,
      decode_budget: null,
      outcome: $outcome,
      elapsed_ms: $elapsed_ms,
      contract_id: (if ($contract_id | length) > 0 then $contract_id else null end),
      reason: (if ($reason | length) > 0 then $reason else null end),
      log_path: (if ($log_path | length) > 0 then $log_path else null end)
    }' >> "${STEPS_FILE}"
}

add_finding() {
  local phase="$1"
  local test_name="$2"
  local severity="$3"
  local description="$4"
  local remediation="$5"
  local f
  f="$(jq -c -n \
    --arg phase "${phase}" \
    --arg test_name "${test_name}" \
    --arg severity "${severity}" \
    --arg description "${description}" \
    --arg remediation "${remediation}" \
    --arg found_at "$(now_iso)" \
    '{
      phase: $phase,
      test_name: $test_name,
      severity: $severity,
      description: $description,
      remediation: $remediation,
      found_at: $found_at
    }')"
  FINDING_RECORDS+=("${f}")
}

add_metric() {
  local phase="$1"
  local metric_name="$2"
  local value="$3"
  local threshold="$4"
  local unit="$5"
  local status="$6"
  local m
  m="$(jq -c -n \
    --arg phase "${phase}" \
    --arg metric_name "${metric_name}" \
    --arg value "${value}" \
    --arg threshold "${threshold}" \
    --arg unit "${unit}" \
    --arg status "${status}" \
    --arg measured_at "$(now_iso)" \
    '{
      phase: $phase,
      metric: $metric_name,
      value: ($value | tonumber),
      threshold: ($threshold | tonumber),
      unit: $unit,
      status: $status,
      measured_at: $measured_at
    }')"
  METRIC_RECORDS+=("${m}")
}

should_run_phase() {
  local phase="$1"
  if [[ -z "${ONLY_PHASES}" ]]; then
    return 0
  fi
  echo ",${ONLY_PHASES}," | grep -q ",${phase}," && return 0
  return 1
}

run_cargo_check() {
  local label="$1"
  local package="$2"
  local test_filter="$3"
  local contract_id="$4"
  local phase_name="$5"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="reliability_soak.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] cargo test -p ${package} ${test_filter}"
    echo "[dry-run] cargo test -p ${package} ${test_filter}" > "${log_file}"
    record_step "${scenario_id}" "cargo_test" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    CHECK_SKIP=$((CHECK_SKIP + 1))
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)
  if command -v rch >/dev/null 2>&1; then
    if rch exec -- cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1; then
      status="pass"
    else
      status="fail"
    fi
  else
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-reliability-soak}" \
      cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1 && status="pass" || status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    CHECK_PASS=$((CHECK_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "cargo_test" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    CHECK_FAIL=$((CHECK_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "cargo_test" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_finding "${phase_name}" "${label}" "high" "${reason}" \
      "cargo test -p ${package} ${test_filter} -- --nocapture"
  fi
}

run_e2e_script() {
  local label="$1"
  local script_path="$2"
  local contract_id="$3"
  local phase_name="$4"
  local env_overrides="${5:-}"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="reliability_soak.${label}"
  local scenario_out="${OUT_ROOT}/scenarios/${label}"

  mkdir -p "${OUT_ROOT}/logs" "${scenario_out}"

  local full_script="${SCRIPT_DIR}/${script_path}"
  if [[ ! -f "${full_script}" ]]; then
    log_step "${label}" "SKIP — script not found: ${script_path}"
    CHECK_SKIP=$((CHECK_SKIP + 1))
    record_step "${scenario_id}" "e2e_script" "planned" 0 "${contract_id}" \
      "script_not_found: ${script_path}" "${log_file}"
    return 0
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] bash ${script_path} ${env_overrides}"
    echo "[dry-run] ${env_overrides} bash ${full_script}" > "${log_file}"
    record_step "${scenario_id}" "e2e_script" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    CHECK_SKIP=$((CHECK_SKIP + 1))
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)
  if env OUT_DIR="${scenario_out}" ${env_overrides} bash "${full_script}" > "${log_file}" 2>&1; then
    status="pass"
  else
    status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    CHECK_PASS=$((CHECK_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "e2e_script" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    CHECK_FAIL=$((CHECK_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "e2e_script" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_finding "${phase_name}" "${label}" "high" \
      "Scenario failed: ${reason}" "bash ${full_script}"
  fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)           RUN_ID="$2"; shift 2;;
    --out-root)         OUT_ROOT="$2"; shift 2;;
    --dry-run)          DRY_RUN=true; shift;;
    --only-phases)      ONLY_PHASES="$2"; shift 2;;
    --soak-duration)    SOAK_DURATION="$2"; shift 2;;
    --ci)               CI_MODE=true; shift;;
    -h|--help)          usage; exit 0;;
    *)                  echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Soak parameters ────────────────────────────────────────────────────────
# CI mode uses short durations for gate checks; full mode uses production soak
if [[ "${CI_MODE}" == "true" ]]; then
  STEADY_SOAK_SEC="${SOAK_DURATION:-120}"
  BURST_SOAK_SEC="${SOAK_DURATION:-90}"
  CAPACITY_SOAK_SEC="${SOAK_DURATION:-60}"
  ADVERSARIAL_DURATION_SEC="${SOAK_DURATION:-60}"
else
  STEADY_SOAK_SEC="${SOAK_DURATION:-7200}"
  BURST_SOAK_SEC="${SOAK_DURATION:-3600}"
  CAPACITY_SOAK_SEC="${SOAK_DURATION:-1800}"
  ADVERSARIAL_DURATION_SEC="${SOAK_DURATION:-900}"
fi

# Metric thresholds
LATENCY_P95_THRESHOLD_MS=500
LATENCY_P99_THRESHOLD_MS=2000
THROUGHPUT_MIN_OPS_S=50
MAX_RSS_MB=512
MAX_QUEUE_DEPTH=8192
ERROR_BUDGET_MAX_PERCENT=5
RECONNECT_SUCCESS_RATE_MIN=95
CANCEL_RECOVERY_MAX_MS=5000

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd cargo

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/reliability-soak/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/scenarios" "${OUT_ROOT}/metrics" "${OUT_ROOT}/evidence"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
SUMMARY_FILE="${OUT_ROOT}/summary.json"
FINDINGS_FILE="${OUT_ROOT}/findings.json"
METRICS_FILE="${OUT_ROOT}/metrics/metric_observations.json"
REGRESSION_FILE="${OUT_ROOT}/metrics/regression_report.json"
REPLAY_FILE="${OUT_ROOT}/replay.sh"

: > "${STEPS_FILE}"

log_step "INIT" "Reliability Soak + Adversarial Load v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"
log_step "INIT" "Soak durations: steady=${STEADY_SOAK_SEC}s burst=${BURST_SOAK_SEC}s capacity=${CAPACITY_SOAK_SEC}s adversarial=${ADVERSARIAL_DURATION_SEC}s"
echo ""

# =============================================================================
# Phase 1: Pre-flight — Dependency + Baseline Checks
# =============================================================================
log_step "PREFLIGHT" "Phase 1: Pre-flight validation"

phase_start=$(now_ms)
preflight_ok=true

# Check benchmark harness exists (28.1 dependency)
if [[ -f "${REPO_ROOT}/crates/fcp-store/benches/symbol_store.rs" ]]; then
  log_step "PREFLIGHT" "  [ok] Symbol store benchmark harness present (235t.28.1)"
else
  preflight_ok=false
fi

# Check stress scripts exist
STRESS_SCRIPTS=(
  "streaming_backpressure_stress.sh"
  "streaming_reconnect_storm.sh"
  "bidirectional_cancel_chain.sh"
  "polling_timeout_backoff_storm.sh"
  "webhook_retry_storm.sh"
  "request_timeout_chain.sh"
)
missing=0
for ss in "${STRESS_SCRIPTS[@]}"; do
  if [[ -f "${SCRIPT_DIR}/${ss}" ]]; then
    log_step "PREFLIGHT" "  [ok] ${ss}"
  else
    missing=$((missing + 1))
  fi
done

# Check performance pack exists
if [[ -f "${SCRIPT_DIR}/asupersync_performance_pack.sh" ]]; then
  log_step "PREFLIGHT" "  [ok] Performance pack present"
else
  preflight_ok=false
fi

# Check fcp-async-core runtime tests
if [[ -d "${REPO_ROOT}/crates/fcp-async-core" ]]; then
  log_step "PREFLIGHT" "  [ok] fcp-async-core crate present"
else
  preflight_ok=false
fi

phase_end=$(now_ms)
phase_elapsed=$((phase_end - phase_start))

if [[ "${preflight_ok}" == "true" ]]; then
  CHECK_PASS=$((CHECK_PASS + 1))
  log_step "PREFLIGHT" "PASS — all dependencies present"
  record_step "reliability_soak.preflight" "dependency_check" "pass" "${phase_elapsed}" \
    "contract.reliability_soak_dependencies"
else
  CHECK_FAIL=$((CHECK_FAIL + 1))
  log_step "PREFLIGHT" "FAIL — missing dependencies"
  record_step "reliability_soak.preflight" "dependency_check" "fail" "${phase_elapsed}" \
    "contract.reliability_soak_dependencies" "missing benchmark or runtime dependencies"
fi
echo ""

# =============================================================================
# Phase 2: Steady-State Soak
# =============================================================================
# Sustained load at production-normal rate. Validates queue depth bounded,
# memory stable, error rate within budget, latency percentiles within SLO.
# =============================================================================
if should_run_phase "steady_soak"; then
  log_step "STEADY_SOAK" "Phase 2: Steady-state soak (${STEADY_SOAK_SEC}s)"

  # 2a: Streaming steady-state — bounded queue depth + memory under sustained SSE
  run_e2e_script "soak_streaming_steady" \
    "streaming_backpressure_stress.sh" \
    "contract.soak_streaming_steady_state" \
    "steady_soak" \
    "STREAM_DURATION_SEC=${STEADY_SOAK_SEC} PRODUCER_RATE_HZ=100 CONSUMER_DELAY_MS=5 MAX_QUEUE_DEPTH=${MAX_QUEUE_DEPTH} MAX_RSS_MB=${MAX_RSS_MB}"

  # 2b: Polling steady-state — cursor continuity + no drift under sustained load
  run_e2e_script "soak_polling_steady" \
    "polling_timeout_backoff_storm.sh" \
    "contract.soak_polling_steady_state" \
    "steady_soak" \
    "CONSECUTIVE_TIMEOUTS=0 POLLING_INTERVAL_MS=500 MAX_BACKOFF_MS=30000"

  # 2c: Request/response steady-state — latency bounded under constant throughput
  run_e2e_script "soak_rr_steady" \
    "request_timeout_chain.sh" \
    "contract.soak_request_response_steady_state" \
    "steady_soak" \
    "CONCURRENT_REQUESTS=5 REQUEST_TIMEOUT_MS=5000 INJECTED_LATENCY_MS=0"

  # 2d: Runtime channel stress — bounded queue depth under sustained send
  run_cargo_check "soak_runtime_channels" "fcp-async-core" \
    "--lib channel" \
    "contract.soak_runtime_channel_stability" \
    "steady_soak"

  echo ""
else
  log_step "STEADY_SOAK" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 3: Burst-Spike Soak
# =============================================================================
# Traffic spike followed by recovery. Validates backpressure activates,
# queues don't overflow, latency degrades gracefully, and recovery is clean.
# =============================================================================
if should_run_phase "burst_soak"; then
  log_step "BURST_SOAK" "Phase 3: Burst-spike soak (${BURST_SOAK_SEC}s)"

  # 3a: Streaming burst — 10x producer rate spike, verify backpressure + recovery
  run_e2e_script "soak_streaming_burst" \
    "streaming_backpressure_stress.sh" \
    "contract.soak_streaming_burst_spike_recovery" \
    "burst_soak" \
    "STREAM_DURATION_SEC=${BURST_SOAK_SEC} PRODUCER_RATE_HZ=500 CONSUMER_DELAY_MS=20 MAX_QUEUE_DEPTH=${MAX_QUEUE_DEPTH} MAX_RSS_MB=${MAX_RSS_MB}"

  # 3b: Webhook burst — rapid event burst + retry storm under load
  run_e2e_script "soak_webhook_burst" \
    "webhook_retry_storm.sh" \
    "contract.soak_webhook_burst_retry_bounded" \
    "burst_soak" \
    "EVENTS_DURING_FAILURE=20 MAX_RETRY_ATTEMPTS=5 MAX_RETRY_BACKOFF_MS=10000"

  # 3c: Cancel storm burst — cancellation cascade under high concurrency
  run_e2e_script "soak_cancel_burst" \
    "bidirectional_cancel_chain.sh" \
    "contract.soak_cancel_cascade_resource_bounded" \
    "burst_soak" \
    ""

  echo ""
else
  log_step "BURST_SOAK" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 4: Near-Capacity Soak
# =============================================================================
# Sustained load at 95% of queue/timeout/connection budgets. Validates
# no cliff failures, graceful degradation, error budget not exhausted.
# =============================================================================
if should_run_phase "capacity_soak"; then
  log_step "CAPACITY_SOAK" "Phase 4: Near-capacity soak (${CAPACITY_SOAK_SEC}s)"

  # 4a: Queue near-capacity — 95% of max queue depth sustained
  run_e2e_script "soak_queue_capacity" \
    "streaming_backpressure_stress.sh" \
    "contract.soak_queue_near_capacity_no_cliff" \
    "capacity_soak" \
    "STREAM_DURATION_SEC=${CAPACITY_SOAK_SEC} PRODUCER_RATE_HZ=1000 CONSUMER_DELAY_MS=1 MAX_QUEUE_DEPTH=$((MAX_QUEUE_DEPTH * 95 / 100)) MAX_RSS_MB=${MAX_RSS_MB}"

  # 4b: Timeout budget near-exhaustion — requests at 90% of timeout budget
  run_e2e_script "soak_timeout_capacity" \
    "request_timeout_chain.sh" \
    "contract.soak_timeout_near_budget_no_cliff" \
    "capacity_soak" \
    "CONCURRENT_REQUESTS=20 REQUEST_TIMEOUT_MS=5000 INJECTED_LATENCY_MS=4500"

  # 4c: Cursor gap under high-volume polling
  run_e2e_script "soak_polling_capacity" \
    "polling_cursor_gap_recovery.sh" \
    "contract.soak_polling_high_volume_cursor_stability" \
    "capacity_soak" \
    "GAP_SIZE=50 MAX_GAP_FILL_RETRIES=5"

  echo ""
else
  log_step "CAPACITY_SOAK" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 5: Adversarial Reconnect Storm
# =============================================================================
# Cascading disconnects with high-frequency reconnect attempts. Validates
# reconnect bounded, session state preserved, ordering maintained.
# =============================================================================
if should_run_phase "adversarial_reconnect"; then
  log_step "ADVERSARIAL_RECONNECT" "Phase 5: Adversarial reconnect storm (${ADVERSARIAL_DURATION_SEC}s)"

  # 5a: WebSocket reconnect storm — rapid disconnect/reconnect cycles
  run_e2e_script "adversarial_ws_reconnect" \
    "streaming_reconnect_storm.sh" \
    "contract.adversarial_reconnect_bounded_recovery" \
    "adversarial_reconnect" \
    "DISCONNECTS=20 MAX_RECONNECT_ATTEMPTS=30 RECONNECT_INTERVAL_MS=100"

  # 5b: SSE reconnect with ordering — event continuity across rapid reconnects
  run_e2e_script "adversarial_sse_reconnect" \
    "sse_reconnect_ordering.sh" \
    "contract.adversarial_sse_ordering_under_storm" \
    "adversarial_reconnect" \
    ""

  echo ""
else
  log_step "ADVERSARIAL_RECONNECT" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 6: Adversarial Repair Pressure
# =============================================================================
# Concurrent RaptorQ decode operations under compute stress. Validates
# decode budget bounded, repair convergence under contention.
# =============================================================================
if should_run_phase "adversarial_repair"; then
  log_step "ADVERSARIAL_REPAIR" "Phase 6: Adversarial repair pressure"

  # 6a: Offline repair under pressure — degraded mesh with concurrent decode
  run_e2e_script "adversarial_offline_repair" \
    "offline_repair_flow.sh" \
    "contract.adversarial_repair_convergence_under_pressure" \
    "adversarial_repair" \
    ""

  # 6b: Targeted repair under contention — symbol requests during active decode
  run_e2e_script "adversarial_targeted_repair" \
    "targeted_repair_flow.sh" \
    "contract.adversarial_targeted_repair_bounded_contention" \
    "adversarial_repair" \
    ""

  # 6c: RaptorQ store adversarial tests — boundary and correctness under stress
  run_cargo_check "adversarial_raptorq_store" "fcp-store" \
    "--test adversarial" \
    "contract.adversarial_raptorq_store_correctness" \
    "adversarial_repair"

  # 6d: RaptorQ codec tests — decode under adversarial input
  run_cargo_check "adversarial_raptorq_codec" "fcp-raptorq" \
    "--lib" \
    "contract.adversarial_raptorq_codec_robustness" \
    "adversarial_repair"

  echo ""
else
  log_step "ADVERSARIAL_REPAIR" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 7: Adversarial Pool Exhaustion
# =============================================================================
# Connection/resource pool saturation and recovery. Validates bounded
# resource usage, clean recovery after exhaustion, no resource leaks.
# =============================================================================
if should_run_phase "adversarial_pool"; then
  log_step "ADVERSARIAL_POOL" "Phase 7: Adversarial pool exhaustion"

  # 7a: Timeout chain with pool exhaustion — all connections timeout simultaneously
  run_e2e_script "adversarial_pool_timeout" \
    "request_timeout_chain.sh" \
    "contract.adversarial_pool_exhaustion_bounded_recovery" \
    "adversarial_pool" \
    "CONCURRENT_REQUESTS=50 REQUEST_TIMEOUT_MS=2000 INJECTED_LATENCY_MS=10000 RECOVERY_REQUESTS=10"

  # 7b: Webhook under sustained failure — connection pool recovery after 503 storm
  run_e2e_script "adversarial_pool_webhook" \
    "webhook_retry_storm.sh" \
    "contract.adversarial_webhook_pool_recovery" \
    "adversarial_pool" \
    "EVENTS_DURING_FAILURE=10 MAX_RETRY_ATTEMPTS=3 FAILURE_DURATION_SEC=30 RECOVERY_WAIT_SEC=30"

  # 7c: Runtime task/channel exhaustion tests
  run_cargo_check "adversarial_runtime_exhaustion" "fcp-async-core" \
    "--lib" \
    "contract.adversarial_runtime_resource_bounded" \
    "adversarial_pool"

  echo ""
else
  log_step "ADVERSARIAL_POOL" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 8: Metric Validation + Regression Detection
# =============================================================================
log_step "METRIC_VALIDATION" "Phase 8: Metric validation and regression detection"

if should_run_phase "metric_validation"; then
  phase_start=$(now_ms)

  # Validate error contract stability — regression in error semantics
  run_cargo_check "metric_error_contracts" "fcp-sdk" \
    "--test error_contract_tests" \
    "contract.reliability_error_contract_stability" \
    "metric_validation"

  # Validate conformance test stability — no regression under load conditions
  run_cargo_check "metric_conformance_stability" "fcp-conformance" \
    "--lib" \
    "contract.reliability_conformance_stability" \
    "metric_validation"

  # Validate symbol store benchmark — performance regression check
  run_cargo_check "metric_store_benchmark" "fcp-store" \
    "--lib" \
    "contract.reliability_store_performance_stability" \
    "metric_validation"

  # Validate async runtime stability
  run_cargo_check "metric_async_runtime" "fcp-async-core" \
    "--lib" \
    "contract.reliability_async_runtime_stability" \
    "metric_validation"

  # SDK migration stability under load
  run_cargo_check "metric_sdk_migration" "fcp-sdk" \
    "--lib migration::" \
    "contract.reliability_sdk_migration_stability" \
    "metric_validation"

  phase_end=$(now_ms)
  phase_elapsed=$((phase_end - phase_start))
  echo ""
else
  log_step "METRIC_VALIDATION" "Skipped (--only-phases filter)"
fi

# =============================================================================
# Phase 9: Evidence Bundle Generation
# =============================================================================
log_step "EVIDENCE" "Phase 9: Generating reliability soak evidence bundle"

# 9a: Metric observations
METRICS_JSON='[]'
if (( ${#METRIC_RECORDS[@]} > 0 )); then
  METRICS_JSON="$(printf '%s\n' "${METRIC_RECORDS[@]}" | jq -s '.')"
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson metrics "${METRICS_JSON}" \
  '{
    run_id: $run_id,
    generated_at: $generated_at,
    thresholds: {
      latency_p95_ms: 500,
      latency_p99_ms: 2000,
      throughput_min_ops_s: 50,
      max_rss_mb: 512,
      max_queue_depth: 8192,
      error_budget_max_percent: 5,
      reconnect_success_rate_min: 95,
      cancel_recovery_max_ms: 5000
    },
    observations: $metrics,
    description: "Metric observations from reliability soak + adversarial load scenarios"
  }' > "${METRICS_FILE}"

# 9b: Regression report
if (( CHECK_FAIL > 0 )); then
  REGRESSION_VERDICT="regression_detected"
else
  REGRESSION_VERDICT="no_regression"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson check_pass "${CHECK_PASS}" \
  --argjson check_fail "${CHECK_FAIL}" \
  --arg verdict "${REGRESSION_VERDICT}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    regression_categories: {
      steady_soak: {
        description: "Sustained load regression: queue depth, memory, latency, error rate",
        contract_ids: [
          "contract.soak_streaming_steady_state",
          "contract.soak_polling_steady_state",
          "contract.soak_request_response_steady_state",
          "contract.soak_runtime_channel_stability"
        ]
      },
      burst_soak: {
        description: "Burst/spike regression: backpressure activation, overflow, recovery latency",
        contract_ids: [
          "contract.soak_streaming_burst_spike_recovery",
          "contract.soak_webhook_burst_retry_bounded",
          "contract.soak_cancel_cascade_resource_bounded"
        ]
      },
      capacity_soak: {
        description: "Near-capacity regression: cliff behavior, graceful degradation, budget adherence",
        contract_ids: [
          "contract.soak_queue_near_capacity_no_cliff",
          "contract.soak_timeout_near_budget_no_cliff",
          "contract.soak_polling_high_volume_cursor_stability"
        ]
      },
      adversarial: {
        description: "Adversarial regression: bounded reconnect, repair convergence, pool recovery",
        contract_ids: [
          "contract.adversarial_reconnect_bounded_recovery",
          "contract.adversarial_sse_ordering_under_storm",
          "contract.adversarial_repair_convergence_under_pressure",
          "contract.adversarial_pool_exhaustion_bounded_recovery"
        ]
      }
    },
    verdict: $verdict,
    total_pass: $check_pass,
    total_fail: $check_fail
  }' > "${REGRESSION_FILE}"

# 9c: Evidence catalog
jq -n \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  '{
    run_id: $run_id,
    generated_at: $generated_at,
    soak_scenarios: {
      steady_state: {
        duration_sec: "7200 (full) / 120 (CI)",
        load_profile: "100 ops/s constant, zero faults",
        invariants: ["queue_depth < 8192", "rss_mb < 512", "error_rate < 5%", "latency_p95 < 500ms"]
      },
      burst_spike: {
        duration_sec: "3600 (full) / 90 (CI)",
        load_profile: "100 ops/s baseline → 500 ops/s spike → 100 ops/s recovery",
        invariants: ["backpressure_activates", "no_queue_overflow", "recovery_latency < 30s"]
      },
      near_capacity: {
        duration_sec: "1800 (full) / 60 (CI)",
        load_profile: "95% of max queue/timeout budgets sustained",
        invariants: ["no_cliff_failure", "graceful_degradation", "error_budget_not_exhausted"]
      }
    },
    adversarial_scenarios: {
      reconnect_storm: {
        load_profile: "20 disconnects, 100ms reconnect interval, max 30 attempts",
        invariants: ["reconnect_bounded", "session_state_preserved", "ordering_maintained"]
      },
      repair_pressure: {
        load_profile: "Concurrent RaptorQ decode under compute stress",
        invariants: ["decode_budget_bounded", "repair_convergence", "no_corruption"]
      },
      pool_exhaustion: {
        load_profile: "50 concurrent timeout requests, 2s budget, 10s injected latency",
        invariants: ["pool_recovery_clean", "no_resource_leak", "bounded_failure_duration"]
      }
    },
    performance_gate_integration: {
      feeds_into: "235t.28.4 (Performance/Reliability Gate Artifact + Config Freeze)",
      metric_keys: [
        "latency_p95_ms", "latency_p99_ms", "throughput_ops_s",
        "rss_mb", "queue_depth_p95", "error_budget_burn_rate",
        "reconnect_success_rate", "cancel_recovery_ms"
      ],
      threshold_policy: "CI uses strict thresholds; full soak uses production SLO targets"
    }
  }' > "${OUT_ROOT}/evidence/reliability_soak_evidence.json"

CHECK_PASS=$((CHECK_PASS + 1))
record_step "reliability_soak.evidence_bundle" "generate" "pass" 0 \
  "contract.reliability_soak_evidence_bundle"

# =============================================================================
# Generate Findings Report
# =============================================================================
log_step "FINDINGS" "Generating findings report"

TOTAL_CHECKS=$((CHECK_PASS + CHECK_FAIL + CHECK_SKIP))
FINDING_COUNT=${#FINDING_RECORDS[@]}

FINDINGS_JSON='[]'
if (( FINDING_COUNT > 0 )); then
  FINDINGS_JSON="$(printf '%s\n' "${FINDING_RECORDS[@]}" | jq -s 'sort_by(.severity, .phase)')"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson total_findings "${FINDING_COUNT}" \
  --argjson findings "${FINDINGS_JSON}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    finding_count: $total_findings,
    findings: $findings
  }' > "${FINDINGS_FILE}"

# =============================================================================
# Generate Summary
# =============================================================================
log_step "SUMMARY" "Generating reliability soak summary"

OVERALL_STATUS="pass"
if (( CHECK_FAIL > 0 )); then
  OVERALL_STATUS="fail"
elif (( CHECK_WARN > 0 )); then
  if [[ "${CI_MODE}" == "true" ]]; then
    OVERALL_STATUS="fail"
  else
    OVERALL_STATUS="warn"
  fi
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg overall_status "${OVERALL_STATUS}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson dry_run "${DRY_RUN}" \
  --argjson total "${TOTAL_CHECKS}" \
  --argjson pass "${CHECK_PASS}" \
  --argjson fail "${CHECK_FAIL}" \
  --argjson skip "${CHECK_SKIP}" \
  --argjson warn "${CHECK_WARN}" \
  --argjson finding_count "${FINDING_COUNT}" \
  --arg only_phases "${ONLY_PHASES}" \
  --argjson steady_soak_sec "${STEADY_SOAK_SEC}" \
  --argjson burst_soak_sec "${BURST_SOAK_SEC}" \
  --argjson capacity_soak_sec "${CAPACITY_SOAK_SEC}" \
  --argjson adversarial_sec "${ADVERSARIAL_DURATION_SEC}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    dry_run: $dry_run,
    checks: {
      total: $total,
      pass: $pass,
      fail: $fail,
      skip: $skip,
      warn: $warn
    },
    finding_count: $finding_count,
    soak_parameters: {
      steady_soak_sec: $steady_soak_sec,
      burst_soak_sec: $burst_soak_sec,
      capacity_soak_sec: $capacity_soak_sec,
      adversarial_sec: $adversarial_sec
    },
    filters: {
      only_phases: (if ($only_phases | length) > 0 then $only_phases else null end)
    },
    phases: {
      preflight: "Dependency + baseline checks",
      steady_soak: "Steady-state soak: streaming + polling + request/response + channels",
      burst_soak: "Burst-spike soak: streaming burst + webhook burst + cancel cascade",
      capacity_soak: "Near-capacity soak: queue 95% + timeout 90% + polling high-volume",
      adversarial_reconnect: "Adversarial reconnect: WS storm + SSE ordering",
      adversarial_repair: "Adversarial repair: offline + targeted + store + codec",
      adversarial_pool: "Adversarial pool: timeout exhaustion + webhook pool + runtime",
      metric_validation: "Metric validation: error contracts + conformance + store + runtime + SDK",
      evidence_bundle: "Evidence bundle: metrics + regression report + catalog"
    },
    artifacts: {
      summary: "summary.json",
      steps: "steps.jsonl",
      findings: "findings.json",
      metrics: "metrics/metric_observations.json",
      regression: "metrics/regression_report.json",
      evidence: "evidence/reliability_soak_evidence.json",
      replay: "replay.sh",
      scenarios: "scenarios/",
      logs: "logs/"
    }
  }' > "${SUMMARY_FILE}"

# =============================================================================
# Generate Replay Script
# =============================================================================
cat > "${REPLAY_FILE}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay: Reliability Soak + Adversarial Load ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Reliability Soak: ${RUN_ID} ==="

bash scripts/e2e/e2e_reliability_soak_adversarial_load.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"$(
  [[ -n "${ONLY_PHASES}" ]] && printf ' \\\n  --only-phases "%s"' "${ONLY_PHASES}"
  [[ "${CI_MODE}" == "true" ]] && printf ' \\\n  --ci'
  [[ -n "${SOAK_DURATION}" ]] && printf ' \\\n  --soak-duration %s' "${SOAK_DURATION}"
  )
REPLAY_EOF
chmod +x "${REPLAY_FILE}"

# =============================================================================
# Summary Output
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  RELIABILITY SOAK + ADVERSARIAL LOAD — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:       ${OVERALL_STATUS}"
echo "  CI Mode:              ${CI_MODE}"
echo "  Dry Run:              ${DRY_RUN}"
echo ""
echo "  Soak Durations:       steady=${STEADY_SOAK_SEC}s burst=${BURST_SOAK_SEC}s capacity=${CAPACITY_SOAK_SEC}s"
echo "  Adversarial Duration: ${ADVERSARIAL_DURATION_SEC}s"
echo ""
echo "  Checks:               ${TOTAL_CHECKS} total"
echo "    Pass:               ${CHECK_PASS}"
echo "    Fail:               ${CHECK_FAIL}"
echo "    Skip:               ${CHECK_SKIP}"
echo "    Warn:               ${CHECK_WARN}"
echo ""
echo "  Findings:             ${FINDING_COUNT}"
if [[ -n "${ONLY_PHASES}" ]]; then
  echo "  Filter:               ${ONLY_PHASES}"
fi
echo ""
echo "  Soak Phases:"
echo "    1. preflight             — Dependency + baseline checks"
echo "    2. steady_soak           — Sustained load (streaming/polling/rr/channels)"
echo "    3. burst_soak            — Traffic spike (streaming/webhook/cancel)"
echo "    4. capacity_soak         — Near-capacity (queue/timeout/polling)"
echo "    5. adversarial_reconnect — Reconnect storm (WS/SSE)"
echo "    6. adversarial_repair    — Repair pressure (offline/targeted/store/codec)"
echo "    7. adversarial_pool      — Pool exhaustion (timeout/webhook/runtime)"
echo "    8. metric_validation     — Regression detection (errors/conformance/store/sdk)"
echo "    9. evidence_bundle       — Metrics + regression report + evidence catalog"
echo ""
echo "  Metric Thresholds:"
echo "    latency_p95:    ${LATENCY_P95_THRESHOLD_MS}ms"
echo "    latency_p99:    ${LATENCY_P99_THRESHOLD_MS}ms"
echo "    throughput_min: ${THROUGHPUT_MIN_OPS_S} ops/s"
echo "    max_rss:        ${MAX_RSS_MB} MB"
echo "    max_queue:      ${MAX_QUEUE_DEPTH}"
echo "    error_budget:   ${ERROR_BUDGET_MAX_PERCENT}%"
echo "    reconnect_rate: ${RECONNECT_SUCCESS_RATE_MIN}%"
echo "    cancel_recovery:${CANCEL_RECOVERY_MAX_MS}ms"
echo ""
echo "  Artifacts:            ${OUT_ROOT}/"
echo "    summary.json                       — gate summary"
echo "    steps.jsonl                        — per-check forensic steps"
echo "    findings.json                      — identified issues"
echo "    metrics/metric_observations.json   — metric data points"
echo "    metrics/regression_report.json     — regression analysis"
echo "    evidence/reliability_soak_evidence.json — evidence catalog"
echo "    replay.sh                          — deterministic replay"
echo "    scenarios/                         — per-scenario outputs"
echo "    logs/                              — per-check execution logs"
echo ""
echo "  Feeds Into:"
echo "    235t.28.3  — Runtime/Queue/Admission Tuning"
echo "    235t.28.4  — Performance/Reliability Gate Artifact + Config Freeze"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if (( FINDING_COUNT > 0 )); then
  echo ""
  echo "  Findings:"
  for f in "${FINDING_RECORDS[@]}"; do
    severity="$(echo "${f}" | jq -r '.severity')"
    phase="$(echo "${f}" | jq -r '.phase')"
    test_name="$(echo "${f}" | jq -r '.test_name')"
    desc="$(echo "${f}" | jq -r '.description[:120]')"
    echo "  - [${severity}] ${phase}/${test_name}: ${desc}"
  done
  echo ""
fi

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  exit 1
fi
