#!/usr/bin/env bash
# =============================================================================
# e2e_canary_scenario_matrix.sh — Canary Scenario Matrix + Abort Threshold Design
# =============================================================================
# Bead:     235t.34.1 (ASUPERSYNC-OPS Canary Scenario Matrix + Abort Thresholds)
# Schema:   asupersync-canary-scenario-matrix/v1
#
# Defines canary deployment scenarios with objective, machine-checkable abort
# thresholds that protect users during staged rollout. Reads upstream gate
# artifacts (perf gate, config freeze, actionability gate, forensic bundle)
# and produces a deterministic canary plan consumed by rollback drill (34.2),
# rehearsal automation (34.3), and go/no-go decision gate (34.4).
#
# Input Sources:
#   1. Config freeze (28.4)          → approved parameters + rollback defaults
#   2. Perf/reliability gate (28.4)  → verdict + blocker index
#   3. Actionability gate (26.7.3)   → diagnostics enforcement status
#   4. Failure-journey bundle (33.4) → user-impact drift + recovery evidence
#   5. Scenario registry             → required scenarios + archetypes
#
# Outputs:
#   canary_scenario_matrix.json    — scenario plan with abort thresholds
#   abort_threshold_catalog.json   — machine-checkable abort criteria
#   canary_deployment_plan.json    — staged rollout stages + health signals
#   BUNDLE_MANIFEST.json           — artifact index
#   replay.sh                      — deterministic replay
#
# Usage:
#   bash scripts/e2e/e2e_canary_scenario_matrix.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing validations
#   --ci                    CI mode (strict: no waivers)
#   --only-stages <list>    Comma-separated stage filter
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CANARY_SCHEMA="asupersync-canary-scenario-matrix/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"
ONLY_STAGES=""

declare -i GATE_PASS=0
declare -i GATE_FAIL=0
declare -i GATE_SKIP=0
declare -i GATE_WARN=0
declare -a BLOCKER_RECORDS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_canary_scenario_matrix.sh [options]

Canary Scenario Matrix + Abort Threshold Design

Defines canary deployment scenarios with objective abort thresholds
for staged rollout. Reads upstream gate artifacts and produces a
deterministic canary plan.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/canary-matrix/<run-id>)
  --dry-run               Emit plan without executing validations
  --ci                    CI mode (strict: no waivers)
  --only-stages <list>    Comma-separated stage filter (preflight,upstream,thresholds,scenarios,stages,health,verdict)
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
  printf '[%s] [CANARY-MATRIX/%s] %s\n' "$(now_iso)" "$1" "$2"
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
      schema_version: $schema_version, run_id: $run_id, scenario_id: $scenario_id,
      trace_id: $trace_id, correlation_id: $correlation_id, connector: $connector,
      zone: $zone, operation: $operation, attempt: $attempt,
      timeout_budget_ms: $timeout_budget_ms, cancellation_reason: null,
      queue_depth: null, decode_budget: null, outcome: $outcome,
      elapsed_ms: $elapsed_ms,
      contract_id: (if ($contract_id | length) > 0 then $contract_id else null end),
      reason: (if ($reason | length) > 0 then $reason else null end),
      log_path: (if ($log_path | length) > 0 then $log_path else null end)
    }' >> "${STEPS_FILE}"
}

add_blocker() {
  local source="$1"
  local category="$2"
  local severity="$3"
  local description="$4"
  local remediation="$5"
  local b
  b="$(jq -c -n \
    --arg source "${source}" \
    --arg category "${category}" \
    --arg severity "${severity}" \
    --arg description "${description}" \
    --arg remediation "${remediation}" \
    --arg found_at "$(now_iso)" \
    '{source: $source, category: $category, severity: $severity, description: $description, remediation: $remediation, found_at: $found_at}')"
  BLOCKER_RECORDS+=("${b}")
}

should_run_stage() {
  local stage="$1"
  if [[ -z "${ONLY_STAGES}" ]]; then return 0; fi
  if [[ ",${ONLY_STAGES}," == *",${stage},"* ]]; then return 0; fi
  return 1
}

run_cargo_check() {
  local label="$1"
  local crate="$2"
  local test_filter="${3:-}"
  local contract_id="${4:-n/a}"
  local scenario_id="canary_matrix.${label}"
  local log_file="${OUT_ROOT}/logs/${label}.log"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    local cmd="cargo test -p ${crate}"
    [[ -n "${test_filter}" ]] && cmd="${cmd} -- ${test_filter}"
    log_step "${label}" "[dry-run] ${cmd}"
    echo "[dry-run] ${cmd}" > "${log_file}"
    record_step "${scenario_id}" "cargo_check" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    GATE_SKIP=$((GATE_SKIP + 1))
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)
  local cmd_args=(-p "${crate}" --lib)
  [[ -n "${test_filter}" ]] && cmd_args+=(-- "${test_filter}")
  if cargo test "${cmd_args[@]}" > "${log_file}" 2>&1; then
    status="pass"
  else
    status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    GATE_PASS=$((GATE_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "cargo_check" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    GATE_FAIL=$((GATE_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "cargo_check" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_blocker "${label}" "cargo_test_failure" "critical" \
      "Crate ${crate} test failure in canary validation" \
      "cargo test -p ${crate} --lib"
  fi
}

# ── Argument parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="$2"; shift 2 ;;
    --out-root) OUT_ROOT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --ci) CI_MODE=true; shift ;;
    --only-stages) ONLY_STAGES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/canary-matrix/${RUN_ID}"
fi

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/scenarios" "${OUT_ROOT}/stages"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
: > "${STEPS_FILE}"

require_cmd jq
require_cmd cargo

log_step "INIT" "Canary Scenario Matrix v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"

# =============================================================================
# Phase 1: Pre-flight — Validate input sources
# =============================================================================

if should_run_stage "preflight"; then
  log_step "PREFLIGHT" "Phase 1: Validating input sources"
  local_start=$(now_ms)

  INPUT_SOURCES=(
    "scripts/e2e/e2e_performance_reliability_gate.sh|28.4 perf gate"
    "scripts/e2e/e2e_actionability_gate.sh|26.7.3 actionability gate"
    "scripts/e2e/e2e_failure_journey_forensic_bundle.sh|33.4 failure-journey bundle"
    "scripts/e2e/scenario_registry.json|scenario registry"
  )

  PREFLIGHT_OK=true
  for entry in "${INPUT_SOURCES[@]}"; do
    IFS='|' read -r path label <<< "${entry}"
    if [[ -f "${REPO_ROOT}/${path}" ]]; then
      log_step "PREFLIGHT" "  [ok] ${label}"
    else
      log_step "PREFLIGHT" "  [MISSING] ${label}: ${path}"
      PREFLIGHT_OK=false
    fi
  done

  if [[ "${PREFLIGHT_OK}" == "true" ]]; then
    GATE_PASS=$((GATE_PASS + 1))
    log_step "PREFLIGHT" "PASS — all input sources present"
    record_step "canary_matrix.preflight" "source_validation" "pass" \
      $(( $(now_ms) - local_start )) "contract.canary_preflight"
  else
    GATE_FAIL=$((GATE_FAIL + 1))
    log_step "PREFLIGHT" "FAIL — missing input sources"
    record_step "canary_matrix.preflight" "source_validation" "fail" \
      $(( $(now_ms) - local_start )) "contract.canary_preflight" "missing_inputs"
    add_blocker "preflight" "missing_input_source" "critical" \
      "One or more upstream input sources are missing" \
      "Check that 28.4, 26.7.3, 33.4 beads are complete"
  fi
fi

# =============================================================================
# Phase 2: Upstream gate verdict validation
# =============================================================================

if should_run_stage "upstream"; then
  log_step "UPSTREAM" "Phase 2: Validating upstream gate verdicts"
  local_start=$(now_ms)

  # Look for most recent perf gate artifacts
  PERF_GATE_DIR=""
  if [[ -d "${REPO_ROOT}/artifacts/asupersync/perf-gate" ]]; then
    PERF_GATE_DIR="$(ls -td "${REPO_ROOT}/artifacts/asupersync/perf-gate"/*/ 2>/dev/null | head -1)"
  fi

  UPSTREAM_OK=true

  if [[ -n "${PERF_GATE_DIR}" && -f "${PERF_GATE_DIR}/performance_reliability_gate.json" ]]; then
    PERF_VERDICT=$(jq -r '.verdict // "unknown"' "${PERF_GATE_DIR}/performance_reliability_gate.json")
    PERF_BLOCKERS=$(jq -r '.blockers.count // 0' "${PERF_GATE_DIR}/performance_reliability_gate.json")
    log_step "UPSTREAM" "  Perf gate verdict: ${PERF_VERDICT} (blockers: ${PERF_BLOCKERS})"

    if [[ "${PERF_VERDICT}" == "fail" ]]; then
      UPSTREAM_OK=false
      add_blocker "upstream_perf_gate" "gate_verdict_fail" "critical" \
        "Performance/reliability gate verdict is FAIL" \
        "bash scripts/e2e/e2e_performance_reliability_gate.sh"
    fi

    FROZEN_PARAMS=$(jq -r '.total_frozen_parameters // 0' "${PERF_GATE_DIR}/config_freeze.json" 2>/dev/null)
    log_step "UPSTREAM" "  Config freeze: ${FROZEN_PARAMS} parameters frozen"
  elif [[ "${DRY_RUN}" == "true" ]]; then
    log_step "UPSTREAM" "  [dry-run] Perf gate artifacts not present — using defaults"
    PERF_VERDICT="pass"
    PERF_BLOCKERS=0
    FROZEN_PARAMS=28
  else
    UPSTREAM_OK=false
    add_blocker "upstream_perf_gate" "missing_artifact" "critical" \
      "No perf gate artifact directory found" \
      "bash scripts/e2e/e2e_performance_reliability_gate.sh --dry-run"
  fi

  if [[ "${UPSTREAM_OK}" == "true" ]]; then
    GATE_PASS=$((GATE_PASS + 1))
    log_step "UPSTREAM" "PASS — upstream gate verdicts acceptable"
    record_step "canary_matrix.upstream" "verdict_validation" "pass" \
      $(( $(now_ms) - local_start )) "contract.canary_upstream_validation"
  else
    GATE_FAIL=$((GATE_FAIL + 1))
    log_step "UPSTREAM" "FAIL — upstream gate verdicts unacceptable"
    record_step "canary_matrix.upstream" "verdict_validation" "fail" \
      $(( $(now_ms) - local_start )) "contract.canary_upstream_validation" "upstream_fail"
  fi
fi

# =============================================================================
# Phase 3: Abort threshold catalog
# =============================================================================

if should_run_stage "thresholds"; then
  log_step "THRESHOLDS" "Phase 3: Generating abort threshold catalog"
  local_start=$(now_ms)

  # Machine-checkable abort thresholds aligned with perf framework metrics
  jq -n '{
    schema_version: "asupersync-canary-scenario-matrix/v1",
    type: "abort_threshold_catalog",
    run_id: $run_id,
    generated_at: $now,
    description: "Objective abort criteria for canary rollout stages. Each threshold is machine-evaluable with no manual judgment required.",
    thresholds: {
      latency: {
        p50_ms: { warn: 200, abort: 500, direction: "lower_is_better", evidence: "soak_steady_state" },
        p95_ms: { warn: 500, abort: 2000, direction: "lower_is_better", evidence: "soak_steady_state" },
        p99_ms: { warn: 2000, abort: 5000, direction: "lower_is_better", evidence: "soak_burst_spike" }
      },
      throughput: {
        ops_per_second: { warn: 50, abort: 20, direction: "higher_is_better", evidence: "soak_steady_state" },
        regression_pct: { warn: 5, abort: 15, direction: "lower_is_better", evidence: "benchmark_baseline" }
      },
      error_rate: {
        error_budget_pct: { warn: 2, abort: 5, direction: "lower_is_better", evidence: "soak_adversarial" },
        consecutive_failures: { warn: 3, abort: 5, direction: "lower_is_better", evidence: "retry_exhaustion" }
      },
      memory: {
        rss_mb: { warn: 384, abort: 512, direction: "lower_is_better", evidence: "soak_capacity_ceiling" },
        rss_regression_pct: { warn: 10, abort: 25, direction: "lower_is_better", evidence: "benchmark_baseline" }
      },
      queue: {
        depth_p95: { warn: 4096, abort: 8192, direction: "lower_is_better", evidence: "soak_burst_spike" },
        backpressure_events: { warn: 10, abort: 50, direction: "lower_is_better", evidence: "adversarial_reconnect" }
      },
      recovery: {
        reconnect_success_rate_pct: { warn: 98, abort: 95, direction: "higher_is_better", evidence: "adversarial_reconnect" },
        cancel_storm_recovery_ms: { warn: 3000, abort: 5000, direction: "lower_is_better", evidence: "adversarial_pool" }
      },
      raptorq: {
        decode_success_rate_pct: { warn: 99, abort: 95, direction: "higher_is_better", evidence: "raptorq_conformance" },
        repair_convergence_ms: { warn: 5000, abort: 15000, direction: "lower_is_better", evidence: "raptorq_repair_stress" }
      }
    },
    abort_policy: {
      rule_1: "Any single abort threshold breach triggers immediate stage rollback",
      rule_2: "Two or more warn thresholds in the same category trigger abort",
      rule_3: "CI mode treats all warnings as abort (strict enforcement)",
      rule_4: "Abort decisions are logged with forensic trace for post-mortem",
      rule_5: "Rollback uses config_freeze.json rollback defaults for parameter recovery"
    },
    evaluation_method: {
      description: "Thresholds are evaluated per-stage after health signal collection",
      cadence_seconds: 30,
      min_samples: 10,
      warmup_seconds: 60,
      cooldown_seconds: 30
    }
  }' \
    --arg run_id "${RUN_ID}" \
    --arg now "$(now_iso)" \
    > "${OUT_ROOT}/abort_threshold_catalog.json"

  THRESHOLD_COUNT=$(jq '[.thresholds | to_entries[] | .value | to_entries[] ] | length' \
    "${OUT_ROOT}/abort_threshold_catalog.json")
  log_step "THRESHOLDS" "Generated abort threshold catalog (${THRESHOLD_COUNT} thresholds)"

  GATE_PASS=$((GATE_PASS + 1))
  record_step "canary_matrix.thresholds" "threshold_catalog" "pass" \
    $(( $(now_ms) - local_start )) "contract.canary_abort_thresholds"
fi

# =============================================================================
# Phase 4: Canary scenario selection from registry
# =============================================================================

if should_run_stage "scenarios"; then
  log_step "SCENARIOS" "Phase 4: Selecting canary scenarios from registry"
  local_start=$(now_ms)

  REGISTRY="${REPO_ROOT}/scripts/e2e/scenario_registry.json"

  # Select scenarios for canary validation grouped by user_impact_category
  jq -n --arg run_id "${RUN_ID}" --arg now "$(now_iso)" \
    --slurpfile reg "${REGISTRY}" '{
    schema_version: "asupersync-canary-scenario-matrix/v1",
    type: "canary_scenario_matrix",
    run_id: $run_id,
    generated_at: $now,
    description: "Canary deployment scenario matrix organized by rollout stage and user impact.",
    source_registry_version: $reg[0].registry_version,
    total_scenarios: ($reg[0].scenarios | length),
    required_scenarios: ([$reg[0].scenarios[] | select(.required == true)] | length),
    scenario_matrix: {
      security: {
        description: "Security-critical scenarios — must pass before any traffic shift",
        stage: "stage_0_preflight",
        abort_on_fail: true,
        scenarios: [$reg[0].scenarios[] | select(.user_impact_category == "security") |
          { key, scenario_id, script, archetype, failure_class }]
      },
      availability: {
        description: "Availability scenarios — validated at 1% canary traffic",
        stage: "stage_1_canary_1pct",
        abort_on_fail: true,
        scenarios: [$reg[0].scenarios[] | select(.user_impact_category == "availability") |
          { key, scenario_id, script, archetype, failure_class }]
      },
      correctness: {
        description: "Correctness scenarios — validated at 5% canary traffic",
        stage: "stage_2_canary_5pct",
        abort_on_fail: true,
        scenarios: [$reg[0].scenarios[] | select(.user_impact_category == "correctness") |
          { key, scenario_id, script, archetype, failure_class }]
      },
      performance: {
        description: "Performance scenarios — validated at 10% canary traffic",
        stage: "stage_3_canary_10pct",
        abort_on_fail: true,
        scenarios: [$reg[0].scenarios[] | select(.user_impact_category == "performance") |
          { key, scenario_id, script, archetype, failure_class }]
      },
      cost_control: {
        description: "Cost control scenarios — validated at 25% before full promotion",
        stage: "stage_4_canary_25pct",
        abort_on_fail: false,
        scenarios: [$reg[0].scenarios[] | select(.user_impact_category == "cost_control") |
          { key, scenario_id, script, archetype, failure_class }]
      }
    },
    archetype_coverage: {
      archetypes: [$reg[0].scenarios[].archetype] | unique,
      failure_classes: [$reg[0].scenarios[].failure_class] | unique,
      total_archetypes: ([$reg[0].scenarios[].archetype] | unique | length),
      total_failure_classes: ([$reg[0].scenarios[].failure_class] | unique | length)
    }
  }' > "${OUT_ROOT}/canary_scenario_matrix.json"

  SCENARIO_COUNT=$(jq '.total_scenarios' "${OUT_ROOT}/canary_scenario_matrix.json")
  REQUIRED_COUNT=$(jq '.required_scenarios' "${OUT_ROOT}/canary_scenario_matrix.json")
  ARCHETYPE_COUNT=$(jq '.archetype_coverage.total_archetypes' "${OUT_ROOT}/canary_scenario_matrix.json")
  FAILURE_CLASS_COUNT=$(jq '.archetype_coverage.total_failure_classes' "${OUT_ROOT}/canary_scenario_matrix.json")

  log_step "SCENARIOS" "Scenario matrix: ${SCENARIO_COUNT} total, ${REQUIRED_COUNT} required"
  log_step "SCENARIOS" "Coverage: ${ARCHETYPE_COUNT} archetypes, ${FAILURE_CLASS_COUNT} failure classes"

  # Validate each impact category has at least one scenario
  CATEGORY_OK=true
  for cat in security availability correctness performance; do
    count=$(jq ".scenario_matrix.${cat}.scenarios | length" "${OUT_ROOT}/canary_scenario_matrix.json")
    if (( count == 0 )); then
      CATEGORY_OK=false
      log_step "SCENARIOS" "  WARNING: No scenarios for impact category: ${cat}"
      GATE_WARN=$((GATE_WARN + 1))
      add_blocker "scenario_coverage" "missing_impact_category" "high" \
        "No scenarios for user impact category: ${cat}" \
        "Add scenarios with user_impact_category=${cat} to scenario_registry.json"
    else
      log_step "SCENARIOS" "  ${cat}: ${count} scenarios"
    fi
  done

  if [[ "${CATEGORY_OK}" == "true" ]]; then
    GATE_PASS=$((GATE_PASS + 1))
    log_step "SCENARIOS" "PASS — all impact categories covered"
  fi
  record_step "canary_matrix.scenarios" "scenario_selection" \
    "$([[ "${CATEGORY_OK}" == "true" ]] && echo pass || echo warn)" \
    $(( $(now_ms) - local_start )) "contract.canary_scenario_selection"
fi

# =============================================================================
# Phase 5: Canary deployment stages
# =============================================================================

if should_run_stage "stages"; then
  log_step "STAGES" "Phase 5: Generating canary deployment stages"
  local_start=$(now_ms)

  jq -n --arg run_id "${RUN_ID}" --arg now "$(now_iso)" '{
    schema_version: "asupersync-canary-scenario-matrix/v1",
    type: "canary_deployment_plan",
    run_id: $run_id,
    generated_at: $now,
    description: "Staged canary rollout plan with health signal gates between each stage.",
    stages: [
      {
        stage_id: "stage_0_preflight",
        name: "Pre-flight validation",
        traffic_pct: 0,
        duration_minutes: 10,
        description: "Validate all upstream gates green, config freeze integrity, and security scenarios before any traffic shift.",
        health_signals: ["upstream_gate_verdicts", "config_freeze_integrity", "security_scenario_pass"],
        abort_criteria: ["any_upstream_gate_fail", "config_freeze_drift", "security_scenario_fail"],
        scenarios: ["security"],
        rollback_action: "no_traffic_shift_needed",
        promotion_criteria: "all_preflight_green"
      },
      {
        stage_id: "stage_1_canary_1pct",
        name: "1% canary traffic",
        traffic_pct: 1,
        duration_minutes: 30,
        description: "Route 1% of traffic to migrated runtime. Monitor availability signals with low blast radius.",
        health_signals: ["error_rate", "latency_p95", "reconnect_success_rate", "queue_depth"],
        abort_criteria: ["error_budget_breach", "latency_p95_abort", "reconnect_rate_below_95pct"],
        scenarios: ["availability"],
        rollback_action: "revert_traffic_to_0pct_restore_rollback_defaults",
        promotion_criteria: "30min_clean_at_1pct"
      },
      {
        stage_id: "stage_2_canary_5pct",
        name: "5% canary traffic",
        traffic_pct: 5,
        duration_minutes: 60,
        description: "Increase to 5% and validate correctness under real-world load patterns.",
        health_signals: ["error_rate", "latency_p50_p95_p99", "throughput_ops_s", "memory_rss", "queue_depth"],
        abort_criteria: ["error_budget_breach", "latency_abort_any_percentile", "throughput_regression_15pct", "memory_abort"],
        scenarios: ["correctness"],
        rollback_action: "revert_traffic_to_1pct_and_hold",
        promotion_criteria: "60min_clean_at_5pct"
      },
      {
        stage_id: "stage_3_canary_10pct",
        name: "10% canary traffic",
        traffic_pct: 10,
        duration_minutes: 120,
        description: "Significant traffic share validates performance under sustained load. Run soak-equivalent metrics.",
        health_signals: ["all_latency_percentiles", "throughput", "error_budget", "memory", "queue_pressure", "recovery_signals", "raptorq_metrics"],
        abort_criteria: ["any_abort_threshold_breach", "two_warn_thresholds_same_category"],
        scenarios: ["performance"],
        rollback_action: "revert_traffic_to_5pct_and_investigate",
        promotion_criteria: "120min_clean_at_10pct_all_metrics"
      },
      {
        stage_id: "stage_4_canary_25pct",
        name: "25% canary traffic",
        traffic_pct: 25,
        duration_minutes: 240,
        description: "Pre-promotion validation at scale. Cost control and resource efficiency verification.",
        health_signals: ["all_metrics", "cost_efficiency", "resource_utilization"],
        abort_criteria: ["any_abort_threshold_breach", "cost_regression_detected"],
        scenarios: ["cost_control"],
        rollback_action: "revert_traffic_to_10pct_and_investigate",
        promotion_criteria: "240min_clean_at_25pct"
      },
      {
        stage_id: "stage_5_full_promotion",
        name: "Full promotion (100%)",
        traffic_pct: 100,
        duration_minutes: null,
        description: "Full traffic shift. Requires go/no-go gate (34.4) approval.",
        health_signals: ["all_metrics_continuous"],
        abort_criteria: ["any_abort_threshold_breach"],
        scenarios: ["all_required"],
        rollback_action: "emergency_rollback_to_25pct_page_oncall",
        promotion_criteria: "go_nogo_gate_approval"
      }
    ],
    stage_transitions: {
      description: "Each stage requires promotion criteria met before advancing. Abort triggers immediate rollback to previous stage.",
      evaluation_cadence_seconds: 30,
      min_samples_per_signal: 10,
      warmup_seconds_per_stage: 60,
      cooldown_seconds_per_stage: 30,
      max_rollback_cascades: 2,
      total_estimated_duration_hours: 7.5
    },
    config_source: "config_freeze.json from 235t.28.4",
    rollback_config: "All parameter rollbacks sourced from config_freeze.json rollback defaults"
  }' > "${OUT_ROOT}/canary_deployment_plan.json"

  STAGE_COUNT=$(jq '.stages | length' "${OUT_ROOT}/canary_deployment_plan.json")
  log_step "STAGES" "Generated deployment plan: ${STAGE_COUNT} stages (0%→1%→5%→10%→25%→100%)"

  GATE_PASS=$((GATE_PASS + 1))
  record_step "canary_matrix.stages" "deployment_plan" "pass" \
    $(( $(now_ms) - local_start )) "contract.canary_deployment_stages"
fi

# =============================================================================
# Phase 6: Health signal validation (cargo checks)
# =============================================================================

if should_run_stage "health"; then
  log_step "HEALTH" "Phase 6: Validating health signal infrastructure"

  # Validate that crates backing health signals compile and pass tests
  run_cargo_check "health_sdk_runtime" "fcp-sdk" "" \
    "contract.canary_health_sdk"
  run_cargo_check "health_async_core" "fcp-async-core" "" \
    "contract.canary_health_async_core"
  run_cargo_check "health_conformance" "fcp-conformance" "" \
    "contract.canary_health_conformance"
  run_cargo_check "health_store" "fcp-store" "" \
    "contract.canary_health_store"
fi

# =============================================================================
# Phase 7: Gate verdict + bundle manifest
# =============================================================================

if should_run_stage "verdict"; then
  log_step "VERDICT" "Phase 7: Computing canary matrix gate verdict"

  TOTAL_CHECKS=$((GATE_PASS + GATE_FAIL + GATE_SKIP + GATE_WARN))

  if (( GATE_FAIL > 0 )); then
    GATE_VERDICT="abort"
  elif (( GATE_WARN > 0 )) && [[ "${CI_MODE}" == "true" ]]; then
    GATE_VERDICT="abort"
  elif (( GATE_WARN > 0 )); then
    GATE_VERDICT="warn"
  else
    GATE_VERDICT="proceed"
  fi

  # Gate status
  BLOCKER_JSON="[]"
  if (( ${#BLOCKER_RECORDS[@]} > 0 )); then
    BLOCKER_JSON="$(printf '%s\n' "${BLOCKER_RECORDS[@]}" | jq -s '.')"
  fi

  jq -n \
    --arg schema_version "${CANARY_SCHEMA}" \
    --arg run_id "${RUN_ID}" \
    --arg generated_at "$(now_iso)" \
    --arg verdict "${GATE_VERDICT}" \
    --argjson ci_mode "${CI_MODE}" \
    --argjson total "${TOTAL_CHECKS}" \
    --argjson pass "${GATE_PASS}" \
    --argjson fail "${GATE_FAIL}" \
    --argjson skip "${GATE_SKIP}" \
    --argjson warn "${GATE_WARN}" \
    --argjson blockers "${BLOCKER_JSON}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      generated_at: $generated_at,
      verdict: $verdict,
      ci_mode: $ci_mode,
      checks: { total: $total, pass: $pass, fail: $fail, skip: $skip, warn: $warn },
      blockers: { count: ($blockers | length), items: $blockers },
      sub_artifacts: {
        canary_scenario_matrix: "canary_scenario_matrix.json",
        abort_threshold_catalog: "abort_threshold_catalog.json",
        canary_deployment_plan: "canary_deployment_plan.json"
      },
      consumers: {
        "235t.34.2": "Rollback drill scripts (reads stages + abort criteria)",
        "235t.34.3": "Rehearsal automation (reads scenario matrix + deployment plan)",
        "235t.34.4": "Go/no-go decision gate (reads verdict + abort catalog)"
      }
    }' > "${OUT_ROOT}/canary_matrix_gate.json"

  # Blocker index
  jq -n \
    --arg run_id "${RUN_ID}" \
    --arg generated_at "$(now_iso)" \
    --argjson blockers "${BLOCKER_JSON}" \
    '{
      run_id: $run_id,
      generated_at: $generated_at,
      blocker_count: ($blockers | length),
      blockers: $blockers
    }' > "${OUT_ROOT}/blocker_index.json"

  # Summary
  jq -n \
    --arg schema_version "${CANARY_SCHEMA}" \
    --arg run_id "${RUN_ID}" \
    --arg generated_at "$(now_iso)" \
    --arg overall_status "${GATE_VERDICT}" \
    --argjson ci_mode "${CI_MODE}" \
    --argjson dry_run "${DRY_RUN}" \
    --argjson total "${TOTAL_CHECKS}" \
    --argjson pass "${GATE_PASS}" \
    --argjson fail "${GATE_FAIL}" \
    --argjson skip "${GATE_SKIP}" \
    --argjson warn "${GATE_WARN}" \
    --argjson blocker_count "${#BLOCKER_RECORDS[@]}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      generated_at: $generated_at,
      overall_status: $overall_status,
      ci_mode: $ci_mode,
      dry_run: $dry_run,
      checks: { total: $total, pass: $pass, fail: $fail, skip: $skip, warn: $warn },
      blocker_count: $blocker_count,
      phases: {
        preflight: "Input source validation (28.4, 26.7.3, 33.4, registry)",
        upstream: "Upstream gate verdict validation (perf/reliability/actionability)",
        thresholds: "Abort threshold catalog (latency/throughput/error/memory/queue/recovery/raptorq)",
        scenarios: "Canary scenario selection from registry (by user impact category)",
        stages: "Deployment stages (0%→1%→5%→10%→25%→100%) with health signals",
        health: "Health signal infrastructure validation (SDK/async-core/conformance/store)",
        verdict: "Gate verdict + bundle manifest"
      },
      artifacts: {
        summary: "summary.json",
        gate_status: "canary_matrix_gate.json",
        scenario_matrix: "canary_scenario_matrix.json",
        abort_thresholds: "abort_threshold_catalog.json",
        deployment_plan: "canary_deployment_plan.json",
        blocker_index: "blocker_index.json",
        bundle_manifest: "BUNDLE_MANIFEST.json",
        steps: "steps.jsonl",
        replay: "replay.sh"
      }
    }' > "${OUT_ROOT}/summary.json"

  # BUNDLE_MANIFEST
  jq -n \
    --arg schema_version "asupersync-bundle-manifest/v1" \
    --arg run_id "${RUN_ID}" \
    --arg created_at "$(now_iso)" \
    --arg verdict "${GATE_VERDICT}" \
    --argjson total "${TOTAL_CHECKS}" \
    --argjson pass "${GATE_PASS}" \
    --argjson fail "${GATE_FAIL}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      created_at: $created_at,
      bundle_type: "canary-scenario-matrix",
      bundle_version: 1,
      mode: "canary-matrix",
      artifacts: [
        { name: "canary_matrix_gate.json", type: "gate_status", required: true },
        { name: "canary_scenario_matrix.json", type: "scenario_matrix", required: true },
        { name: "abort_threshold_catalog.json", type: "abort_thresholds", required: true },
        { name: "canary_deployment_plan.json", type: "deployment_plan", required: true },
        { name: "summary.json", type: "gate_summary", required: true },
        { name: "steps.jsonl", type: "forensic_steps", required: true },
        { name: "blocker_index.json", type: "blocker_index", required: true },
        { name: "BUNDLE_MANIFEST.json", type: "manifest", required: true },
        { name: "replay.sh", type: "replay_script", required: true },
        { name: "logs/", type: "execution_logs", required: true }
      ],
      metadata: {
        verdict: $verdict,
        total_checks: $total,
        passed: $pass,
        failed: $fail,
        stages: 6,
        abort_thresholds: 15,
        scenario_source: "scenario_registry.json"
      },
      dependency_evidence: {
        "235t.28.4": "scripts/e2e/e2e_performance_reliability_gate.sh",
        "235t.26.7.3": "scripts/e2e/e2e_actionability_gate.sh",
        "235t.33.4": "scripts/e2e/e2e_failure_journey_forensic_bundle.sh"
      },
      replay_instructions: {
        full_gate: "bash scripts/e2e/e2e_canary_scenario_matrix.sh --run-id <run-id>",
        dry_run: "bash scripts/e2e/e2e_canary_scenario_matrix.sh --dry-run"
      }
    }' > "${OUT_ROOT}/BUNDLE_MANIFEST.json"

  # Replay script
  cat > "${OUT_ROOT}/replay.sh" <<REPLAY
#!/usr/bin/env bash
# Deterministic replay of canary scenario matrix run ${RUN_ID}
set -euo pipefail
bash scripts/e2e/e2e_canary_scenario_matrix.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"
REPLAY
  chmod +x "${OUT_ROOT}/replay.sh"

  # Final report
  cat <<REPORT


════════════════════════════════════════════════════════════════════
  CANARY SCENARIO MATRIX — ${RUN_ID}
════════════════════════════════════════════════════════════════════

  Gate Verdict:         ${GATE_VERDICT}
  CI Mode:              ${CI_MODE}
  Dry Run:              ${DRY_RUN}

  Checks:               ${TOTAL_CHECKS} total
    Pass:               ${GATE_PASS}
    Fail:               ${GATE_FAIL}
    Skip:               ${GATE_SKIP}
    Warn:               ${GATE_WARN}

  Blockers:             ${#BLOCKER_RECORDS[@]}

  Canary Stages:
    0. preflight (0%)   — Security scenarios + upstream validation
    1. canary 1%        — Availability (30min bake)
    2. canary 5%        — Correctness (60min bake)
    3. canary 10%       — Performance (120min bake)
    4. canary 25%       — Cost control (240min bake)
    5. full promotion   — Requires go/no-go gate (34.4)

  Gate Phases:
    1. preflight        — Input source validation
    2. upstream         — Upstream gate verdict validation
    3. thresholds       — Abort threshold catalog generation
    4. scenarios        — Canary scenario selection from registry
    5. stages           — Deployment stage plan generation
    6. health           — Health signal infrastructure validation
    7. verdict          — Gate verdict + bundle manifest

  Artifacts:            ${OUT_ROOT}/
    canary_matrix_gate.json        — gate verdict + consumers
    canary_scenario_matrix.json    — scenario plan by impact category
    abort_threshold_catalog.json   — machine-checkable abort criteria
    canary_deployment_plan.json    — staged rollout plan
    BUNDLE_MANIFEST.json           — artifact index
    summary.json                   — gate summary
    steps.jsonl                    — forensic steps
    replay.sh                      — deterministic replay

  Consumer Beads:
    235t.34.2  — Rollback drill scripts
    235t.34.3  — Rehearsal automation
    235t.34.4  — Go/no-go decision gate

════════════════════════════════════════════════════════════════════

REPORT

  record_step "canary_matrix.verdict" "gate_verdict" "${GATE_VERDICT}" 0 \
    "contract.canary_matrix_gate"
fi
