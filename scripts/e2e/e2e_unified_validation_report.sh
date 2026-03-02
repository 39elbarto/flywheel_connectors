#!/usr/bin/env bash
# =============================================================================
# e2e_unified_validation_report.sh — Unified Validation Report + Release Gate
# =============================================================================
# Bead:     235t.27.4 (ASUPERSYNC-VALIDATION Unified Report + Release Gate)
# Schema:   asupersync-unified-validation-report/v1
#
# Terminal gate artifact aggregating conformance, cross-component E2E, and
# fuzz/adversarial outcomes into a machine-readable release-gate status
# consumed by UX/OPS/cutover beads.
#
# Input Sources:
#   1. Conformance revalidation   (27.1) → summary.json + drift_classification.json
#   2. Cross-component E2E        (27.2) → summary.json + drift_classification.json
#   3. Fuzz/adversarial boundary  (27.3) → summary.json + findings.json
#   4. Suite runner (optional)    → suite_report.json
#   5. Actionability gate (opt.)  → actionability_gate_report.json
#
# Outputs:
#   unified_validation_report.json  — aggregate gate status + evidence pointers
#   release_gate_status.json        — machine-consumable pass/fail/block for downstream
#   blocker_index.json              — all blocking deltas with remediation
#   waiver_table.json               — approved waivers with expiry
#   BUNDLE_MANIFEST.json            — artifact index
#   replay.sh                       — deterministic replay
#
# Usage:
#   bash scripts/e2e/e2e_unified_validation_report.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --suite-root <path>     Path to suite runner output root
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing sub-gates
#   --ci                    CI mode (strict: no waivers accepted)
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-unified-validation-report/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
SUITE_ROOT=""
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"

declare -i PHASE_PASS=0
declare -i PHASE_FAIL=0
declare -i PHASE_SKIP=0
declare -i PHASE_WARN=0
declare -a BLOCKER_RECORDS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_unified_validation_report.sh [options]

Unified Validation Report + Release Gate Artifact

Aggregates conformance, cross-component E2E, and fuzz/adversarial
revalidation outcomes into a terminal release-gate artifact.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --suite-root <path>     Suite runner output root (default: auto-detect latest)
  --out-root <path>       Artifact root (default: artifacts/asupersync/unified/<run-id>)
  --dry-run               Emit plan without executing sub-gates
  --ci                    CI mode (strict: no waivers accepted)
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
  printf '[%s] [UNIFIED-REPORT/%s] %s\n' "$(now_iso)" "$1" "$2"
}

record_step() {
  local phase="$1"
  local status="$2"
  local duration_ms="$3"
  local detail="${4:-}"

  jq -c -n \
    --arg schema_version "${FORENSICS_SCHEMA}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario_id "unified_report.${phase}" \
    --arg trace_id "${RUN_ID}-unified_report.${phase}" \
    --arg correlation_id "${RUN_ID}" \
    --arg connector "n/a" \
    --arg zone "n/a" \
    --arg operation "${phase}" \
    --argjson attempt 1 \
    --argjson timeout_budget_ms 600000 \
    --arg outcome "${status}" \
    --argjson elapsed_ms "${duration_ms}" \
    --arg reason "${detail}" \
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
      reason: (if ($reason | length) > 0 then $reason else null end)
    }' >> "${STEPS_FILE}"
}

add_blocker() {
  local source="$1"
  local category="$2"
  local description="$3"
  local remediation="$4"
  local severity="$5"
  local b
  b="$(jq -c -n \
    --arg source "${source}" \
    --arg category "${category}" \
    --arg description "${description}" \
    --arg remediation "${remediation}" \
    --arg severity "${severity}" \
    --arg found_at "$(now_iso)" \
    '{
      source: $source,
      category: $category,
      description: $description,
      remediation: $remediation,
      severity: $severity,
      found_at: $found_at
    }')"
  BLOCKER_RECORDS+=("${b}")
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)       RUN_ID="$2"; shift 2;;
    --suite-root)   SUITE_ROOT="$2"; shift 2;;
    --out-root)     OUT_ROOT="$2"; shift 2;;
    --dry-run)      DRY_RUN=true; shift;;
    --ci)           CI_MODE=true; shift;;
    -h|--help)      usage; exit 0;;
    *)              echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/unified/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
: > "${STEPS_FILE}"

# Auto-detect suite root if not specified
if [[ -z "${SUITE_ROOT}" ]]; then
  SUITE_ROOT="${REPO_ROOT}/artifacts/asupersync/suite"
  # Find the latest run directory
  if [[ -d "${SUITE_ROOT}" ]]; then
    latest_run="$(ls -t "${SUITE_ROOT}" 2>/dev/null | head -1)"
    if [[ -n "${latest_run}" ]]; then
      SUITE_ROOT="${SUITE_ROOT}/${latest_run}"
    fi
  fi
fi

log_step "INIT" "Unified Validation Report v1 — run_id=${RUN_ID}"
log_step "INIT" "Suite root: ${SUITE_ROOT}"
log_step "INIT" "Output: ${OUT_ROOT}"
echo ""

# =============================================================================
# Phase 1: Run Conformance Revalidation (27.1)
# =============================================================================
log_step "CONFORMANCE" "Phase 1: Protocol Conformance Revalidation (27.1)"
CONFORMANCE_ROOT="${OUT_ROOT}/conformance"

phase_start=$(now_ms)
if [[ "${DRY_RUN}" == "true" ]]; then
  mkdir -p "${CONFORMANCE_ROOT}"
  echo '{"overall_status":"planned","dry_run":true}' > "${CONFORMANCE_ROOT}/summary.json"
  echo '{"drift_records":[]}' > "${CONFORMANCE_ROOT}/drift_classification.json"
  log_step "CONFORMANCE" "[dry-run] Planned"
  PHASE_SKIP=$((PHASE_SKIP + 1))
  record_step "conformance_revalidation" "planned" 0 "dry_run"
else
  bash "${SCRIPT_DIR}/e2e_conformance_revalidation.sh" \
    --run-id "${RUN_ID}" \
    --out-root "${CONFORMANCE_ROOT}" 2>&1 | tee "${OUT_ROOT}/conformance.log" || true

  if [[ -f "${CONFORMANCE_ROOT}/summary.json" ]]; then
    conf_status=$(jq -r '.overall_status // "unknown"' "${CONFORMANCE_ROOT}/summary.json")
    if [[ "${conf_status}" == "pass" ]]; then
      PHASE_PASS=$((PHASE_PASS + 1))
      log_step "CONFORMANCE" "PASS"
    else
      PHASE_FAIL=$((PHASE_FAIL + 1))
      log_step "CONFORMANCE" "FAIL (status=${conf_status})"
      # Extract drift records as blockers
      drift_count=$(jq -r '.summary.drift_count // 0' "${CONFORMANCE_ROOT}/drift_classification.json" 2>/dev/null || echo "0")
      if (( drift_count > 0 )); then
        add_blocker "conformance_revalidation" "drift" \
          "${drift_count} drift records in conformance revalidation" \
          "Review drift_classification.json — each record has contract_id and rerun_command" \
          "high"
      fi
    fi
  else
    PHASE_FAIL=$((PHASE_FAIL + 1))
    log_step "CONFORMANCE" "FAIL (no summary.json produced)"
    add_blocker "conformance_revalidation" "infrastructure" \
      "Conformance revalidation failed to produce summary.json" \
      "Check conformance.log for build/test errors" \
      "critical"
  fi
fi
phase_end=$(now_ms)
phase_elapsed=$((phase_end - phase_start))
if [[ "${DRY_RUN}" != "true" ]]; then
  conf_status_val="${conf_status:-unknown}"
  record_step "conformance_revalidation" "${conf_status_val}" "${phase_elapsed}"
fi

# =============================================================================
# Phase 2: Run Cross-Component E2E Revalidation (27.2)
# =============================================================================
log_step "CROSS_COMPONENT" "Phase 2: Cross-Component E2E Revalidation (27.2)"
CROSS_COMP_ROOT="${OUT_ROOT}/cross-component"

phase_start=$(now_ms)
if [[ "${DRY_RUN}" == "true" ]]; then
  mkdir -p "${CROSS_COMP_ROOT}"
  echo '{"overall_status":"planned","dry_run":true}' > "${CROSS_COMP_ROOT}/summary.json"
  echo '{"drift_records":[],"regressions":[]}' > "${CROSS_COMP_ROOT}/drift_classification.json"
  log_step "CROSS_COMPONENT" "[dry-run] Planned"
  PHASE_SKIP=$((PHASE_SKIP + 1))
  record_step "cross_component_revalidation" "planned" 0 "dry_run"
else
  bash "${SCRIPT_DIR}/e2e_cross_component_revalidation.sh" \
    --run-id "${RUN_ID}" \
    --out-root "${CROSS_COMP_ROOT}" 2>&1 | tee "${OUT_ROOT}/cross_component.log" || true

  if [[ -f "${CROSS_COMP_ROOT}/summary.json" ]]; then
    cc_status=$(jq -r '.overall_status // "unknown"' "${CROSS_COMP_ROOT}/summary.json")
    if [[ "${cc_status}" == "pass" ]]; then
      PHASE_PASS=$((PHASE_PASS + 1))
      log_step "CROSS_COMPONENT" "PASS"
    elif [[ "${cc_status}" == "warn" ]]; then
      PHASE_WARN=$((PHASE_WARN + 1))
      log_step "CROSS_COMPONENT" "WARN (non-blocking warnings)"
    else
      PHASE_FAIL=$((PHASE_FAIL + 1))
      log_step "CROSS_COMPONENT" "FAIL (status=${cc_status})"
      regression_count=$(jq -r '.drift.regression_count // 0' "${CROSS_COMP_ROOT}/summary.json" 2>/dev/null || echo "0")
      if (( regression_count > 0 )); then
        add_blocker "cross_component_revalidation" "regression" \
          "${regression_count} regressions in cross-component data paths" \
          "Review regression_index.json — each entry has contract_id and rerun_command" \
          "high"
      fi
    fi
  else
    PHASE_FAIL=$((PHASE_FAIL + 1))
    log_step "CROSS_COMPONENT" "FAIL (no summary.json produced)"
    add_blocker "cross_component_revalidation" "infrastructure" \
      "Cross-component revalidation failed to produce summary.json" \
      "Check cross_component.log for build/test errors" \
      "critical"
  fi
fi
phase_end=$(now_ms)
phase_elapsed=$((phase_end - phase_start))
if [[ "${DRY_RUN}" != "true" ]]; then
  cc_status_val="${cc_status:-unknown}"
  record_step "cross_component_revalidation" "${cc_status_val}" "${phase_elapsed}"
fi

# =============================================================================
# Phase 3: Run Fuzz/Adversarial Boundary Revalidation (27.3)
# =============================================================================
log_step "FUZZ_ADVERSARIAL" "Phase 3: Fuzz + Adversarial Boundary Revalidation (27.3)"
FUZZ_ROOT="${OUT_ROOT}/fuzz-adversarial"

phase_start=$(now_ms)
if [[ "${DRY_RUN}" == "true" ]]; then
  mkdir -p "${FUZZ_ROOT}"
  echo '{"overall_status":"planned","dry_run":true}' > "${FUZZ_ROOT}/summary.json"
  echo '{"findings":[],"severity_summary":{"total":0,"critical":0,"high":0}}' > "${FUZZ_ROOT}/findings.json"
  log_step "FUZZ_ADVERSARIAL" "[dry-run] Planned"
  PHASE_SKIP=$((PHASE_SKIP + 1))
  record_step "fuzz_adversarial_revalidation" "planned" 0 "dry_run"
else
  bash "${SCRIPT_DIR}/e2e_fuzz_adversarial_revalidation.sh" \
    --run-id "${RUN_ID}" \
    --out-root "${FUZZ_ROOT}" 2>&1 | tee "${OUT_ROOT}/fuzz_adversarial.log" || true

  if [[ -f "${FUZZ_ROOT}/summary.json" ]]; then
    fuzz_status=$(jq -r '.overall_status // "unknown"' "${FUZZ_ROOT}/summary.json")
    if [[ "${fuzz_status}" == "pass" ]]; then
      PHASE_PASS=$((PHASE_PASS + 1))
      log_step "FUZZ_ADVERSARIAL" "PASS"
    elif [[ "${fuzz_status}" == "warn" ]]; then
      PHASE_WARN=$((PHASE_WARN + 1))
      log_step "FUZZ_ADVERSARIAL" "WARN (non-blocking warnings)"
    else
      PHASE_FAIL=$((PHASE_FAIL + 1))
      log_step "FUZZ_ADVERSARIAL" "FAIL (status=${fuzz_status})"
      critical_count=$(jq -r '.severity_summary.critical // 0' "${FUZZ_ROOT}/findings.json" 2>/dev/null || echo "0")
      high_count=$(jq -r '.severity_summary.high // 0' "${FUZZ_ROOT}/findings.json" 2>/dev/null || echo "0")
      if (( critical_count > 0 )); then
        add_blocker "fuzz_adversarial_revalidation" "crash" \
          "${critical_count} critical findings (crash/hang/corruption)" \
          "Review findings.json — critical items must be fixed before cutover" \
          "critical"
      fi
      if (( high_count > 0 )); then
        add_blocker "fuzz_adversarial_revalidation" "regression" \
          "${high_count} high-severity findings (behavioral regression)" \
          "Review findings.json — high items affect user-visible quality" \
          "high"
      fi
    fi
  else
    PHASE_FAIL=$((PHASE_FAIL + 1))
    log_step "FUZZ_ADVERSARIAL" "FAIL (no summary.json produced)"
    add_blocker "fuzz_adversarial_revalidation" "infrastructure" \
      "Fuzz/adversarial revalidation failed to produce summary.json" \
      "Check fuzz_adversarial.log for build/test errors" \
      "critical"
  fi
fi
phase_end=$(now_ms)
phase_elapsed=$((phase_end - phase_start))
if [[ "${DRY_RUN}" != "true" ]]; then
  fuzz_status_val="${fuzz_status:-unknown}"
  record_step "fuzz_adversarial_revalidation" "${fuzz_status_val}" "${phase_elapsed}"
fi

# =============================================================================
# Phase 4: Ingest Suite Runner Report (optional)
# =============================================================================
log_step "SUITE" "Phase 4: Suite runner report ingestion"

SUITE_STATUS="not_available"
SUITE_GATE_FAILURES=0

phase_start=$(now_ms)
if [[ -f "${SUITE_ROOT}/suite_report.json" ]]; then
  SUITE_STATUS=$(jq -r '.overall_status // "unknown"' "${SUITE_ROOT}/suite_report.json")
  SUITE_GATE_FAILURES=$(jq -r '.gate_failures // 0' "${SUITE_ROOT}/suite_report.json" 2>/dev/null || echo "0")
  log_step "SUITE" "Ingested: status=${SUITE_STATUS}, gate_failures=${SUITE_GATE_FAILURES}"
  if [[ "${SUITE_STATUS}" == "pass" ]]; then
    PHASE_PASS=$((PHASE_PASS + 1))
  elif [[ "${SUITE_STATUS}" == "warn" ]]; then
    PHASE_WARN=$((PHASE_WARN + 1))
  else
    PHASE_FAIL=$((PHASE_FAIL + 1))
    if (( SUITE_GATE_FAILURES > 0 )); then
      add_blocker "suite_runner" "gate_failure" \
        "${SUITE_GATE_FAILURES} gate failures in suite runner" \
        "Review suite_report.json for per-gate status" \
        "high"
    fi
  fi
  record_step "suite_runner_ingestion" "${SUITE_STATUS}" 0
else
  log_step "SUITE" "No suite_report.json found (optional — not blocking)"
  PHASE_SKIP=$((PHASE_SKIP + 1))
  record_step "suite_runner_ingestion" "planned" 0 "not_available"
fi
phase_end=$(now_ms)

# =============================================================================
# Phase 5: Ingest Actionability Gate Report (optional)
# =============================================================================
log_step "ACTIONABILITY" "Phase 5: Actionability gate report ingestion"

ACTIONABILITY_STATUS="not_available"

if [[ -f "${SUITE_ROOT}/actionability_gate_report.json" ]]; then
  ACTIONABILITY_STATUS=$(jq -r '.overall_status // "unknown"' "${SUITE_ROOT}/actionability_gate_report.json")
  log_step "ACTIONABILITY" "Ingested: status=${ACTIONABILITY_STATUS}"
  if [[ "${ACTIONABILITY_STATUS}" == "pass" ]]; then
    PHASE_PASS=$((PHASE_PASS + 1))
  else
    PHASE_WARN=$((PHASE_WARN + 1))
    log_step "ACTIONABILITY" "WARN: actionability gate not passing (non-blocking for validation)"
  fi
  record_step "actionability_gate_ingestion" "${ACTIONABILITY_STATUS}" 0
else
  log_step "ACTIONABILITY" "No actionability_gate_report.json found (optional)"
  PHASE_SKIP=$((PHASE_SKIP + 1))
  record_step "actionability_gate_ingestion" "planned" 0 "not_available"
fi

# =============================================================================
# Compute Release Gate Status
# =============================================================================
log_step "GATE" "Computing release gate status"

TOTAL_PHASES=$((PHASE_PASS + PHASE_FAIL + PHASE_SKIP + PHASE_WARN))
BLOCKER_COUNT=${#BLOCKER_RECORDS[@]}

# Gate logic:
# - PASS: all required phases pass (conformance, cross-component, fuzz)
# - WARN: all required pass but optional phases have warnings
# - FAIL: any required phase fails or critical blockers exist
# - BLOCK: infrastructure failures prevent evaluation

GATE_STATUS="pass"
GATE_REASON="All validation phases passed"

if (( PHASE_FAIL > 0 )); then
  GATE_STATUS="fail"
  GATE_REASON="${PHASE_FAIL} phase(s) failed — see blocker_index.json"
fi

# Check for critical blockers
CRITICAL_BLOCKERS=0
if (( BLOCKER_COUNT > 0 )); then
  BLOCKERS_JSON="$(printf '%s\n' "${BLOCKER_RECORDS[@]}" | jq -s '.')"
  CRITICAL_BLOCKERS=$(echo "${BLOCKERS_JSON}" | jq '[.[] | select(.severity == "critical")] | length')
  if (( CRITICAL_BLOCKERS > 0 )); then
    GATE_STATUS="block"
    GATE_REASON="${CRITICAL_BLOCKERS} critical blocker(s) — release blocked"
  fi
fi

# CI mode: no waivers
if [[ "${CI_MODE}" == "true" && "${GATE_STATUS}" == "pass" && "${PHASE_WARN}" -gt 0 ]]; then
  GATE_STATUS="fail"
  GATE_REASON="CI mode: ${PHASE_WARN} warning(s) promoted to failures"
fi

# =============================================================================
# Generate Blocker Index
# =============================================================================
BLOCKERS_JSON='[]'
if (( BLOCKER_COUNT > 0 )); then
  BLOCKERS_JSON="$(printf '%s\n' "${BLOCKER_RECORDS[@]}" | jq -s 'sort_by(.severity, .source)')"
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson count "${BLOCKER_COUNT}" \
  --argjson critical "${CRITICAL_BLOCKERS}" \
  --argjson blockers "${BLOCKERS_JSON}" \
  '{
    run_id: $run_id,
    generated_at: $generated_at,
    blocker_count: $count,
    critical_count: $critical,
    blockers: $blockers,
    remediation_guide: "Each blocker includes source, category, and remediation steps. Critical blockers must be resolved before cutover."
  }' > "${OUT_ROOT}/blocker_index.json"

# =============================================================================
# Generate Waiver Table
# =============================================================================
# Waivers are pre-approved deviations documented here for traceability
WAIVER_POLICY="Waivers require explicit approval with expiry date"
if [[ "${CI_MODE}" == "true" ]]; then
  WAIVER_POLICY="CI mode: no waivers accepted"
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson ci_mode "${CI_MODE}" \
  --arg policy "${WAIVER_POLICY}" \
  '{
    run_id: $run_id,
    generated_at: $generated_at,
    ci_mode: $ci_mode,
    policy: $policy,
    waivers: [],
    notes: "No active waivers. Add entries here for approved deviations with expiry dates and approval chain."
  }' > "${OUT_ROOT}/waiver_table.json"

# =============================================================================
# Generate Release Gate Status (machine-consumable)
# =============================================================================
jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg gate_status "${GATE_STATUS}" \
  --arg gate_reason "${GATE_REASON}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson blocker_count "${BLOCKER_COUNT}" \
  --argjson critical_blockers "${CRITICAL_BLOCKERS}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    gate_status: $gate_status,
    gate_reason: $gate_reason,
    ci_mode: $ci_mode,
    blockers: {
      total: $blocker_count,
      critical: $critical_blockers
    },
    pass_criteria: {
      conformance: "All golden vectors, schema, compliance, datagram tests pass (0 regressions)",
      cross_component: "All 8 data paths validated (0 regressions in cross-boundary behavior)",
      fuzz_adversarial: "0 critical findings, 0 corpus regression crashes, all boundaries enforced",
      suite: "Optional: E2E scenario matrix + gate pipeline passes",
      actionability: "Optional: failure taxonomy + remediation clarity validated"
    },
    consumer_guidance: {
      ux_gate: "Gate status must be pass/warn for UX error semantics work (235t.33)",
      ops_gate: "Gate status must be pass for rollback drill scripts (235t.34)",
      perf_gate: "Gate status must be pass for performance config freeze (235t.28.4)",
      cutover_gate: "Gate status must be pass (no blockers) for final cutover (235t.29)"
    }
  }' > "${OUT_ROOT}/release_gate_status.json"

# =============================================================================
# Generate Unified Validation Report
# =============================================================================
log_step "REPORT" "Generating unified validation report"

# Collect sub-gate summaries
CONF_SUMMARY='{}'
if [[ -f "${CONFORMANCE_ROOT}/summary.json" ]]; then
  CONF_SUMMARY=$(jq '{
    status: .overall_status,
    total: .matrices.total,
    pass: .matrices.pass,
    fail: .matrices.fail,
    skip: .matrices.skip,
    drift_count: .drift_count
  }' "${CONFORMANCE_ROOT}/summary.json" 2>/dev/null || echo '{}')
fi

CC_SUMMARY='{}'
if [[ -f "${CROSS_COMP_ROOT}/summary.json" ]]; then
  CC_SUMMARY=$(jq '{
    status: .overall_status,
    total: .data_paths.total_tests,
    pass: .data_paths.pass,
    fail: .data_paths.fail,
    skip: .data_paths.skip,
    warn: .data_paths.warn,
    drift_count: .drift.drift_count,
    regression_count: .drift.regression_count
  }' "${CROSS_COMP_ROOT}/summary.json" 2>/dev/null || echo '{}')
fi

FUZZ_SUMMARY='{}'
if [[ -f "${FUZZ_ROOT}/summary.json" ]]; then
  FUZZ_SUMMARY=$(jq '{
    status: .overall_status,
    total: .tests.total,
    pass: .tests.pass,
    fail: .tests.fail,
    skip: .tests.skip,
    warn: .tests.warn,
    finding_count: .findings.total,
    critical_findings: .findings.critical,
    high_findings: .findings.high
  }' "${FUZZ_ROOT}/summary.json" 2>/dev/null || echo '{}')
fi

SUITE_SUMMARY='null'
if [[ -f "${SUITE_ROOT}/suite_report.json" ]]; then
  SUITE_SUMMARY=$(jq '{
    status: .overall_status,
    gate_failures: .gate_failures,
    scenario_summary: .scenario_summary
  }' "${SUITE_ROOT}/suite_report.json" 2>/dev/null || echo 'null')
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg gate_status "${GATE_STATUS}" \
  --arg gate_reason "${GATE_REASON}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson dry_run "${DRY_RUN}" \
  --argjson total_phases "${TOTAL_PHASES}" \
  --argjson phases_pass "${PHASE_PASS}" \
  --argjson phases_fail "${PHASE_FAIL}" \
  --argjson phases_skip "${PHASE_SKIP}" \
  --argjson phases_warn "${PHASE_WARN}" \
  --argjson blocker_count "${BLOCKER_COUNT}" \
  --argjson conformance "${CONF_SUMMARY}" \
  --argjson cross_component "${CC_SUMMARY}" \
  --argjson fuzz_adversarial "${FUZZ_SUMMARY}" \
  --argjson suite "${SUITE_SUMMARY}" \
  --arg actionability_status "${ACTIONABILITY_STATUS}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    gate_status: $gate_status,
    gate_reason: $gate_reason,
    ci_mode: $ci_mode,
    dry_run: $dry_run,
    phases: {
      total: $total_phases,
      pass: $phases_pass,
      fail: $phases_fail,
      skip: $phases_skip,
      warn: $phases_warn
    },
    blocker_count: $blocker_count,
    sub_gates: {
      conformance_revalidation: $conformance,
      cross_component_revalidation: $cross_component,
      fuzz_adversarial_revalidation: $fuzz_adversarial,
      suite_runner: $suite,
      actionability_gate: $actionability_status
    },
    artifacts: {
      unified_report: "unified_validation_report.json",
      release_gate: "release_gate_status.json",
      blocker_index: "blocker_index.json",
      waiver_table: "waiver_table.json",
      steps: "steps.jsonl",
      replay: "replay.sh",
      bundle_manifest: "BUNDLE_MANIFEST.json",
      conformance: "conformance/",
      cross_component: "cross-component/",
      fuzz_adversarial: "fuzz-adversarial/"
    }
  }' > "${OUT_ROOT}/unified_validation_report.json"

# =============================================================================
# Generate Bundle Manifest
# =============================================================================
jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg gate_status "${GATE_STATUS}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    gate_status: $gate_status,
    bundle_type: "unified-validation",
    contents: [
      { path: "unified_validation_report.json", type: "report", required: true },
      { path: "release_gate_status.json", type: "gate_status", required: true },
      { path: "blocker_index.json", type: "blocker_index", required: true },
      { path: "waiver_table.json", type: "waiver_table", required: true },
      { path: "steps.jsonl", type: "forensics", required: true },
      { path: "replay.sh", type: "replay", required: true },
      { path: "BUNDLE_MANIFEST.json", type: "manifest", required: true },
      { path: "conformance/summary.json", type: "sub_gate_summary", required: false },
      { path: "conformance/drift_classification.json", type: "drift", required: false },
      { path: "conformance/steps.jsonl", type: "forensics", required: false },
      { path: "cross-component/summary.json", type: "sub_gate_summary", required: false },
      { path: "cross-component/drift_classification.json", type: "drift", required: false },
      { path: "cross-component/regression_index.json", type: "regression", required: false },
      { path: "cross-component/path_coverage.json", type: "coverage", required: false },
      { path: "cross-component/steps.jsonl", type: "forensics", required: false },
      { path: "fuzz-adversarial/summary.json", type: "sub_gate_summary", required: false },
      { path: "fuzz-adversarial/findings.json", type: "findings", required: false },
      { path: "fuzz-adversarial/fuzz_coverage.json", type: "coverage", required: false },
      { path: "fuzz-adversarial/steps.jsonl", type: "forensics", required: false }
    ],
    triage_guide: {
      gate_pass: "All sub-gates passed. Proceed to downstream beads.",
      gate_fail: "Check blocker_index.json for blocking items. Each has remediation steps.",
      gate_block: "Critical infrastructure failure. Check individual sub-gate logs.",
      waiver_process: "Add entries to waiver_table.json with expiry + approval chain."
    }
  }' > "${OUT_ROOT}/BUNDLE_MANIFEST.json"

# =============================================================================
# Generate Replay Script
# =============================================================================
cat > "${OUT_ROOT}/replay.sh" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay: Unified Validation Report ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Unified Validation Report: ${RUN_ID} ==="

bash scripts/e2e/e2e_unified_validation_report.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"$(
  [[ -n "${SUITE_ROOT}" ]] && printf ' \\\n  --suite-root "%s"' "${SUITE_ROOT}"
  [[ "${CI_MODE}" == "true" ]] && printf ' \\\n  --ci'
  )
REPLAY_EOF
chmod +x "${OUT_ROOT}/replay.sh"

# =============================================================================
# Summary Output
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  UNIFIED VALIDATION REPORT — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
if [[ "${GATE_STATUS}" == "pass" ]]; then
  echo "  │  RELEASE GATE STATUS:  PASS                            │"
elif [[ "${GATE_STATUS}" == "warn" ]]; then
  echo "  │  RELEASE GATE STATUS:  WARN (non-blocking)             │"
elif [[ "${GATE_STATUS}" == "block" ]]; then
  echo "  │  RELEASE GATE STATUS:  BLOCK (critical blockers)       │"
else
  echo "  │  RELEASE GATE STATUS:  FAIL                            │"
fi
echo "  │  Reason: $(printf '%-45s' "${GATE_REASON}")│"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
echo "  CI Mode:              ${CI_MODE}"
echo "  Dry Run:              ${DRY_RUN}"
echo ""
echo "  Phases:               ${TOTAL_PHASES} total"
echo "    Pass:               ${PHASE_PASS}"
echo "    Fail:               ${PHASE_FAIL}"
echo "    Skip:               ${PHASE_SKIP}"
echo "    Warn:               ${PHASE_WARN}"
echo ""
echo "  Blockers:             ${BLOCKER_COUNT} total"
echo "    Critical:           ${CRITICAL_BLOCKERS}"
echo ""
echo "  Sub-Gate Results:"
echo "    1. Conformance (27.1):    $(jq -r '.status // "n/a"' <<< "${CONF_SUMMARY}")"
echo "    2. Cross-Component (27.2): $(jq -r '.status // "n/a"' <<< "${CC_SUMMARY}")"
echo "    3. Fuzz/Adversarial (27.3): $(jq -r '.status // "n/a"' <<< "${FUZZ_SUMMARY}")"
echo "    4. Suite Runner:          ${SUITE_STATUS}"
echo "    5. Actionability Gate:    ${ACTIONABILITY_STATUS}"
echo ""
echo "  Artifacts:            ${OUT_ROOT}/"
echo "    unified_validation_report.json  — aggregate report"
echo "    release_gate_status.json        — machine-readable gate status"
echo "    blocker_index.json              — blocking deltas + remediation"
echo "    waiver_table.json               — approved waivers"
echo "    BUNDLE_MANIFEST.json            — artifact index"
echo "    steps.jsonl                     — per-phase forensic steps"
echo "    replay.sh                       — deterministic replay"
echo "    conformance/                    — conformance revalidation"
echo "    cross-component/               — cross-component E2E"
echo "    fuzz-adversarial/              — fuzz/adversarial boundary"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if (( BLOCKER_COUNT > 0 )); then
  echo ""
  echo "  Blockers requiring resolution:"
  for b in "${BLOCKER_RECORDS[@]}"; do
    severity="$(echo "${b}" | jq -r '.severity')"
    source="$(echo "${b}" | jq -r '.source')"
    desc="$(echo "${b}" | jq -r '.description[:100]')"
    echo "  - [${severity}] ${source}: ${desc}"
  done
  echo ""
fi

if [[ "${GATE_STATUS}" == "fail" || "${GATE_STATUS}" == "block" ]]; then
  exit 1
fi
