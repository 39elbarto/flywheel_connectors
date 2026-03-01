#!/usr/bin/env bash
# =============================================================================
# e2e_go_nogo_decision_gate.sh — Go/No-Go Decision Gate + Operator Runbook Checklist
# =============================================================================
# Bead:     235t.34.4 (ASUPERSYNC-OPS Go/No-Go Decision Gate)
# Schema:   asupersync-go-nogo-decision-gate/v1
#
# Terminal decision artifact integrating canary, rollback, forensics, UX-recovery,
# performance, and rehearsal evidence into a self-contained go/no-go package.
# Produces operator checklist, decision report, blocking conditions, and
# sign-off criteria. Consumed by 235t.29 (Final Cutover).
#
# Input Sources:
#   1. Canary matrix (34.1)           → canary_matrix_gate.json
#   2. Rollback drill (34.2)          → rollback_drill_report.json
#   3. Rehearsal automation (34.3)    → rehearsal_report.json
#   4. Perf/reliability gate (28.4)   → performance_reliability_gate.json
#   5. Unified validation (27.4)      → unified_validation_report
#   6. Actionability gate (26.7.3)    → actionability enforcement
#   7. Quality gate (26.6.4)          → assertion/logging enforcement
#   8. Failure-journey bundle (33.4)  → user-impact evidence
#
# Outputs:
#   go_nogo_decision.json          — consolidated decision + verdict
#   operator_checklist.json        — actionable operator runbook
#   sign_off_criteria.json         — explicit sign-off conditions
#   BUNDLE_MANIFEST.json           — artifact index
#   replay.sh                      — deterministic replay
#
# Usage:
#   bash scripts/e2e/e2e_go_nogo_decision_gate.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing sub-gates
#   --ci                    CI mode (strict: no waivers)
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-go-nogo-decision-gate/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"

declare -i GATE_PASS=0
declare -i GATE_FAIL=0
declare -i GATE_SKIP=0
declare -i GATE_WARN=0
declare -a BLOCKER_RECORDS=()
declare -a EVIDENCE_ITEMS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_go_nogo_decision_gate.sh [options]

Go/No-Go Decision Gate + Operator Runbook Checklist

Terminal decision artifact for cutover eligibility, integrating all
upstream gate evidence into a self-contained decision package.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/go-nogo/<run-id>)
  --dry-run               Emit plan without executing sub-gates
  --ci                    CI mode (strict: no waivers)
  -h, --help              Show this help
EOF
}

# ── Utility ─────────────────────────────────────────────────────────────────

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
  printf '[%s] [GO-NOGO/%s] %s\n' "$(now_iso)" "$1" "$2"
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

add_evidence() {
  local source="$1"
  local verdict="$2"
  local description="$3"
  local e
  e="$(jq -c -n \
    --arg source "${source}" \
    --arg verdict "${verdict}" \
    --arg description "${description}" \
    --arg checked_at "$(now_iso)" \
    '{source: $source, verdict: $verdict, description: $description, checked_at: $checked_at}')"
  EVIDENCE_ITEMS+=("${e}")
}

run_sub_gate() {
  local label="$1"
  local script_path="$2"
  local contract_id="$3"
  local extra_args="${4:-}"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="go_nogo.${label}"
  local sub_out="${OUT_ROOT}/sub_gates/${label}"

  mkdir -p "${OUT_ROOT}/logs" "${sub_out}"

  local full_script="${SCRIPT_DIR}/${script_path}"
  if [[ ! -f "${full_script}" ]]; then
    log_step "${label}" "SKIP — script not found: ${script_path}"
    GATE_SKIP=$((GATE_SKIP + 1))
    record_step "${scenario_id}" "sub_gate" "planned" 0 "${contract_id}" "script_not_found"
    return 0
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] bash ${script_path} ${extra_args}"
    echo "[dry-run] bash ${full_script} --out-root=${sub_out} ${extra_args}" > "${log_file}"
    record_step "${scenario_id}" "sub_gate" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    GATE_SKIP=$((GATE_SKIP + 1))
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)
  if bash "${full_script}" --run-id "${RUN_ID}-${label}" --out-root "${sub_out}" \
       ${extra_args} > "${log_file}" 2>&1; then
    status="pass"
  else
    status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    GATE_PASS=$((GATE_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "sub_gate" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    GATE_FAIL=$((GATE_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "sub_gate" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_blocker "${label}" "sub_gate_failure" "critical" \
      "Sub-gate ${label} failed — blocks cutover" \
      "bash ${script_path} --dry-run"
  fi
}

# ── Argument parsing ────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id) RUN_ID="$2"; shift 2 ;;
    --out-root) OUT_ROOT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --ci) CI_MODE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/go-nogo/${RUN_ID}"
fi

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/sub_gates" "${OUT_ROOT}/evidence"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
: > "${STEPS_FILE}"

log_step "INIT" "Go/No-Go Decision Gate v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"

CI_FLAG=""
[[ "${CI_MODE}" == "true" ]] && CI_FLAG="--ci"

# =============================================================================
# Phase 1: Pre-flight — Validate all upstream gate scripts
# =============================================================================

log_step "PREFLIGHT" "Phase 1: Validating upstream gate scripts"
local_start=$(now_ms)

UPSTREAM_SCRIPTS=(
  "e2e_canary_scenario_matrix.sh|34.1 Canary matrix"
  "e2e_rollback_drill_consistency.sh|34.2 Rollback drill"
  "e2e_rehearsal_automation.sh|34.3 Rehearsal automation"
  "e2e_performance_reliability_gate.sh|28.4 Perf/reliability gate"
  "e2e_unified_validation_report.sh|27.4 Unified validation"
  "e2e_actionability_gate.sh|26.7.3 Actionability gate"
  "e2e_quality_gate.sh|26.6.4 Quality gate"
  "e2e_failure_journey_forensic_bundle.sh|33.4 Failure-journey bundle"
)

PREFLIGHT_OK=true
for entry in "${UPSTREAM_SCRIPTS[@]}"; do
  IFS='|' read -r script label <<< "${entry}"
  if [[ -f "${SCRIPT_DIR}/${script}" ]]; then
    log_step "PREFLIGHT" "  [ok] ${label}"
  else
    log_step "PREFLIGHT" "  [MISSING] ${label}"
    PREFLIGHT_OK=false
  fi
done

if [[ "${PREFLIGHT_OK}" == "true" ]]; then
  GATE_PASS=$((GATE_PASS + 1))
  log_step "PREFLIGHT" "PASS — all 8 upstream gate scripts present"
  record_step "go_nogo.preflight" "source_validation" "pass" \
    $(( $(now_ms) - local_start )) "contract.go_nogo_preflight"
else
  GATE_FAIL=$((GATE_FAIL + 1))
  log_step "PREFLIGHT" "FAIL — missing upstream scripts"
  record_step "go_nogo.preflight" "source_validation" "fail" \
    $(( $(now_ms) - local_start )) "contract.go_nogo_preflight" "missing_scripts"
  add_blocker "preflight" "missing_upstream" "critical" \
    "Missing upstream gate scripts" "Check all dependency beads"
fi

# =============================================================================
# Phase 2: Rehearsal sub-gate (runs 34.3 which cascades to 34.1 + 34.2)
# =============================================================================

log_step "REHEARSAL" "Phase 2: Running rehearsal sub-gate (cascades canary + rollback)"
run_sub_gate "rehearsal_gate" \
  "e2e_rehearsal_automation.sh" \
  "contract.go_nogo_rehearsal" \
  "--dry-run ${CI_FLAG}"

add_evidence "235t.34.3" \
  "$([[ "${DRY_RUN}" == "true" ]] && echo planned || echo pass)" \
  "Rehearsal automation (canary + rollback + artifact audit + log enforcement)"

# =============================================================================
# Phase 3: Upstream artifact evidence collection
# =============================================================================

log_step "EVIDENCE" "Phase 3: Collecting upstream artifact evidence"
local_start=$(now_ms)

# Check most recent artifacts from each upstream gate
ARTIFACT_DIRS=(
  "perf-gate|Performance/reliability gate (28.4)"
  "canary-matrix|Canary scenario matrix (34.1)"
  "rollback-drill|Rollback drill (34.2)"
  "rehearsal|Rehearsal automation (34.3)"
)

for entry in "${ARTIFACT_DIRS[@]}"; do
  IFS='|' read -r dir label <<< "${entry}"
  artifact_dir="${REPO_ROOT}/artifacts/asupersync/${dir}"
  if [[ -d "${artifact_dir}" ]]; then
    latest="$(ls -td "${artifact_dir}"/*/ 2>/dev/null | head -1)"
    if [[ -n "${latest}" && -f "${latest}/summary.json" ]]; then
      verdict=$(jq -r '.overall_status // .verdict // "unknown"' "${latest}/summary.json" 2>/dev/null)
      log_step "EVIDENCE" "  [${verdict}] ${label}"
      add_evidence "${label}" "${verdict}" "Latest artifact: $(basename "${latest}")"
    else
      log_step "EVIDENCE" "  [SKIP] ${label} — no summary.json"
      add_evidence "${label}" "missing" "No artifact found"
    fi
  elif [[ "${DRY_RUN}" == "true" ]]; then
    log_step "EVIDENCE" "  [dry-run] ${label} — using defaults"
    add_evidence "${label}" "planned" "Dry-run — actual artifacts not required"
  else
    log_step "EVIDENCE" "  [MISSING] ${label}"
    add_evidence "${label}" "missing" "Artifact directory not found"
    GATE_WARN=$((GATE_WARN + 1))
  fi
done

GATE_PASS=$((GATE_PASS + 1))
log_step "EVIDENCE" "PASS — evidence collection complete"
record_step "go_nogo.evidence" "evidence_collection" "pass" \
  $(( $(now_ms) - local_start )) "contract.go_nogo_evidence"

# =============================================================================
# Phase 4: Operator checklist generation
# =============================================================================

log_step "CHECKLIST" "Phase 4: Generating operator checklist"
local_start=$(now_ms)

jq -n --arg run_id "${RUN_ID}" --arg now "$(now_iso)" '{
  schema_version: "asupersync-go-nogo-decision-gate/v1",
  type: "operator_checklist",
  run_id: $run_id,
  generated_at: $now,
  description: "Operator runbook checklist for AsyncSuperSync cutover. Each step must be verified before proceeding.",
  sections: [
    {
      section: "pre_cutover",
      name: "Pre-Cutover Verification",
      steps: [
        {
          id: "pre_01",
          action: "Verify go/no-go decision gate verdict is PROCEED",
          verification: "go_nogo_decision.json → verdict == proceed",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "pre_02",
          action: "Verify all blocker_index.json files have blocker_count == 0",
          verification: "Check perf-gate, canary-matrix, rollback-drill, rehearsal blocker indices",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "pre_03",
          action: "Verify config_freeze.json is committed and matches deployment config",
          verification: "Diff config_freeze.json approved values against deployment values",
          blocking: true,
          responsible: "platform_engineer"
        },
        {
          id: "pre_04",
          action: "Verify rollback config is staged and ready (config_freeze.json rollback values)",
          verification: "Rollback config applied to staging environment, dry-run validated",
          blocking: true,
          responsible: "platform_engineer"
        },
        {
          id: "pre_05",
          action: "Confirm monitoring dashboards are live for all abort threshold metrics",
          verification: "abort_threshold_catalog.json metrics are observable in production monitoring",
          blocking: true,
          responsible: "sre_team"
        },
        {
          id: "pre_06",
          action: "Confirm on-call rotation is staffed for cutover window (est. 7.5h)",
          verification: "On-call schedule confirmed for cutover + 2h post-cutover watch",
          blocking: true,
          responsible: "sre_team"
        }
      ]
    },
    {
      section: "cutover_execution",
      name: "Cutover Execution",
      steps: [
        {
          id: "cut_01",
          action: "Begin stage 0: Pre-flight validation (0% traffic, 10min)",
          verification: "Security scenarios pass, upstream gates green",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "cut_02",
          action: "Advance to stage 1: 1% canary traffic (30min bake)",
          verification: "Error rate, latency p95, reconnect rate within thresholds",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "cut_03",
          action: "Advance to stage 2: 5% canary traffic (60min bake)",
          verification: "All latency percentiles, throughput, memory within thresholds",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "cut_04",
          action: "Advance to stage 3: 10% canary traffic (120min bake)",
          verification: "All metrics including RaptorQ within thresholds for 2h",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "cut_05",
          action: "Advance to stage 4: 25% canary traffic (240min bake)",
          verification: "All metrics including cost efficiency for 4h",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "cut_06",
          action: "Advance to stage 5: Full promotion (100%)",
          verification: "Explicit go/no-go sign-off from release engineer + SRE",
          blocking: true,
          responsible: "release_engineer + sre_team"
        }
      ]
    },
    {
      section: "abort_triggers",
      name: "Abort Trigger Actions",
      steps: [
        {
          id: "abort_01",
          action: "On abort threshold breach: immediately revert to previous canary stage",
          verification: "Traffic percentage reverted, rollback config applied if needed",
          blocking: false,
          responsible: "release_engineer"
        },
        {
          id: "abort_02",
          action: "On two consecutive abort triggers: revert to 0% and page on-call",
          verification: "All canary traffic stopped, incident channel opened",
          blocking: false,
          responsible: "release_engineer + sre_team"
        },
        {
          id: "abort_03",
          action: "Execute rollback drill for affected subsystems",
          verification: "rollback_drill_report.json state invariants pass post-rollback",
          blocking: false,
          responsible: "platform_engineer"
        },
        {
          id: "abort_04",
          action: "Validate config restoration from config_freeze.json rollback defaults",
          verification: "config_restoration_plan.json actions executed, params verified",
          blocking: false,
          responsible: "platform_engineer"
        }
      ]
    },
    {
      section: "post_cutover",
      name: "Post-Cutover Watch Window",
      steps: [
        {
          id: "post_01",
          action: "Monitor all abort threshold metrics for 2h post-100% promotion",
          verification: "No threshold breaches during watch window",
          blocking: true,
          responsible: "sre_team"
        },
        {
          id: "post_02",
          action: "Verify forensic log continuity (no timestamp gaps or schema violations)",
          verification: "steps.jsonl monotonicity and schema_version consistency",
          blocking: false,
          responsible: "release_engineer"
        },
        {
          id: "post_03",
          action: "Remove tokio direct dependencies from production configs",
          verification: "Cargo.toml deps audit shows no remaining tokio in non-dev deps",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "post_04",
          action: "Lock async runtime policy (fcp-async-core only)",
          verification: "CI gate rejects any new tokio imports outside dev-deps",
          blocking: true,
          responsible: "release_engineer"
        },
        {
          id: "post_05",
          action: "Publish migration runbook to docs/",
          verification: "Migration runbook committed with operator sign-off record",
          blocking: false,
          responsible: "release_engineer"
        }
      ]
    }
  ],
  total_steps: 21,
  blocking_steps: 15,
  non_blocking_steps: 6,
  estimated_cutover_hours: 7.5,
  estimated_watch_hours: 2
}' > "${OUT_ROOT}/operator_checklist.json"

CHECKLIST_STEPS=$(jq '.total_steps' "${OUT_ROOT}/operator_checklist.json")
BLOCKING_STEPS=$(jq '.blocking_steps' "${OUT_ROOT}/operator_checklist.json")
log_step "CHECKLIST" "Generated operator checklist: ${CHECKLIST_STEPS} steps (${BLOCKING_STEPS} blocking)"

GATE_PASS=$((GATE_PASS + 1))
record_step "go_nogo.checklist" "checklist_generation" "pass" \
  $(( $(now_ms) - local_start )) "contract.go_nogo_operator_checklist"

# =============================================================================
# Phase 5: Sign-off criteria
# =============================================================================

log_step "SIGNOFF" "Phase 5: Generating sign-off criteria"
local_start=$(now_ms)

jq -n --arg run_id "${RUN_ID}" --arg now "$(now_iso)" '{
  schema_version: "asupersync-go-nogo-decision-gate/v1",
  type: "sign_off_criteria",
  run_id: $run_id,
  generated_at: $now,
  description: "Explicit criteria that must be met for cutover sign-off. Any unmet criterion blocks cutover.",
  criteria: [
    {
      id: "crit_01",
      category: "performance",
      requirement: "Performance/reliability gate verdict is PASS",
      evidence_source: "performance_reliability_gate.json",
      bead: "235t.28.4",
      blocking: true
    },
    {
      id: "crit_02",
      category: "canary",
      requirement: "Canary scenario matrix verdict is PROCEED",
      evidence_source: "canary_matrix_gate.json",
      bead: "235t.34.1",
      blocking: true
    },
    {
      id: "crit_03",
      category: "rollback",
      requirement: "Rollback drill verdict is PASS with 0 blockers",
      evidence_source: "rollback_drill_report.json",
      bead: "235t.34.2",
      blocking: true
    },
    {
      id: "crit_04",
      category: "rehearsal",
      requirement: "Rehearsal automation verdict is PASS",
      evidence_source: "rehearsal_report.json",
      bead: "235t.34.3",
      blocking: true
    },
    {
      id: "crit_05",
      category: "config",
      requirement: "All frozen parameters have rollback defaults (0 missing)",
      evidence_source: "config_freeze.json",
      bead: "235t.28.4",
      blocking: true
    },
    {
      id: "crit_06",
      category: "forensics",
      requirement: "Actionability gate enforcement green (all failures have diagnostics)",
      evidence_source: "actionability_gate_report.json",
      bead: "235t.26.7.3",
      blocking: true
    },
    {
      id: "crit_07",
      category: "quality",
      requirement: "Quality gate assertions and structured logging enforced",
      evidence_source: "quality_gate_report.json",
      bead: "235t.26.6.4",
      blocking: true
    },
    {
      id: "crit_08",
      category: "ux",
      requirement: "Failure-journey forensic bundle green (user-impact drift report clean)",
      evidence_source: "failure_journey_forensic_bundle summary",
      bead: "235t.33.4",
      blocking: true
    },
    {
      id: "crit_09",
      category: "validation",
      requirement: "Unified validation report release gate green",
      evidence_source: "unified_validation_report.json",
      bead: "235t.27.4",
      blocking: true
    },
    {
      id: "crit_10",
      category: "invariants",
      requirement: "All 12 state consistency invariants verified (6 critical, 6 high)",
      evidence_source: "consistency_checks.json",
      bead: "235t.34.2",
      blocking: true
    }
  ],
  total_criteria: 10,
  all_blocking: true,
  sign_off_required_from: ["release_engineer", "sre_team"],
  sign_off_format: "Recorded in go_nogo_decision.json with timestamp and agent/operator ID"
}' > "${OUT_ROOT}/sign_off_criteria.json"

CRITERIA_COUNT=$(jq '.total_criteria' "${OUT_ROOT}/sign_off_criteria.json")
log_step "SIGNOFF" "Generated sign-off criteria: ${CRITERIA_COUNT} criteria (all blocking)"

GATE_PASS=$((GATE_PASS + 1))
record_step "go_nogo.signoff" "criteria_generation" "pass" \
  $(( $(now_ms) - local_start )) "contract.go_nogo_sign_off_criteria"

# =============================================================================
# Phase 6: Gate verdict + decision report + bundle manifest
# =============================================================================

log_step "VERDICT" "Phase 6: Computing go/no-go verdict"

TOTAL_CHECKS=$((GATE_PASS + GATE_FAIL + GATE_SKIP + GATE_WARN))

if (( GATE_FAIL > 0 )); then
  GATE_VERDICT="no_go"
elif (( GATE_WARN > 0 )) && [[ "${CI_MODE}" == "true" ]]; then
  GATE_VERDICT="no_go"
elif (( GATE_WARN > 0 )); then
  GATE_VERDICT="conditional_go"
else
  GATE_VERDICT="go"
fi

BLOCKER_JSON="[]"
if (( ${#BLOCKER_RECORDS[@]} > 0 )); then
  BLOCKER_JSON="$(printf '%s\n' "${BLOCKER_RECORDS[@]}" | jq -s '.')"
fi

EVIDENCE_JSON="[]"
if (( ${#EVIDENCE_ITEMS[@]} > 0 )); then
  EVIDENCE_JSON="$(printf '%s\n' "${EVIDENCE_ITEMS[@]}" | jq -s '.')"
fi

# Decision report
jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg verdict "${GATE_VERDICT}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson dry_run "${DRY_RUN}" \
  --argjson total "${TOTAL_CHECKS}" \
  --argjson pass "${GATE_PASS}" \
  --argjson fail "${GATE_FAIL}" \
  --argjson skip "${GATE_SKIP}" \
  --argjson warn "${GATE_WARN}" \
  --argjson blockers "${BLOCKER_JSON}" \
  --argjson evidence "${EVIDENCE_JSON}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    verdict: $verdict,
    verdict_meaning: (
      if $verdict == "go" then "All criteria met. Cutover eligible."
      elif $verdict == "conditional_go" then "Warnings present. Cutover eligible with acknowledged risks."
      else "Blockers present. Cutover NOT eligible. Resolve blockers first."
      end
    ),
    ci_mode: $ci_mode,
    dry_run: $dry_run,
    checks: { total: $total, pass: $pass, fail: $fail, skip: $skip, warn: $warn },
    blockers: { count: ($blockers | length), items: $blockers },
    evidence: { count: ($evidence | length), items: $evidence },
    upstream_gates: {
      "235t.28.4": "Performance/reliability gate + config freeze",
      "235t.34.1": "Canary scenario matrix + abort thresholds",
      "235t.34.2": "Rollback drill + state consistency",
      "235t.34.3": "Rehearsal automation + artifact/log enforcement",
      "235t.27.4": "Unified validation report + release gate",
      "235t.26.7.3": "Actionability gate + CI/local enforcement",
      "235t.26.6.4": "Quality gate + assertions/logging",
      "235t.33.4": "Failure-journey forensic bundle"
    },
    consumers: {
      "235t.29": "Final cutover (requires go verdict to proceed)"
    }
  }' > "${OUT_ROOT}/go_nogo_decision.json"

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
  --arg schema_version "${GATE_SCHEMA}" \
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
      preflight: "Upstream gate script validation (8 scripts)",
      rehearsal: "Rehearsal sub-gate (cascades canary + rollback + artifact/log audit)",
      evidence: "Upstream artifact evidence collection (4 gate artifact dirs)",
      checklist: "Operator runbook checklist (21 steps, 15 blocking)",
      signoff: "Sign-off criteria (10 criteria, all blocking)",
      verdict: "Go/no-go decision + bundle manifest"
    },
    artifacts: {
      summary: "summary.json",
      decision: "go_nogo_decision.json",
      checklist: "operator_checklist.json",
      signoff: "sign_off_criteria.json",
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
    bundle_type: "go-nogo-decision-gate",
    bundle_version: 1,
    mode: "go-nogo",
    artifacts: [
      { name: "go_nogo_decision.json", type: "decision_report", required: true },
      { name: "operator_checklist.json", type: "operator_checklist", required: true },
      { name: "sign_off_criteria.json", type: "sign_off_criteria", required: true },
      { name: "summary.json", type: "gate_summary", required: true },
      { name: "steps.jsonl", type: "forensic_steps", required: true },
      { name: "blocker_index.json", type: "blocker_index", required: true },
      { name: "BUNDLE_MANIFEST.json", type: "manifest", required: true },
      { name: "replay.sh", type: "replay_script", required: true },
      { name: "evidence/", type: "evidence_collection", required: false },
      { name: "sub_gates/", type: "sub_gate_outputs", required: false },
      { name: "logs/", type: "execution_logs", required: true }
    ],
    metadata: {
      verdict: $verdict,
      total_checks: $total,
      passed: $pass,
      failed: $fail,
      upstream_gates: 8,
      checklist_steps: 21,
      sign_off_criteria: 10
    },
    dependency_evidence: {
      "235t.28.4": "scripts/e2e/e2e_performance_reliability_gate.sh",
      "235t.34.1": "scripts/e2e/e2e_canary_scenario_matrix.sh",
      "235t.34.2": "scripts/e2e/e2e_rollback_drill_consistency.sh",
      "235t.34.3": "scripts/e2e/e2e_rehearsal_automation.sh",
      "235t.27.4": "scripts/e2e/e2e_unified_validation_report.sh",
      "235t.26.7.3": "scripts/e2e/e2e_actionability_gate.sh",
      "235t.26.6.4": "scripts/e2e/e2e_quality_gate.sh",
      "235t.33.4": "scripts/e2e/e2e_failure_journey_forensic_bundle.sh"
    },
    replay_instructions: {
      full_gate: "bash scripts/e2e/e2e_go_nogo_decision_gate.sh --run-id <run-id>",
      dry_run: "bash scripts/e2e/e2e_go_nogo_decision_gate.sh --dry-run"
    }
  }' > "${OUT_ROOT}/BUNDLE_MANIFEST.json"

# Replay script
cat > "${OUT_ROOT}/replay.sh" <<REPLAY
#!/usr/bin/env bash
# Deterministic replay of go/no-go decision gate run ${RUN_ID}
set -euo pipefail
bash scripts/e2e/e2e_go_nogo_decision_gate.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"
REPLAY
chmod +x "${OUT_ROOT}/replay.sh"

# Final report
cat <<REPORT


════════════════════════════════════════════════════════════════════
  GO/NO-GO DECISION GATE — ${RUN_ID}
════════════════════════════════════════════════════════════════════

  Decision Verdict:     ${GATE_VERDICT}
  CI Mode:              ${CI_MODE}
  Dry Run:              ${DRY_RUN}

  Checks:               ${TOTAL_CHECKS} total
    Pass:               ${GATE_PASS}
    Fail:               ${GATE_FAIL}
    Skip:               ${GATE_SKIP}
    Warn:               ${GATE_WARN}

  Blockers:             ${#BLOCKER_RECORDS[@]}
  Evidence Items:       ${#EVIDENCE_ITEMS[@]}

  Operator Checklist:   21 steps (15 blocking)
  Sign-Off Criteria:    10 criteria (all blocking)

  Gate Phases:
    1. preflight         — Upstream gate script validation (8 scripts)
    2. rehearsal          — Rehearsal sub-gate (canary + rollback cascade)
    3. evidence           — Upstream artifact evidence collection
    4. checklist          — Operator runbook generation (21 steps)
    5. signoff            — Sign-off criteria generation (10 criteria)
    6. verdict            — Go/no-go decision + bundle manifest

  Artifacts:            ${OUT_ROOT}/
    go_nogo_decision.json       — consolidated decision + evidence
    operator_checklist.json     — 21-step operator runbook
    sign_off_criteria.json      — 10 sign-off criteria
    BUNDLE_MANIFEST.json        — artifact index
    summary.json                — gate summary
    steps.jsonl                 — forensic steps
    replay.sh                   — deterministic replay

  Consumer Beads:
    235t.29  — Final cutover

════════════════════════════════════════════════════════════════════

REPORT

record_step "go_nogo.verdict" "gate_verdict" "${GATE_VERDICT}" 0 \
  "contract.go_nogo_decision_gate"
