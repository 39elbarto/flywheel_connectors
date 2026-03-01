#!/usr/bin/env bash
# =============================================================================
# e2e_suite_runner.sh — Unified E2E Validation Suite Orchestrator
# =============================================================================
# Bead:     235t.26.4 (ASUPERSYNC-E2E Scripted End-to-End Scenario Suite)
# Schema:   asupersync-e2e-suite/v1
#
# Aggregates all child scenario families into a single executable E2E validation
# suite. Coordinates run_matrix.sh (scenario execution), integration_gate_executor,
# unit_gate_executor, and coverage_gate_publication into a unified report.
#
# Phases:
#   1. Pre-flight checks (jq, registry, coverage matrix)
#   2. Scenario catalog generation from scenario_registry.json
#   3. E2E scenario matrix execution (run_matrix.sh)
#   4. Unit gate execution (unit_gate_executor.sh)
#   5. Integration gate execution (integration_gate_executor.sh)
#   6. Coverage gate publication (coverage_gate_publication.sh)
#   7. Cross-gate aggregation and unified report
#   8. Forensics bundle validation
#
# Usage:
#   bash scripts/e2e/e2e_suite_runner.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --seed <seed>           Root deterministic seed (default: derived from run-id)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit commands/plan without executing
#   --skip-e2e              Skip E2E scenario matrix
#   --skip-unit-gate        Skip unit gate executor
#   --skip-integration-gate Skip integration gate executor
#   --skip-coverage-gate    Skip coverage gate publication
#   --skip-validation       Skip forensics bundle validation
#   --only-scenarios <csv>  Filter E2E scenarios (passed to run_matrix.sh)
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCHEMA_VERSION="asupersync-e2e-suite/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ROOT_SEED=""
OUT_ROOT=""
DRY_RUN=false
SKIP_E2E=false
SKIP_UNIT_GATE=false
SKIP_INTEGRATION_GATE=false
SKIP_COVERAGE_GATE=false
SKIP_VALIDATION=false
ONLY_SCENARIOS=""

# Gate statuses
E2E_STATUS="skipped"
UNIT_GATE_STATUS="skipped"
INTEGRATION_GATE_STATUS="skipped"
COVERAGE_GATE_STATUS="skipped"
VALIDATION_STATUS="skipped"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_suite_runner.sh [options]

Unified E2E Validation Suite Orchestrator — runs all scenario families, gates,
and produces an aggregated pass/fail report with artifact/replay links.

Options:
  --run-id <id>             Stable run identifier (default: UTC timestamp)
  --seed <seed>             Root deterministic seed (default: derived from run-id)
  --out-root <path>         Artifact root (default: artifacts/asupersync/suite/<run-id>)
  --dry-run                 Emit plan without executing
  --skip-e2e                Skip E2E scenario matrix
  --skip-unit-gate          Skip unit gate executor
  --skip-integration-gate   Skip integration gate executor
  --skip-coverage-gate      Skip coverage gate publication
  --skip-validation         Skip forensics bundle validation
  --only-scenarios <csv>    Filter E2E scenarios (comma-separated keys)
  -h, --help                Show this help
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: Missing required command: $1" >&2
    exit 1
  fi
}

now_iso() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

log_step() {
  local phase="$1"
  local msg="$2"
  printf '[%s] [%s] %s\n' "$(now_iso)" "${phase}" "${msg}"
}

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)       RUN_ID="$2"; shift 2;;
    --seed)         ROOT_SEED="$2"; shift 2;;
    --out-root)     OUT_ROOT="$2"; shift 2;;
    --dry-run)      DRY_RUN=true; shift;;
    --skip-e2e)     SKIP_E2E=true; shift;;
    --skip-unit-gate) SKIP_UNIT_GATE=true; shift;;
    --skip-integration-gate) SKIP_INTEGRATION_GATE=true; shift;;
    --skip-coverage-gate) SKIP_COVERAGE_GATE=true; shift;;
    --skip-validation) SKIP_VALIDATION=true; shift;;
    --only-scenarios) ONLY_SCENARIOS="$2"; shift 2;;
    -h|--help)      usage; exit 0;;
    *)              echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ───────────────────────────────────────────────────────────────
require_cmd jq
require_cmd bash

REGISTRY="${SCRIPT_DIR}/scenario_registry.json"
COVERAGE_MATRIX="${REPO_ROOT}/docs/ASUPERSYNC_Coverage_Matrix.json"

if [[ ! -f "${REGISTRY}" ]]; then
  echo "ERROR: scenario_registry.json not found at ${REGISTRY}" >&2
  exit 1
fi

if [[ -z "${ROOT_SEED}" ]]; then
  ROOT_SEED="${RUN_ID}"
fi

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/suite/${RUN_ID}"
fi

mkdir -p "${OUT_ROOT}"

SUITE_REPORT="${OUT_ROOT}/suite_report.json"
SUITE_CATALOG="${OUT_ROOT}/scenario_catalog.json"
SUITE_REPLAY="${OUT_ROOT}/replay.sh"
SUITE_STEPS="${OUT_ROOT}/steps.jsonl"

E2E_DIR="${OUT_ROOT}/e2e"
UNIT_GATE_DIR="${OUT_ROOT}/unit-gate"
INTEGRATION_GATE_DIR="${OUT_ROOT}/integration-gate"
COVERAGE_GATE_DIR="${OUT_ROOT}/coverage-gate"

log_step "INIT" "E2E Suite Runner v1 — run_id=${RUN_ID}, seed=${ROOT_SEED}"
log_step "INIT" "Artifact root: ${OUT_ROOT}"

# ── Phase 1: Scenario Catalog ────────────────────────────────────────────────
log_step "CATALOG" "Generating scenario catalog from registry"

jq '{
  schema_version: "asupersync-e2e-suite/v1",
  run_id: "'"${RUN_ID}"'",
  generated_at: "'"$(now_iso)"'",
  registry_version: .registry_version,
  total_scenarios: (.scenarios | length),
  required_scenarios: ([.scenarios[] | select(.required == true)] | length),
  optional_scenarios: ([.scenarios[] | select(.required == false)] | length),
  archetypes: ([.scenarios[].archetype] | unique | sort),
  failure_classes: ([.scenarios[].failure_class] | unique | sort),
  impact_categories: ([.scenarios[].user_impact_category] | unique | sort),
  scenarios: [.scenarios[] | {
    key: .key,
    scenario_id: .scenario_id,
    script: .script,
    required: .required,
    contract_id: .contract_id,
    archetype: .archetype,
    failure_class: .failure_class,
    user_impact_category: .user_impact_category
  }]
}' "${REGISTRY}" > "${SUITE_CATALOG}"

TOTAL_SCENARIOS=$(jq '.total_scenarios' "${SUITE_CATALOG}")
REQUIRED_SCENARIOS=$(jq '.required_scenarios' "${SUITE_CATALOG}")
log_step "CATALOG" "Catalog: ${TOTAL_SCENARIOS} scenarios (${REQUIRED_SCENARIOS} required)"

# Write initial step
{
  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "catalog" \
    --arg status "pass" \
    --arg description "Generated scenario catalog with ${TOTAL_SCENARIOS} scenarios" \
    --arg timestamp "$(now_iso)" \
    '{schema_version: $schema_version, run_id: $run_id, phase: $phase, status: $status, description: $description, timestamp: $timestamp}'
} > "${SUITE_STEPS}"

# ── Phase 2: E2E Scenario Matrix ─────────────────────────────────────────────
if [[ "${SKIP_E2E}" == "false" ]]; then
  log_step "E2E" "Running E2E scenario matrix"
  mkdir -p "${E2E_DIR}"

  E2E_ARGS=(
    --run-id "${RUN_ID}"
    --seed "${ROOT_SEED}"
    --out-root "${E2E_DIR}"
  )
  if [[ -n "${ONLY_SCENARIOS}" ]]; then
    E2E_ARGS+=(--only-scenarios "${ONLY_SCENARIOS}")
  fi
  if [[ "${DRY_RUN}" == "true" ]]; then
    E2E_ARGS+=(--dry-run)
  fi

  E2E_START=$(now_ms)
  if bash "${SCRIPT_DIR}/run_matrix.sh" "${E2E_ARGS[@]}"; then
    E2E_STATUS="pass"
  else
    E2E_STATUS="fail"
  fi
  E2E_END=$(now_ms)
  E2E_DURATION=$(( E2E_END - E2E_START ))

  # Extract summary from E2E output
  E2E_SUMMARY="${E2E_DIR}/summary.json"
  if [[ -f "${E2E_SUMMARY}" ]]; then
    E2E_PASS=$(jq -r '.pass // 0' "${E2E_SUMMARY}")
    E2E_FAIL=$(jq -r '.fail // 0' "${E2E_SUMMARY}")
    E2E_SKIP=$(jq -r '.skipped // 0' "${E2E_SUMMARY}")
    log_step "E2E" "Result: ${E2E_STATUS} (pass=${E2E_PASS}, fail=${E2E_FAIL}, skip=${E2E_SKIP}, ${E2E_DURATION}ms)"
  else
    E2E_PASS=0; E2E_FAIL=0; E2E_SKIP=0
    log_step "E2E" "Result: ${E2E_STATUS} (no summary.json found, ${E2E_DURATION}ms)"
  fi

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "e2e_matrix" \
    --arg status "${E2E_STATUS}" \
    --argjson duration_ms "${E2E_DURATION}" \
    --argjson pass "${E2E_PASS:-0}" \
    --argjson fail "${E2E_FAIL:-0}" \
    --argjson skip "${E2E_SKIP:-0}" \
    --arg timestamp "$(now_iso)" \
    '{schema_version: $schema_version, run_id: $run_id, phase: $phase, status: $status, duration_ms: $duration_ms, pass: $pass, fail: $fail, skip: $skip, timestamp: $timestamp}' \
    >> "${SUITE_STEPS}"
else
  log_step "E2E" "Skipped (--skip-e2e)"
fi

# ── Phase 3: Unit Gate ────────────────────────────────────────────────────────
if [[ "${SKIP_UNIT_GATE}" == "false" ]]; then
  log_step "UNIT" "Running unit gate executor"
  mkdir -p "${UNIT_GATE_DIR}"

  UNIT_ARGS=(
    --run-id "${RUN_ID}"
    --out-root "${UNIT_GATE_DIR}"
  )
  if [[ "${DRY_RUN}" == "true" ]]; then
    UNIT_ARGS+=(--dry-run)
  fi

  UNIT_START=$(now_ms)
  if bash "${SCRIPT_DIR}/unit_gate_executor.sh" "${UNIT_ARGS[@]}"; then
    UNIT_GATE_STATUS="pass"
  else
    UNIT_GATE_STATUS="fail"
  fi
  UNIT_END=$(now_ms)
  UNIT_DURATION=$(( UNIT_END - UNIT_START ))

  log_step "UNIT" "Result: ${UNIT_GATE_STATUS} (${UNIT_DURATION}ms)"

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "unit_gate" \
    --arg status "${UNIT_GATE_STATUS}" \
    --argjson duration_ms "${UNIT_DURATION}" \
    --arg timestamp "$(now_iso)" \
    '{schema_version: $schema_version, run_id: $run_id, phase: $phase, status: $status, duration_ms: $duration_ms, timestamp: $timestamp}' \
    >> "${SUITE_STEPS}"
else
  log_step "UNIT" "Skipped (--skip-unit-gate)"
fi

# ── Phase 4: Integration Gate ─────────────────────────────────────────────────
if [[ "${SKIP_INTEGRATION_GATE}" == "false" ]]; then
  log_step "INTEG" "Running integration gate executor"
  mkdir -p "${INTEGRATION_GATE_DIR}"

  INTEG_ARGS=(
    --run-id "${RUN_ID}"
    --out-root "${INTEGRATION_GATE_DIR}"
  )
  if [[ "${DRY_RUN}" == "true" ]]; then
    INTEG_ARGS+=(--dry-run)
  fi

  INTEG_START=$(now_ms)
  if bash "${SCRIPT_DIR}/integration_gate_executor.sh" "${INTEG_ARGS[@]}"; then
    INTEGRATION_GATE_STATUS="pass"
  else
    INTEGRATION_GATE_STATUS="fail"
  fi
  INTEG_END=$(now_ms)
  INTEG_DURATION=$(( INTEG_END - INTEG_START ))

  log_step "INTEG" "Result: ${INTEGRATION_GATE_STATUS} (${INTEG_DURATION}ms)"

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "integration_gate" \
    --arg status "${INTEGRATION_GATE_STATUS}" \
    --argjson duration_ms "${INTEG_DURATION}" \
    --arg timestamp "$(now_iso)" \
    '{schema_version: $schema_version, run_id: $run_id, phase: $phase, status: $status, duration_ms: $duration_ms, timestamp: $timestamp}' \
    >> "${SUITE_STEPS}"
else
  log_step "INTEG" "Skipped (--skip-integration-gate)"
fi

# ── Phase 5: Coverage Gate Publication ────────────────────────────────────────
if [[ "${SKIP_COVERAGE_GATE}" == "false" ]]; then
  log_step "COVER" "Running coverage gate publication"
  mkdir -p "${COVERAGE_GATE_DIR}"

  COVER_ARGS=(
    --run-id "${RUN_ID}"
    --out-root "${COVERAGE_GATE_DIR}"
  )
  if [[ "${DRY_RUN}" == "true" ]]; then
    COVER_ARGS+=(--dry-run)
  fi

  COVER_START=$(now_ms)
  if bash "${SCRIPT_DIR}/coverage_gate_publication.sh" "${COVER_ARGS[@]}"; then
    COVERAGE_GATE_STATUS="pass"
  else
    COVERAGE_GATE_STATUS="fail"
  fi
  COVER_END=$(now_ms)
  COVER_DURATION=$(( COVER_END - COVER_START ))

  log_step "COVER" "Result: ${COVERAGE_GATE_STATUS} (${COVER_DURATION}ms)"

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "coverage_gate" \
    --arg status "${COVERAGE_GATE_STATUS}" \
    --argjson duration_ms "${COVER_DURATION}" \
    --arg timestamp "$(now_iso)" \
    '{schema_version: $schema_version, run_id: $run_id, phase: $phase, status: $status, duration_ms: $duration_ms, timestamp: $timestamp}' \
    >> "${SUITE_STEPS}"
else
  log_step "COVER" "Skipped (--skip-coverage-gate)"
fi

# ── Phase 6: Forensics Bundle Validation ──────────────────────────────────────
if [[ "${SKIP_VALIDATION}" == "false" ]]; then
  log_step "VALID" "Running forensics bundle validation"

  VALID_START=$(now_ms)
  VALIDATION_STATUS="pass"

  # Validate E2E bundle if it exists
  if [[ -d "${E2E_DIR}" && -f "${E2E_DIR}/summary.json" ]]; then
    if ! bash "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" \
        --mode e2e-matrix --root "${E2E_DIR}" 2>/dev/null; then
      VALIDATION_STATUS="fail"
      log_step "VALID" "E2E bundle validation failed"
    fi
  fi

  # Validate integration gate bundle if it exists
  if [[ -d "${INTEGRATION_GATE_DIR}" && -f "${INTEGRATION_GATE_DIR}/gate_summary.json" ]]; then
    if ! bash "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" \
        --mode integration-gate --root "${INTEGRATION_GATE_DIR}" 2>/dev/null; then
      VALIDATION_STATUS="fail"
      log_step "VALID" "Integration gate bundle validation failed"
    fi
  fi

  VALID_END=$(now_ms)
  VALID_DURATION=$(( VALID_END - VALID_START ))

  log_step "VALID" "Result: ${VALIDATION_STATUS} (${VALID_DURATION}ms)"

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "forensics_validation" \
    --arg status "${VALIDATION_STATUS}" \
    --argjson duration_ms "${VALID_DURATION}" \
    --arg timestamp "$(now_iso)" \
    '{schema_version: $schema_version, run_id: $run_id, phase: $phase, status: $status, duration_ms: $duration_ms, timestamp: $timestamp}' \
    >> "${SUITE_STEPS}"
else
  log_step "VALID" "Skipped (--skip-validation)"
fi

# ── Phase 7: Aggregated Suite Report ──────────────────────────────────────────
log_step "REPORT" "Generating unified suite report"

# Determine overall status
OVERALL_STATUS="pass"
GATE_FAILURES=0
if [[ "${E2E_STATUS}" == "fail" ]]; then
  OVERALL_STATUS="fail"
  GATE_FAILURES=$((GATE_FAILURES + 1))
fi
if [[ "${UNIT_GATE_STATUS}" == "fail" ]]; then
  OVERALL_STATUS="fail"
  GATE_FAILURES=$((GATE_FAILURES + 1))
fi
if [[ "${INTEGRATION_GATE_STATUS}" == "fail" ]]; then
  OVERALL_STATUS="fail"
  GATE_FAILURES=$((GATE_FAILURES + 1))
fi
if [[ "${COVERAGE_GATE_STATUS}" == "fail" ]]; then
  OVERALL_STATUS="fail"
  GATE_FAILURES=$((GATE_FAILURES + 1))
fi
if [[ "${VALIDATION_STATUS}" == "fail" ]]; then
  OVERALL_STATUS="fail"
  GATE_FAILURES=$((GATE_FAILURES + 1))
fi

jq -n \
  --arg schema_version "${SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg seed "${ROOT_SEED}" \
  --arg overall_status "${OVERALL_STATUS}" \
  --argjson gate_failures "${GATE_FAILURES}" \
  --arg generated_at "$(now_iso)" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg e2e_status "${E2E_STATUS}" \
  --arg unit_gate_status "${UNIT_GATE_STATUS}" \
  --arg integration_gate_status "${INTEGRATION_GATE_STATUS}" \
  --arg coverage_gate_status "${COVERAGE_GATE_STATUS}" \
  --arg validation_status "${VALIDATION_STATUS}" \
  --argjson total_scenarios "${TOTAL_SCENARIOS}" \
  --argjson required_scenarios "${REQUIRED_SCENARIOS}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    seed: $seed,
    overall_status: $overall_status,
    gate_failures: $gate_failures,
    generated_at: $generated_at,
    gates: {
      e2e_matrix: { status: $e2e_status },
      unit_gate: { status: $unit_gate_status },
      integration_gate: { status: $integration_gate_status },
      coverage_gate: { status: $coverage_gate_status },
      forensics_validation: { status: $validation_status }
    },
    scenario_summary: {
      total: $total_scenarios,
      required: $required_scenarios
    },
    artifacts: {
      suite_report: "suite_report.json",
      scenario_catalog: "scenario_catalog.json",
      steps: "steps.jsonl",
      replay: "replay.sh",
      e2e: "e2e/",
      unit_gate: "unit-gate/",
      integration_gate: "integration-gate/",
      coverage_gate: "coverage-gate/"
    }
  }' > "${SUITE_REPORT}"

# ── Phase 8: Replay Script ───────────────────────────────────────────────────
log_step "REPLAY" "Generating replay script"

cat > "${SUITE_REPLAY}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay script for E2E Suite Run: ${RUN_ID}
# Generated: $(now_iso)
# Seed: ${ROOT_SEED}
set -euo pipefail

echo "=== Replaying E2E Suite: ${RUN_ID} ==="
echo "Seed: ${ROOT_SEED}"
echo ""

# Full suite replay:
bash scripts/e2e/e2e_suite_runner.sh \\
  --run-id "${RUN_ID}" \\
  --seed "${ROOT_SEED}"

# Individual gate replays:
# E2E scenarios only:
#   bash scripts/e2e/e2e_suite_runner.sh --run-id "${RUN_ID}" --seed "${ROOT_SEED}" --skip-unit-gate --skip-integration-gate --skip-coverage-gate
# Unit gate only:
#   bash scripts/e2e/e2e_suite_runner.sh --run-id "${RUN_ID}" --seed "${ROOT_SEED}" --skip-e2e --skip-integration-gate --skip-coverage-gate
# Integration gate only:
#   bash scripts/e2e/e2e_suite_runner.sh --run-id "${RUN_ID}" --seed "${ROOT_SEED}" --skip-e2e --skip-unit-gate --skip-coverage-gate
REPLAY_EOF
chmod +x "${SUITE_REPLAY}"

# ── Summary Output ───────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  E2E SUITE REPORT — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:     ${OVERALL_STATUS}"
echo "  Gate Failures:      ${GATE_FAILURES}"
echo ""
echo "  Gates:"
echo "    E2E Matrix:       ${E2E_STATUS}"
echo "    Unit Gate:        ${UNIT_GATE_STATUS}"
echo "    Integration Gate: ${INTEGRATION_GATE_STATUS}"
echo "    Coverage Gate:    ${COVERAGE_GATE_STATUS}"
echo "    Forensics Valid:  ${VALIDATION_STATUS}"
echo ""
echo "  Scenarios:          ${TOTAL_SCENARIOS} total (${REQUIRED_SCENARIOS} required)"
echo ""
echo "  Artifacts:          ${OUT_ROOT}/"
echo "    suite_report.json   — aggregated pass/fail"
echo "    scenario_catalog.json — scenario inventory"
echo "    steps.jsonl         — per-phase execution log"
echo "    replay.sh           — deterministic replay"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  exit 1
fi
