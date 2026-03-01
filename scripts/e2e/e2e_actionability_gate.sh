#!/usr/bin/env bash
# =============================================================================
# e2e_actionability_gate.sh — Actionability Gate + CI/Local Enforcement
# =============================================================================
# Bead:     235t.26.7.3 (ASUPERSYNC-FORENSICS Actionability Gate)
# Schema:   asupersync-actionability-gate/v1
#
# Final forensic actionability gate. Enforces:
#   1. Failure taxonomy quality — every failure has actionable taxonomy, not generic
#   2. Remediation clarity — failures link to contract IDs and rerun commands
#   3. Replay sufficiency — bundles contain complete replay artifacts
#   4. CI/local enforcement parity — identical gate semantics in both modes
#
# Consumes output from:
#   - e2e_quality_gate.sh (quality gate report + scenario verdicts)
#   - validate_asupersync_forensics_bundle.sh (forensics validator reports)
#   - coverage_gate_publication.sh (coverage gate report)
#   - e2e_suite_runner.sh (suite report)
#
# Usage:
#   bash scripts/e2e/e2e_actionability_gate.sh [options]
#
# Options:
#   --suite-root <path>         Suite artifact root (e2e_suite_runner output)
#   --quality-gate-root <path>  Quality gate artifact root
#   --run-id <id>               Stable run identifier
#   --out-root <path>           Actionability gate output directory
#   --registry <path>           Scenario registry JSON path
#   --ci                        CI mode (identical semantics, explicit flag)
#   --dry-run                   Emit plan without heavy validation
#   -h, --help                  Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-actionability-gate/v1"

SUITE_ROOT=""
QUALITY_GATE_ROOT=""
RUN_ID=""
OUT_ROOT=""
REGISTRY="${SCRIPT_DIR}/scenario_registry.json"
DRY_RUN=false
CI_MODE="${CI:-false}"

declare -i TOTAL_CHECKS=0
declare -i CHECKS_PASS=0
declare -i CHECKS_FAIL=0
declare -i CHECKS_WARN=0
declare -a FINDINGS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_actionability_gate.sh [options]

Actionability Gate + CI/Local Enforcement

Enforces actionable failure diagnostics, remediation clarity, and
replay sufficiency across all ASUPERSYNC forensic evidence bundles.
CI and local runs enforce identical gate semantics.

Options:
  --suite-root <path>         Suite artifact root (e2e_suite_runner output)
  --quality-gate-root <path>  Quality gate artifact root
  --run-id <id>               Stable run identifier (auto-discovered if omitted)
  --out-root <path>           Actionability gate output directory
  --registry <path>           Scenario registry JSON path
  --ci                        CI mode (identical semantics, explicit flag)
  --dry-run                   Emit plan without heavy validation
  -h, --help                  Show this help
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

log_gate() {
  printf '[%s] [ACTIONABILITY/%s] %s\n' "$(now_iso)" "$1" "$2"
}

add_finding() {
  local check="$1"
  local severity="$2"
  local message="$3"
  local path="${4:-}"
  local remediation="${5:-}"
  local f
  f="$(jq -c -n \
    --arg check "${check}" \
    --arg severity "${severity}" \
    --arg message "${message}" \
    --arg path "${path}" \
    --arg remediation "${remediation}" \
    '{
      check: $check,
      severity: $severity,
      message: $message,
      path: (if ($path | length) > 0 then $path else null end),
      remediation: (if ($remediation | length) > 0 then $remediation else null end)
    }')"
  FINDINGS+=("${f}")
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  if [[ "${severity}" == "error" ]]; then
    CHECKS_FAIL=$((CHECKS_FAIL + 1))
  elif [[ "${severity}" == "warning" ]]; then
    CHECKS_WARN=$((CHECKS_WARN + 1))
  else
    CHECKS_PASS=$((CHECKS_PASS + 1))
  fi
}

pass_check() {
  local check="$1"
  local detail="${2:-}"
  TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
  CHECKS_PASS=$((CHECKS_PASS + 1))
  if [[ -n "${detail}" ]]; then
    add_finding "${check}" "pass" "${detail}"
  fi
}

record_step() {
  local phase="$1" status="$2" detail="$3" duration_ms="${4:-0}"
  jq -c -n \
    --arg schema_version "${GATE_SCHEMA}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "${phase}" \
    --arg status "${status}" \
    --arg detail "${detail}" \
    --argjson duration_ms "${duration_ms}" \
    --arg timestamp "$(now_iso)" \
    '{schema_version: $schema_version, run_id: $run_id, phase: $phase, status: $status, detail: $detail, duration_ms: $duration_ms, timestamp: $timestamp}' \
    >> "${STEPS_FILE}"
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --suite-root)         SUITE_ROOT="$2"; shift 2;;
    --quality-gate-root)  QUALITY_GATE_ROOT="$2"; shift 2;;
    --run-id)             RUN_ID="$2"; shift 2;;
    --out-root)           OUT_ROOT="$2"; shift 2;;
    --registry)           REGISTRY="$2"; shift 2;;
    --ci)                 CI_MODE=true; shift;;
    --dry-run)            DRY_RUN=true; shift;;
    -h|--help)            usage; exit 0;;
    *)                    echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd bash

if [[ -n "${SUITE_ROOT}" && ! -d "${SUITE_ROOT}" ]]; then
  echo "ERROR: suite root does not exist: ${SUITE_ROOT}" >&2
  exit 2
fi
if [[ -n "${SUITE_ROOT}" ]]; then
  SUITE_ROOT="$(cd "${SUITE_ROOT}" && pwd)"
fi

# Auto-discover run_id
if [[ -z "${RUN_ID}" ]]; then
  for candidate_dir in "${QUALITY_GATE_ROOT}" "${SUITE_ROOT}"; do
    [[ -z "${candidate_dir}" ]] && continue
    for candidate_file in "quality_gate_report.json" "suite_report.json" "summary.json"; do
      if [[ -f "${candidate_dir}/${candidate_file}" ]]; then
        RUN_ID="$(jq -r '.run_id // empty' "${candidate_dir}/${candidate_file}" 2>/dev/null || true)"
        [[ -n "${RUN_ID}" ]] && break 2
      fi
    done
  done
fi
if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
fi

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/actionability-gate/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}"

GATE_REPORT="${OUT_ROOT}/actionability_gate_report.json"
STEPS_FILE="${OUT_ROOT}/steps.jsonl"
VERDICT_FILE="${OUT_ROOT}/consolidated_verdict.json"
REPLAY_SCRIPT="${OUT_ROOT}/replay.sh"

: > "${STEPS_FILE}"

log_gate "INIT" "Actionability Gate v1 — run_id=${RUN_ID}, ci=${CI_MODE}"
log_gate "INIT" "Output: ${OUT_ROOT}"

# ── Taxonomy of generic / non-actionable failure reasons ────────────────────
GENERIC_REASONS='["fail","failed","error","unknown","failure","err","timeout","crash"]'

# =============================================================================
# Phase 1: Failure Taxonomy Quality
# =============================================================================
log_gate "TAXONOMY" "Phase 1: Validating failure taxonomy quality"
P1_START=$(now_ms)

TAXONOMY_CHECKED=0
TAXONOMY_PASS=0
TAXONOMY_FAIL=0

# Check quality gate violations for non-actionable failures
if [[ -n "${QUALITY_GATE_ROOT}" && -f "${QUALITY_GATE_ROOT}/quality_gate_report.json" ]]; then
  qg_report="${QUALITY_GATE_ROOT}/quality_gate_report.json"

  # Check that quality gate itself passed
  qg_status="$(jq -r '.overall_status' "${qg_report}" 2>/dev/null || echo "unknown")"
  TAXONOMY_CHECKED=$((TAXONOMY_CHECKED + 1))
  if [[ "${qg_status}" == "pass" ]]; then
    TAXONOMY_PASS=$((TAXONOMY_PASS + 1))
    pass_check "taxonomy.quality_gate_status" "Quality gate passed"
  else
    add_finding "taxonomy.quality_gate_status" "error" \
      "Quality gate overall_status=${qg_status} — downstream gates require passing quality gate" \
      "${qg_report}" \
      "Re-run: bash scripts/e2e/e2e_quality_gate.sh --suite-root <suite-root>"
    TAXONOMY_FAIL=$((TAXONOMY_FAIL + 1))
  fi

  # Check for generic failure reasons in violations
  violation_count="$(jq '.violations | length' "${qg_report}" 2>/dev/null || echo 0)"
  if (( violation_count > 0 )); then
    generic_violations="$(jq --argjson generics "${GENERIC_REASONS}" \
      '[.violations[] | select(.severity == "error") | select(.message | ascii_downcase | IN($generics[]))] | length' \
      "${qg_report}" 2>/dev/null || echo 0)"

    TAXONOMY_CHECKED=$((TAXONOMY_CHECKED + 1))
    if (( generic_violations > 0 )); then
      add_finding "taxonomy.generic_violation_messages" "error" \
        "${generic_violations} quality gate violations use generic failure messages" \
        "${qg_report}" \
        "Update failure messages with actionable taxonomy (contract_id, error_code, rerun_command)"
      TAXONOMY_FAIL=$((TAXONOMY_FAIL + 1))
    else
      TAXONOMY_PASS=$((TAXONOMY_PASS + 1))
      pass_check "taxonomy.violation_messages" "All violation messages are specific"
    fi
  fi

  # Check scenario verdicts have reasons for failures
  if [[ -f "${QUALITY_GATE_ROOT}/scenario_verdicts.json" ]]; then
    verdict_fails="$(jq '[.scenarios[] | select(.verdict == "fail")] | length' \
      "${QUALITY_GATE_ROOT}/scenario_verdicts.json" 2>/dev/null || echo 0)"
    verdict_fails_with_reason="$(jq '[.scenarios[] | select(.verdict == "fail" and .reason != null and (.reason | length) > 0)] | length' \
      "${QUALITY_GATE_ROOT}/scenario_verdicts.json" 2>/dev/null || echo 0)"

    TAXONOMY_CHECKED=$((TAXONOMY_CHECKED + 1))
    if (( verdict_fails > 0 && verdict_fails != verdict_fails_with_reason )); then
      missing=$((verdict_fails - verdict_fails_with_reason))
      add_finding "taxonomy.verdict_reasons" "error" \
        "${missing} of ${verdict_fails} failed scenarios missing failure reason" \
        "${QUALITY_GATE_ROOT}/scenario_verdicts.json" \
        "Review scenario_verdicts.json for scenarios with verdict=fail and null reason"
      TAXONOMY_FAIL=$((TAXONOMY_FAIL + 1))
    else
      TAXONOMY_PASS=$((TAXONOMY_PASS + 1))
      pass_check "taxonomy.verdict_reasons" "All failed scenarios have reasons"
    fi
  fi
fi

# Check E2E results for actionable failure reasons
if [[ -n "${SUITE_ROOT}" ]]; then
  e2e_results=""
  if [[ -f "${SUITE_ROOT}/e2e/results.jsonl" ]]; then
    e2e_results="${SUITE_ROOT}/e2e/results.jsonl"
  elif [[ -f "${SUITE_ROOT}/e2e/summary.jsonl" ]]; then
    e2e_results="${SUITE_ROOT}/e2e/summary.jsonl"
  fi

  if [[ -n "${e2e_results}" ]]; then
    # Count failures and check reasons
    failed_scenarios="$(jq -c 'select(.status == "fail")' "${e2e_results}" 2>/dev/null || true)"
    if [[ -n "${failed_scenarios}" ]]; then
      total_failed=0
      generic_reasons=0
      missing_reasons=0
      while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        total_failed=$((total_failed + 1))
        reason="$(jq -r '.reason // ""' <<< "${line}")"
        if [[ -z "${reason}" ]]; then
          missing_reasons=$((missing_reasons + 1))
        else
          reason_lower="$(printf '%s' "${reason}" | tr '[:upper:]' '[:lower:]')"
          case "${reason_lower}" in
            fail|failed|error|unknown|failure|err|timeout|crash)
              generic_reasons=$((generic_reasons + 1))
              ;;
          esac
        fi
      done <<< "${failed_scenarios}"

      TAXONOMY_CHECKED=$((TAXONOMY_CHECKED + 1))
      if (( missing_reasons > 0 || generic_reasons > 0 )); then
        add_finding "taxonomy.e2e_failure_reasons" "error" \
          "E2E results: ${missing_reasons} missing + ${generic_reasons} generic reasons out of ${total_failed} failures" \
          "${e2e_results}" \
          "Update E2E scripts to emit specific failure taxonomy (error_code + context)"
        TAXONOMY_FAIL=$((TAXONOMY_FAIL + 1))
      else
        TAXONOMY_PASS=$((TAXONOMY_PASS + 1))
        pass_check "taxonomy.e2e_failure_reasons" "All E2E failures have specific reasons"
      fi
    fi
  fi
fi

P1_END=$(now_ms)
P1_DURATION=$((P1_END - P1_START))
P1_STATUS="pass"
if (( TAXONOMY_FAIL > 0 )); then P1_STATUS="fail"; fi
log_gate "TAXONOMY" "Taxonomy checks: pass=${TAXONOMY_PASS}, fail=${TAXONOMY_FAIL}, total=${TAXONOMY_CHECKED} (${P1_DURATION}ms)"
record_step "failure_taxonomy" "${P1_STATUS}" \
  "pass=${TAXONOMY_PASS}, fail=${TAXONOMY_FAIL}, total=${TAXONOMY_CHECKED}" "${P1_DURATION}"

# =============================================================================
# Phase 2: Remediation Clarity
# =============================================================================
log_gate "REMEDIATION" "Phase 2: Validating remediation linkage"
P2_START=$(now_ms)

REMED_CHECKED=0
REMED_PASS=0
REMED_FAIL=0

# Check that failed scenarios link to contract IDs
if [[ -n "${QUALITY_GATE_ROOT}" && -f "${QUALITY_GATE_ROOT}/scenario_verdicts.json" ]]; then
  failed_no_contract="$(jq '[.scenarios[] | select(.verdict == "fail" and (.contract_id == null or .contract_id == ""))] | length' \
    "${QUALITY_GATE_ROOT}/scenario_verdicts.json" 2>/dev/null || echo 0)"
  failed_total="$(jq '[.scenarios[] | select(.verdict == "fail")] | length' \
    "${QUALITY_GATE_ROOT}/scenario_verdicts.json" 2>/dev/null || echo 0)"

  REMED_CHECKED=$((REMED_CHECKED + 1))
  if (( failed_no_contract > 0 )); then
    add_finding "remediation.contract_linkage" "error" \
      "${failed_no_contract} of ${failed_total} failed scenarios missing contract_id for remediation" \
      "${QUALITY_GATE_ROOT}/scenario_verdicts.json" \
      "Ensure scenario_registry.json has contract_id for every scenario"
    REMED_FAIL=$((REMED_FAIL + 1))
  else
    REMED_PASS=$((REMED_PASS + 1))
    pass_check "remediation.contract_linkage" "All failed scenarios link to contracts"
  fi
fi

# Check that E2E failures have replay_command
if [[ -n "${SUITE_ROOT}" && -f "${SUITE_ROOT}/e2e/results.jsonl" ]]; then
  fail_no_replay="$(jq -c 'select(.status == "fail" and (.replay_command == null or .replay_command == ""))' \
    "${SUITE_ROOT}/e2e/results.jsonl" 2>/dev/null | wc -l | tr -d ' ')"

  REMED_CHECKED=$((REMED_CHECKED + 1))
  if (( fail_no_replay > 0 )); then
    add_finding "remediation.replay_command" "error" \
      "${fail_no_replay} failed E2E scenarios missing replay_command" \
      "${SUITE_ROOT}/e2e/results.jsonl" \
      "E2E scripts must emit replay_command in results for every executed scenario"
    REMED_FAIL=$((REMED_FAIL + 1))
  else
    REMED_PASS=$((REMED_PASS + 1))
    pass_check "remediation.replay_command" "All failed scenarios have replay commands"
  fi
fi

# Check that failure index exists with actionable entries
if [[ -n "${SUITE_ROOT}" && -f "${SUITE_ROOT}/e2e/failure_index.json" ]]; then
  REMED_CHECKED=$((REMED_CHECKED + 1))
  if jq -e '.' "${SUITE_ROOT}/e2e/failure_index.json" >/dev/null 2>&1; then
    REMED_PASS=$((REMED_PASS + 1))
    pass_check "remediation.failure_index" "Failure index exists and is valid JSON"
  else
    add_finding "remediation.failure_index" "error" \
      "failure_index.json is malformed" \
      "${SUITE_ROOT}/e2e/failure_index.json" \
      "Check e2e_suite_runner.sh failure index generation"
    REMED_FAIL=$((REMED_FAIL + 1))
  fi
fi

# Check rerun_failed.sh exists and is actionable
if [[ -n "${SUITE_ROOT}" && -f "${SUITE_ROOT}/e2e/rerun_failed.sh" ]]; then
  REMED_CHECKED=$((REMED_CHECKED + 1))
  if [[ -x "${SUITE_ROOT}/e2e/rerun_failed.sh" ]]; then
    REMED_PASS=$((REMED_PASS + 1))
    pass_check "remediation.rerun_script" "rerun_failed.sh is executable"
  else
    add_finding "remediation.rerun_script" "warning" \
      "rerun_failed.sh is not executable" \
      "${SUITE_ROOT}/e2e/rerun_failed.sh" \
      "chmod +x scripts/e2e equivalent in bundle"
    REMED_FAIL=$((REMED_FAIL + 1))
  fi
fi

P2_END=$(now_ms)
P2_DURATION=$((P2_END - P2_START))
P2_STATUS="pass"
if (( REMED_FAIL > 0 )); then P2_STATUS="fail"; fi
log_gate "REMEDIATION" "Remediation checks: pass=${REMED_PASS}, fail=${REMED_FAIL}, total=${REMED_CHECKED} (${P2_DURATION}ms)"
record_step "remediation_clarity" "${P2_STATUS}" \
  "pass=${REMED_PASS}, fail=${REMED_FAIL}, total=${REMED_CHECKED}" "${P2_DURATION}"

# =============================================================================
# Phase 3: Replay Sufficiency
# =============================================================================
log_gate "REPLAY" "Phase 3: Validating replay sufficiency"
P3_START=$(now_ms)

REPLAY_CHECKED=0
REPLAY_PASS=0
REPLAY_FAIL=0

check_replay_bundle() {
  local label="$1"
  local root="$2"
  local mode="$3"

  REPLAY_CHECKED=$((REPLAY_CHECKED + 1))

  # Run the forensics validator in the appropriate mode
  local validator_report="${root}/forensics_validator_report.json"
  if [[ -f "${validator_report}" ]]; then
    validator_passed="$(jq -r '.passed' "${validator_report}" 2>/dev/null || echo "false")"
    if [[ "${validator_passed}" == "true" ]]; then
      REPLAY_PASS=$((REPLAY_PASS + 1))
      pass_check "replay.${label}" "Forensics validator passed for ${label}"
      return 0
    else
      issue_count="$(jq -r '.issue_count // 0' "${validator_report}" 2>/dev/null || echo 0)"
      add_finding "replay.${label}" "error" \
        "Forensics validator for ${label} failed: ${issue_count} issues" \
        "${validator_report}" \
        "bash scripts/e2e/validate_asupersync_forensics_bundle.sh --mode ${mode} --root ${root}"
      REPLAY_FAIL=$((REPLAY_FAIL + 1))
      return 1
    fi
  fi

  # No cached report — run validation
  if [[ "${DRY_RUN}" == "true" ]]; then
    REPLAY_PASS=$((REPLAY_PASS + 1))
    pass_check "replay.${label}" "Dry-run: skipped forensics validation for ${label}"
    return 0
  fi

  if bash "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" \
      --mode "${mode}" --root "${root}" --run-id "${RUN_ID}" \
      --report "${validator_report}" >/dev/null 2>&1; then
    REPLAY_PASS=$((REPLAY_PASS + 1))
    pass_check "replay.${label}" "Forensics validation passed for ${label}"
  else
    add_finding "replay.${label}" "error" \
      "Forensics validation failed for ${label}" \
      "${validator_report}" \
      "bash scripts/e2e/validate_asupersync_forensics_bundle.sh --mode ${mode} --root ${root}"
    REPLAY_FAIL=$((REPLAY_FAIL + 1))
  fi
}

# Validate each available bundle
if [[ -n "${SUITE_ROOT}" ]]; then
  check_replay_bundle "suite" "${SUITE_ROOT}" "suite"
  [[ -d "${SUITE_ROOT}/e2e" ]] && check_replay_bundle "e2e" "${SUITE_ROOT}/e2e" "e2e-matrix"
  [[ -d "${SUITE_ROOT}/unit-gate" ]] && check_replay_bundle "unit_gate" "${SUITE_ROOT}/unit-gate" "unit-gate"
  [[ -d "${SUITE_ROOT}/integration-gate" ]] && check_replay_bundle "integ_gate" "${SUITE_ROOT}/integration-gate" "integration-gate"
fi
if [[ -n "${QUALITY_GATE_ROOT}" ]]; then
  check_replay_bundle "quality_gate" "${QUALITY_GATE_ROOT}" "quality-gate"
fi

P3_END=$(now_ms)
P3_DURATION=$((P3_END - P3_START))
P3_STATUS="pass"
if (( REPLAY_FAIL > 0 )); then P3_STATUS="fail"; fi
log_gate "REPLAY" "Replay checks: pass=${REPLAY_PASS}, fail=${REPLAY_FAIL}, total=${REPLAY_CHECKED} (${P3_DURATION}ms)"
record_step "replay_sufficiency" "${P3_STATUS}" \
  "pass=${REPLAY_PASS}, fail=${REPLAY_FAIL}, total=${REPLAY_CHECKED}" "${P3_DURATION}"

# =============================================================================
# Phase 4: CI/Local Enforcement Parity
# =============================================================================
log_gate "PARITY" "Phase 4: Validating CI/local enforcement parity"
P4_START=$(now_ms)

PARITY_CHECKED=0
PARITY_PASS=0
PARITY_FAIL=0

# Verify that gate scripts exist and have consistent interfaces
GATE_SCRIPTS=(
  "e2e_suite_runner.sh"
  "e2e_quality_gate.sh"
  "e2e_actionability_gate.sh"
  "validate_asupersync_forensics_bundle.sh"
  "coverage_gate_publication.sh"
  "unit_gate_executor.sh"
  "integration_gate_executor.sh"
)

for script in "${GATE_SCRIPTS[@]}"; do
  script_path="${SCRIPT_DIR}/${script}"
  PARITY_CHECKED=$((PARITY_CHECKED + 1))
  if [[ ! -f "${script_path}" ]]; then
    add_finding "parity.script_missing" "error" \
      "Gate script missing: ${script}" \
      "${script_path}" \
      "Create or restore scripts/e2e/${script}"
    PARITY_FAIL=$((PARITY_FAIL + 1))
    continue
  fi

  # Verify shebang and strict mode
  first_line="$(head -n 1 "${script_path}")"
  if [[ "${first_line}" != "#!/usr/bin/env bash" ]]; then
    add_finding "parity.script_shebang" "warning" \
      "${script}: missing standard bash shebang" \
      "${script_path}"
    PARITY_FAIL=$((PARITY_FAIL + 1))
    continue
  fi

  if ! grep -q '^set -euo pipefail$' "${script_path}"; then
    add_finding "parity.script_strict" "warning" \
      "${script}: missing strict shell options (set -euo pipefail)" \
      "${script_path}"
    PARITY_FAIL=$((PARITY_FAIL + 1))
    continue
  fi

  PARITY_PASS=$((PARITY_PASS + 1))
done

# Verify scenario registry is valid and complete
PARITY_CHECKED=$((PARITY_CHECKED + 1))
if [[ -f "${REGISTRY}" ]]; then
  if jq -e '. | type == "object" and (.scenarios | type == "array") and (.scenarios | length) > 0' "${REGISTRY}" >/dev/null 2>&1; then
    scenario_total="$(jq '.scenarios | length' "${REGISTRY}")"
    required_total="$(jq '[.scenarios[] | select(.required)] | length' "${REGISTRY}")"
    PARITY_PASS=$((PARITY_PASS + 1))
    pass_check "parity.registry" "Scenario registry valid: ${scenario_total} scenarios (${required_total} required)"
  else
    add_finding "parity.registry" "error" \
      "Scenario registry is malformed or empty" \
      "${REGISTRY}" \
      "Validate with: jq . scripts/e2e/scenario_registry.json"
    PARITY_FAIL=$((PARITY_FAIL + 1))
  fi
else
  add_finding "parity.registry" "error" \
    "Scenario registry missing" \
    "${REGISTRY}"
  PARITY_FAIL=$((PARITY_FAIL + 1))
fi

# Verify logging standard doc exists
PARITY_CHECKED=$((PARITY_CHECKED + 1))
LOGGING_STANDARD="${REPO_ROOT}/docs/ASUPERSYNC_Logging_Forensics_Standard.md"
if [[ -f "${LOGGING_STANDARD}" ]]; then
  PARITY_PASS=$((PARITY_PASS + 1))
  pass_check "parity.logging_standard" "Logging forensics standard document exists"
else
  add_finding "parity.logging_standard" "warning" \
    "Logging forensics standard document missing" \
    "${LOGGING_STANDARD}"
  PARITY_FAIL=$((PARITY_FAIL + 1))
fi

P4_END=$(now_ms)
P4_DURATION=$((P4_END - P4_START))
P4_STATUS="pass"
if (( PARITY_FAIL > 0 )); then P4_STATUS="fail"; fi
log_gate "PARITY" "Parity checks: pass=${PARITY_PASS}, fail=${PARITY_FAIL}, total=${PARITY_CHECKED} (${P4_DURATION}ms)"
record_step "ci_local_parity" "${P4_STATUS}" \
  "pass=${PARITY_PASS}, fail=${PARITY_FAIL}, total=${PARITY_CHECKED}" "${P4_DURATION}"

# =============================================================================
# Phase 5: Consolidated Verdict
# =============================================================================
log_gate "VERDICT" "Phase 5: Generating consolidated verdict"

OVERALL_STATUS="pass"
ERROR_COUNT=$((TAXONOMY_FAIL + REMED_FAIL + REPLAY_FAIL + PARITY_FAIL))
if (( ERROR_COUNT > 0 )); then
  OVERALL_STATUS="fail"
fi

FINDINGS_JSON='[]'
if (( ${#FINDINGS[@]} > 0 )); then
  FINDINGS_JSON="$(printf '%s\n' "${FINDINGS[@]}" | jq -s 'sort_by(.check, .severity)')"
fi

# Consolidated verdict for UX/OPS/cutover consumers
jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg overall_status "${OVERALL_STATUS}" \
  --argjson ci_mode "${CI_MODE}" \
  --arg taxonomy_status "${P1_STATUS}" \
  --arg remediation_status "${P2_STATUS}" \
  --arg replay_status "${P3_STATUS}" \
  --arg parity_status "${P4_STATUS}" \
  --argjson error_count "${ERROR_COUNT}" \
  --argjson warning_count "${CHECKS_WARN}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    actionability_verdict: {
      failure_taxonomy: $taxonomy_status,
      remediation_clarity: $remediation_status,
      replay_sufficiency: $replay_status,
      ci_local_parity: $parity_status
    },
    errors: $error_count,
    warnings: $warning_count,
    consumer_guidance: {
      ux_gate: "Check failure_taxonomy + remediation_clarity phases for user-facing diagnostic quality",
      ops_gate: "Check replay_sufficiency phase for incident replay readiness",
      cutover_gate: "All 4 phases must pass for migration cutover approval",
      remediation: "Each finding includes a remediation field with actionable fix command"
    }
  }' > "${VERDICT_FILE}"

# Full gate report
jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg overall_status "${OVERALL_STATUS}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson error_count "${ERROR_COUNT}" \
  --argjson warning_count "${CHECKS_WARN}" \
  --argjson total_checks "${TOTAL_CHECKS}" \
  --arg taxonomy_status "${P1_STATUS}" \
  --argjson taxonomy_pass "${TAXONOMY_PASS}" \
  --argjson taxonomy_fail "${TAXONOMY_FAIL}" \
  --argjson taxonomy_total "${TAXONOMY_CHECKED}" \
  --arg remediation_status "${P2_STATUS}" \
  --argjson remediation_pass "${REMED_PASS}" \
  --argjson remediation_fail "${REMED_FAIL}" \
  --argjson remediation_total "${REMED_CHECKED}" \
  --arg replay_status "${P3_STATUS}" \
  --argjson replay_pass "${REPLAY_PASS}" \
  --argjson replay_fail "${REPLAY_FAIL}" \
  --argjson replay_total "${REPLAY_CHECKED}" \
  --arg parity_status "${P4_STATUS}" \
  --argjson parity_pass "${PARITY_PASS}" \
  --argjson parity_fail "${PARITY_FAIL}" \
  --argjson parity_total "${PARITY_CHECKED}" \
  --argjson findings "${FINDINGS_JSON}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    summary: {
      errors: $error_count,
      warnings: $warning_count,
      total_checks: $total_checks
    },
    phases: {
      failure_taxonomy: {
        status: $taxonomy_status,
        pass: $taxonomy_pass,
        fail: $taxonomy_fail,
        total: $taxonomy_total
      },
      remediation_clarity: {
        status: $remediation_status,
        pass: $remediation_pass,
        fail: $remediation_fail,
        total: $remediation_total
      },
      replay_sufficiency: {
        status: $replay_status,
        pass: $replay_pass,
        fail: $replay_fail,
        total: $replay_total
      },
      ci_local_parity: {
        status: $parity_status,
        pass: $parity_pass,
        fail: $parity_fail,
        total: $parity_total
      }
    },
    findings: $findings,
    artifacts: {
      actionability_gate_report: "actionability_gate_report.json",
      consolidated_verdict: "consolidated_verdict.json",
      steps: "steps.jsonl",
      replay: "replay.sh"
    }
  }' > "${GATE_REPORT}"

# ── Replay script ───────────────────────────────────────────────────────────
cat > "${REPLAY_SCRIPT}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay script for Actionability Gate Run: ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Actionability Gate: ${RUN_ID} ==="

bash scripts/e2e/e2e_actionability_gate.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}" \\
  --registry "${REGISTRY}"$(
  [[ -n "${SUITE_ROOT}" ]] && printf ' \\\n  --suite-root "%s"' "${SUITE_ROOT}"
  [[ -n "${QUALITY_GATE_ROOT}" ]] && printf ' \\\n  --quality-gate-root "%s"' "${QUALITY_GATE_ROOT}"
  )
REPLAY_EOF
chmod +x "${REPLAY_SCRIPT}"

# ── Summary Output ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  ACTIONABILITY GATE REPORT — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:         ${OVERALL_STATUS}"
echo "  CI Mode:                ${CI_MODE}"
echo "  Errors:                 ${ERROR_COUNT}"
echo "  Warnings:               ${CHECKS_WARN}"
echo ""
echo "  Phases:"
echo "    Failure Taxonomy:     ${P1_STATUS} (pass=${TAXONOMY_PASS}, fail=${TAXONOMY_FAIL})"
echo "    Remediation Clarity:  ${P2_STATUS} (pass=${REMED_PASS}, fail=${REMED_FAIL})"
echo "    Replay Sufficiency:   ${P3_STATUS} (pass=${REPLAY_PASS}, fail=${REPLAY_FAIL})"
echo "    CI/Local Parity:      ${P4_STATUS} (pass=${PARITY_PASS}, fail=${PARITY_FAIL})"
echo ""
echo "  Artifacts:              ${OUT_ROOT}/"
echo "    actionability_gate_report.json  — full gate report"
echo "    consolidated_verdict.json       — consumer-ready verdict (UX/OPS/cutover)"
echo "    steps.jsonl                     — per-phase execution log"
echo "    replay.sh                       — deterministic replay"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  echo ""
  echo "  Top findings requiring remediation:"
  jq -r '.findings[:8][] | select(.severity == "error") | "  - [\(.check)] \(.message)\(if .remediation then "\n    Fix: \(.remediation)" else "" end)"' \
    "${GATE_REPORT}" 2>/dev/null || true
  echo ""
  exit 1
fi
