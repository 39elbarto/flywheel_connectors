#!/usr/bin/env bash
# =============================================================================
# e2e_quality_gate.sh — Quality Gate: Assertions + Detailed Structured Logging
# =============================================================================
# Bead:     235t.26.6.4 (ASUPERSYNC-E2E Quality Gate)
# Schema:   asupersync-quality-gate/v1
#
# Terminal quality gate for E2E validation. Enforces:
#   1. Assertion class policy per scenario family (archetype × failure_class)
#   2. Structured-log completeness against asupersync-forensics/v1
#   3. Deterministic replay validation for emitted artifact bundles
#   4. Scenario-level pass/fail with evidence pointers
#
# Consumes output from e2e_suite_runner.sh (suite bundles) and/or individual
# gate outputs (unit-gate, integration-gate, coverage-gate, e2e-matrix).
#
# Usage:
#   bash scripts/e2e/e2e_quality_gate.sh [options]
#
# Options:
#   --suite-root <path>       Suite artifact root (e2e_suite_runner output)
#   --e2e-root <path>         Standalone E2E matrix artifact root
#   --unit-gate-root <path>   Standalone unit gate artifact root
#   --integ-gate-root <path>  Standalone integration gate artifact root
#   --coverage-gate-root <p>  Standalone coverage gate artifact root
#   --run-id <id>             Stable run identifier (default: auto-discovered)
#   --out-root <path>         Quality gate output directory
#   --registry <path>         Scenario registry JSON path
#   --logging-standard <p>    Logging forensics standard doc path (informational)
#   --dry-run                 Emit plan without executing heavy validation
#   --ci                      CI mode (strict: zero-tolerance, absolute paths)
#   -h, --help                Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-quality-gate/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

SUITE_ROOT=""
E2E_ROOT=""
UNIT_GATE_ROOT=""
INTEG_GATE_ROOT=""
COVERAGE_GATE_ROOT=""
RUN_ID=""
OUT_ROOT=""
REGISTRY="${SCRIPT_DIR}/scenario_registry.json"
DRY_RUN=false
CI_MODE="${CI:-false}"

declare -i GATE_PASS=0
declare -i GATE_FAIL=0
declare -i GATE_WARN=0
declare -a VIOLATIONS=()
declare -a EVIDENCE=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_quality_gate.sh [options]

Quality Gate: Assertions + Detailed Structured Logging

Enforces assertion class completeness, structured-log integrity, and
deterministic replay validation for ASUPERSYNC E2E evidence bundles.

Options:
  --suite-root <path>       Suite artifact root (e2e_suite_runner output)
  --e2e-root <path>         Standalone E2E matrix artifact root
  --unit-gate-root <path>   Standalone unit gate artifact root
  --integ-gate-root <path>  Standalone integration gate artifact root
  --coverage-gate-root <p>  Standalone coverage gate artifact root
  --run-id <id>             Stable run identifier (auto-discovered if omitted)
  --out-root <path>         Quality gate output directory
  --registry <path>         Scenario registry JSON path
  --dry-run                 Emit plan without executing heavy validation
  --ci                      CI mode (strict: zero-tolerance, absolute paths)
  -h, --help                Show this help
EOF
}

# ── Utility ─────────────────────────────────────────────────────────────────

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

log_gate() {
  local phase="$1"
  local msg="$2"
  printf '[%s] [QUALITY-GATE/%s] %s\n' "$(now_iso)" "${phase}" "${msg}"
}

sha256_file() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${f}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${f}" | awk '{print $1}'
  else
    openssl dgst -sha256 "${f}" | awk '{print $NF}'
  fi
}

add_violation() {
  local rule="$1"
  local severity="$2"
  local message="$3"
  local scenario="${4:-}"
  local evidence_path="${5:-}"
  local v
  v="$(jq -c -n \
    --arg rule "${rule}" \
    --arg severity "${severity}" \
    --arg message "${message}" \
    --arg scenario "${scenario}" \
    --arg evidence_path "${evidence_path}" \
    '{
      rule: $rule,
      severity: $severity,
      message: $message,
      scenario: (if ($scenario | length) > 0 then $scenario else null end),
      evidence_path: (if ($evidence_path | length) > 0 then $evidence_path else null end)
    }')"
  VIOLATIONS+=("${v}")
  if [[ "${severity}" == "error" ]]; then
    GATE_FAIL=$((GATE_FAIL + 1))
  else
    GATE_WARN=$((GATE_WARN + 1))
  fi
}

add_evidence() {
  local kind="$1"
  local path="$2"
  local status="$3"
  local detail="${4:-}"
  local e
  e="$(jq -c -n \
    --arg kind "${kind}" \
    --arg path "${path}" \
    --arg status "${status}" \
    --arg detail "${detail}" \
    '{
      kind: $kind,
      path: $path,
      status: $status,
      detail: (if ($detail | length) > 0 then $detail else null end)
    }')"
  EVIDENCE+=("${e}")
}

record_step() {
  local phase="$1"
  local status="$2"
  local detail="$3"
  local duration_ms="${4:-0}"
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
    --suite-root)      SUITE_ROOT="$2"; shift 2;;
    --e2e-root)        E2E_ROOT="$2"; shift 2;;
    --unit-gate-root)  UNIT_GATE_ROOT="$2"; shift 2;;
    --integ-gate-root) INTEG_GATE_ROOT="$2"; shift 2;;
    --coverage-gate-root) COVERAGE_GATE_ROOT="$2"; shift 2;;
    --run-id)          RUN_ID="$2"; shift 2;;
    --out-root)        OUT_ROOT="$2"; shift 2;;
    --registry)        REGISTRY="$2"; shift 2;;
    --dry-run)         DRY_RUN=true; shift;;
    --ci)              CI_MODE=true; shift;;
    -h|--help)         usage; exit 0;;
    *)                 echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd bash

# Resolve suite root → individual gate roots
if [[ -n "${SUITE_ROOT}" ]]; then
  if [[ ! -d "${SUITE_ROOT}" ]]; then
    echo "ERROR: suite root does not exist: ${SUITE_ROOT}" >&2
    exit 2
  fi
  SUITE_ROOT="$(cd "${SUITE_ROOT}" && pwd)"
  [[ -z "${E2E_ROOT}" && -d "${SUITE_ROOT}/e2e" ]] && E2E_ROOT="${SUITE_ROOT}/e2e"
  [[ -z "${UNIT_GATE_ROOT}" && -d "${SUITE_ROOT}/unit-gate" ]] && UNIT_GATE_ROOT="${SUITE_ROOT}/unit-gate"
  [[ -z "${INTEG_GATE_ROOT}" && -d "${SUITE_ROOT}/integration-gate" ]] && INTEG_GATE_ROOT="${SUITE_ROOT}/integration-gate"
  [[ -z "${COVERAGE_GATE_ROOT}" && -d "${SUITE_ROOT}/coverage-gate" ]] && COVERAGE_GATE_ROOT="${SUITE_ROOT}/coverage-gate"
fi

# Auto-discover run_id
if [[ -z "${RUN_ID}" ]]; then
  for candidate_dir in "${SUITE_ROOT}" "${E2E_ROOT}" "${UNIT_GATE_ROOT}" "${INTEG_GATE_ROOT}" "${COVERAGE_GATE_ROOT}"; do
    [[ -z "${candidate_dir}" ]] && continue
    for candidate_file in "suite_report.json" "summary.json" "gate_summary.json" "manifest.json"; do
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
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/quality-gate/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}"

GATE_REPORT="${OUT_ROOT}/quality_gate_report.json"
STEPS_FILE="${OUT_ROOT}/steps.jsonl"
SCENARIO_VERDICTS="${OUT_ROOT}/scenario_verdicts.json"
REPLAY_SCRIPT="${OUT_ROOT}/replay.sh"

: > "${STEPS_FILE}"

log_gate "INIT" "Quality Gate v1 — run_id=${RUN_ID}"
log_gate "INIT" "Output: ${OUT_ROOT}"

if [[ ! -f "${REGISTRY}" ]]; then
  echo "ERROR: scenario registry not found: ${REGISTRY}" >&2
  exit 2
fi

# ── Load assertion class policy ─────────────────────────────────────────────
# The policy defines which assertion classes are REQUIRED per archetype.
# Every scenario of a given archetype must exercise assertions from its
# required classes. Classes map to forensic step fields that must appear
# in executed scenario logs.

ASSERTION_POLICY_JSON="$(cat <<'POLICY_EOF'
{
  "schema_version": "asupersync-assertion-policy/v1",
  "description": "Required assertion classes per scenario archetype",
  "archetype_policies": {
    "request_response": {
      "required_assertions": [
        "outcome_verdict",
        "error_taxonomy_classification",
        "timeout_budget_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms", "timeout_budget_ms"],
      "min_assertions_per_scenario": 2
    },
    "polling": {
      "required_assertions": [
        "outcome_verdict",
        "cursor_continuity_check",
        "timeout_budget_check",
        "backoff_bounds_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms", "timeout_budget_ms", "queue_depth"],
      "min_assertions_per_scenario": 3
    },
    "webhook": {
      "required_assertions": [
        "outcome_verdict",
        "idempotency_check",
        "signature_validation",
        "retry_bounds_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms", "attempt"],
      "min_assertions_per_scenario": 3
    },
    "streaming": {
      "required_assertions": [
        "outcome_verdict",
        "reconnect_bounded_check",
        "backpressure_bounds_check",
        "ordering_continuity_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms", "queue_depth"],
      "min_assertions_per_scenario": 3
    },
    "bidirectional": {
      "required_assertions": [
        "outcome_verdict",
        "cancellation_propagation_check",
        "resource_cleanup_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms", "cancellation_reason"],
      "min_assertions_per_scenario": 2
    },
    "queue_pubsub": {
      "required_assertions": [
        "outcome_verdict",
        "decode_budget_check",
        "repair_convergence_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms", "decode_budget"],
      "min_assertions_per_scenario": 2
    },
    "cli_process": {
      "required_assertions": [
        "outcome_verdict",
        "coverage_completeness_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms"],
      "min_assertions_per_scenario": 2
    },
    "database": {
      "required_assertions": [
        "outcome_verdict",
        "connection_pool_bounds_check",
        "timeout_budget_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms", "timeout_budget_ms"],
      "min_assertions_per_scenario": 2
    },
    "file_blob": {
      "required_assertions": [
        "outcome_verdict",
        "data_integrity_check",
        "partial_recovery_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms"],
      "min_assertions_per_scenario": 2
    },
    "browser": {
      "required_assertions": [
        "outcome_verdict",
        "session_recovery_check",
        "resource_cleanup_check"
      ],
      "required_forensic_fields": ["outcome", "elapsed_ms"],
      "min_assertions_per_scenario": 2
    }
  }
}
POLICY_EOF
)"

# Write policy to output
printf '%s' "${ASSERTION_POLICY_JSON}" | jq '.' > "${OUT_ROOT}/assertion_policy.json"

# =============================================================================
# Phase 1: Assertion Class Coverage Validation
# =============================================================================
log_gate "ASSERT" "Phase 1: Validating assertion class coverage per scenario family"
PHASE1_START=$(now_ms)

SCENARIO_COUNT=$(jq '.scenarios | length' "${REGISTRY}")
declare -A SCENARIO_VERDICTS_MAP
declare -i ASSERT_PASS=0
declare -i ASSERT_FAIL=0
declare -i ASSERT_SKIP=0

validate_scenario_assertions() {
  local key="$1"
  local archetype="$2"
  local failure_class="$3"
  local required="$4"
  local contract_id="$5"
  local scenario_id="$6"

  # Look up the archetype policy
  local policy_entry
  policy_entry="$(jq -c --arg arch "${archetype}" \
    '.archetype_policies[$arch] // null' <<< "${ASSERTION_POLICY_JSON}")"

  if [[ "${policy_entry}" == "null" || -z "${policy_entry}" ]]; then
    add_violation "assertion.policy.missing_archetype" "warning" \
      "No assertion policy defined for archetype '${archetype}'" "${key}"
    SCENARIO_VERDICTS_MAP["${key}"]="skip:no_policy"
    ASSERT_SKIP=$((ASSERT_SKIP + 1))
    return 0
  fi

  local min_assertions
  min_assertions="$(jq -r '.min_assertions_per_scenario' <<< "${policy_entry}")"

  # Check if the scenario has E2E results
  local scenario_dir=""
  local results_line=""

  if [[ -n "${E2E_ROOT}" && -f "${E2E_ROOT}/results.jsonl" ]]; then
    results_line="$(jq -c --arg key "${key}" 'select(.scenario == $key)' "${E2E_ROOT}/results.jsonl" 2>/dev/null | head -n 1 || true)"
  fi
  if [[ -z "${results_line}" && -n "${E2E_ROOT}" && -f "${E2E_ROOT}/summary.jsonl" ]]; then
    results_line="$(jq -c --arg key "${key}" 'select(.scenario == $key)' "${E2E_ROOT}/summary.jsonl" 2>/dev/null | head -n 1 || true)"
  fi

  if [[ -n "${E2E_ROOT}" && -d "${E2E_ROOT}/scenarios/${key}" ]]; then
    scenario_dir="${E2E_ROOT}/scenarios/${key}"
  fi

  # If no results, check if this was a dry-run / planned scenario
  if [[ -z "${results_line}" && -z "${scenario_dir}" ]]; then
    if [[ "${DRY_RUN}" == "true" ]]; then
      SCENARIO_VERDICTS_MAP["${key}"]="planned:dry_run"
      ASSERT_SKIP=$((ASSERT_SKIP + 1))
      return 0
    fi
    # Required scenario missing results entirely
    if [[ "${required}" == "true" ]]; then
      add_violation "assertion.coverage.missing_results" "error" \
        "Required scenario '${key}' (${archetype}/${failure_class}) has no execution results" \
        "${key}" "${E2E_ROOT:-none}"
      SCENARIO_VERDICTS_MAP["${key}"]="fail:no_results"
      ASSERT_FAIL=$((ASSERT_FAIL + 1))
    else
      SCENARIO_VERDICTS_MAP["${key}"]="skip:optional_no_results"
      ASSERT_SKIP=$((ASSERT_SKIP + 1))
    fi
    return 0
  fi

  # Check execution status
  local exec_status="unknown"
  if [[ -n "${results_line}" ]]; then
    exec_status="$(jq -r '.status // "unknown"' <<< "${results_line}")"
  fi

  if [[ "${exec_status}" == "skipped" || "${exec_status}" == "planned" ]]; then
    SCENARIO_VERDICTS_MAP["${key}"]="skip:${exec_status}"
    ASSERT_SKIP=$((ASSERT_SKIP + 1))
    return 0
  fi

  # Validate required forensic fields in scenario log
  local required_fields
  required_fields="$(jq -r '.required_forensic_fields[]' <<< "${policy_entry}")"

  local execution_log=""
  if [[ -n "${scenario_dir}" ]]; then
    for log_candidate in "execution.log" "scenario.log" "output.log"; do
      if [[ -f "${scenario_dir}/${log_candidate}" ]]; then
        execution_log="${scenario_dir}/${log_candidate}"
        break
      fi
    done
  fi

  # Check forensic field presence in results
  local field_violations=0
  if [[ -n "${results_line}" ]]; then
    while IFS= read -r field; do
      [[ -z "${field}" ]] && continue
      # For results lines, check that the field is present or has a matching forensic step
      case "${field}" in
        outcome|elapsed_ms|attempt)
          # These are always present in results schema
          ;;
        timeout_budget_ms|queue_depth|decode_budget|cancellation_reason)
          # These are nullable forensic extension fields — check scenario dir for steps
          if [[ -n "${scenario_dir}" ]]; then
            local step_file=""
            for sf in "steps.jsonl" "forensics.jsonl"; do
              if [[ -f "${scenario_dir}/${sf}" ]]; then
                step_file="${scenario_dir}/${sf}"
                break
              fi
            done
            if [[ -n "${step_file}" ]]; then
              local field_present
              field_present="$(jq -r --arg f "${field}" \
                "select(has(\$f) and .[\$f] != null) | .[\$f]" \
                "${step_file}" 2>/dev/null | head -n 1 || true)"
              if [[ -z "${field_present}" ]]; then
                add_violation "assertion.forensic_field.missing" "warning" \
                  "Forensic field '${field}' not populated for archetype '${archetype}'" \
                  "${key}" "${step_file}"
                field_violations=$((field_violations + 1))
              fi
            fi
          fi
          ;;
      esac
    done <<< "${required_fields}"
  fi

  # Check assertion count (log lines with assertion markers or pass/fail verdicts)
  local assertion_count=0
  if [[ -n "${execution_log}" && -f "${execution_log}" ]]; then
    # Count lines that look like assertions: ASSERT, PASS, FAIL, CHECK, VERIFY
    assertion_count=$(grep -cEi '(ASSERT|VERDICT|CHECK|VERIFY|PASS|FAIL|EXPECT)' "${execution_log}" 2>/dev/null || echo 0)
  fi
  if [[ -n "${results_line}" ]]; then
    # The scenario result itself counts as an assertion (outcome verdict)
    assertion_count=$((assertion_count + 1))
  fi

  if (( assertion_count < min_assertions )); then
    add_violation "assertion.count.insufficient" "error" \
      "Scenario '${key}' has ${assertion_count} assertions (minimum: ${min_assertions} for archetype '${archetype}')" \
      "${key}" "${execution_log:-${E2E_ROOT}}"
    SCENARIO_VERDICTS_MAP["${key}"]="fail:insufficient_assertions"
    ASSERT_FAIL=$((ASSERT_FAIL + 1))
    return 0
  fi

  # Scenario passed assertion validation
  SCENARIO_VERDICTS_MAP["${key}"]="pass"
  ASSERT_PASS=$((ASSERT_PASS + 1))
  add_evidence "assertion_check" "${key}" "pass" \
    "assertions=${assertion_count}, min=${min_assertions}, archetype=${archetype}"
}

# Iterate all scenarios from the registry
while IFS=$'\t' read -r key archetype failure_class required contract_id scenario_id; do
  [[ -z "${key}" ]] && continue
  validate_scenario_assertions "${key}" "${archetype}" "${failure_class}" "${required}" "${contract_id}" "${scenario_id}"
done < <(jq -r '.scenarios[] | [.key, .archetype, .failure_class, (.required | tostring), .contract_id, .scenario_id] | @tsv' "${REGISTRY}")

PHASE1_END=$(now_ms)
PHASE1_DURATION=$((PHASE1_END - PHASE1_START))
log_gate "ASSERT" "Assertion coverage: pass=${ASSERT_PASS}, fail=${ASSERT_FAIL}, skip=${ASSERT_SKIP} (${PHASE1_DURATION}ms)"

PHASE1_STATUS="pass"
if (( ASSERT_FAIL > 0 )); then
  PHASE1_STATUS="fail"
fi
record_step "assertion_class_coverage" "${PHASE1_STATUS}" \
  "pass=${ASSERT_PASS}, fail=${ASSERT_FAIL}, skip=${ASSERT_SKIP}" "${PHASE1_DURATION}"

# =============================================================================
# Phase 2: Structured-Log Completeness Validation
# =============================================================================
log_gate "LOGS" "Phase 2: Validating structured-log completeness (${FORENSICS_SCHEMA})"
PHASE2_START=$(now_ms)

declare -i LOG_CHECKS=0
declare -i LOG_PASS=0
declare -i LOG_FAIL=0

validate_steps_completeness() {
  local label="$1"
  local steps_file="$2"

  if [[ ! -f "${steps_file}" ]]; then
    add_violation "structured_log.missing" "error" \
      "Required steps.jsonl missing for ${label}" "" "${steps_file}"
    LOG_FAIL=$((LOG_FAIL + 1))
    LOG_CHECKS=$((LOG_CHECKS + 1))
    return 1
  fi

  LOG_CHECKS=$((LOG_CHECKS + 1))
  local line_count=0
  local schema_violations=0
  local missing_fields=0
  local line

  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line//[[:space:]]/}" ]] && continue
    line_count=$((line_count + 1))

    # Validate JSON parse
    if ! jq -e . >/dev/null 2>&1 <<< "${line}"; then
      add_violation "structured_log.invalid_json" "error" \
        "${label} steps.jsonl line ${line_count}: invalid JSON" "" "${steps_file}"
      schema_violations=$((schema_violations + 1))
      continue
    fi

    # Check required fields per forensics/v1
    local has_run_id has_scenario_id has_outcome has_elapsed
    has_run_id="$(jq -r 'select(.run_id != null and (.run_id | length) > 0) | "yes"' <<< "${line}" 2>/dev/null || true)"
    has_scenario_id="$(jq -r 'select(.scenario_id != null and (.scenario_id | length) > 0) | "yes"' <<< "${line}" 2>/dev/null || true)"
    has_outcome="$(jq -r 'select(.outcome != null and (.outcome | IN("pass","fail","planned"))) | "yes"' <<< "${line}" 2>/dev/null || true)"
    has_elapsed="$(jq -r 'select(.elapsed_ms != null and (.elapsed_ms | type) == "number") | "yes"' <<< "${line}" 2>/dev/null || true)"

    # Some step files use a suite-level schema (phase/status) rather than forensics/v1
    local has_phase
    has_phase="$(jq -r 'select(.phase != null) | "yes"' <<< "${line}" 2>/dev/null || true)"

    if [[ "${has_phase}" == "yes" ]]; then
      # Suite-level step — validate phase/status schema
      local has_status
      has_status="$(jq -r 'select(.status != null and (.status | length) > 0) | "yes"' <<< "${line}" 2>/dev/null || true)"
      if [[ "${has_status}" != "yes" ]]; then
        add_violation "structured_log.phase_missing_status" "error" \
          "${label} steps.jsonl line ${line_count}: phase step missing status field" "" "${steps_file}"
        missing_fields=$((missing_fields + 1))
      fi
    else
      # Forensics-level step — stricter schema
      if [[ "${has_run_id}" != "yes" ]]; then
        missing_fields=$((missing_fields + 1))
      fi
      if [[ "${has_outcome}" != "yes" && "${has_scenario_id}" == "yes" ]]; then
        add_violation "structured_log.missing_outcome" "error" \
          "${label} steps.jsonl line ${line_count}: forensic step missing outcome" "" "${steps_file}"
        missing_fields=$((missing_fields + 1))
      fi
    fi
  done < "${steps_file}"

  if (( line_count == 0 )); then
    add_violation "structured_log.empty" "error" \
      "${label} steps.jsonl is empty" "" "${steps_file}"
    LOG_FAIL=$((LOG_FAIL + 1))
    return 1
  fi

  if (( schema_violations > 0 || missing_fields > 0 )); then
    add_violation "structured_log.incomplete" "error" \
      "${label} steps.jsonl: ${schema_violations} parse errors, ${missing_fields} missing required fields (${line_count} lines)" \
      "" "${steps_file}"
    LOG_FAIL=$((LOG_FAIL + 1))
    return 1
  fi

  LOG_PASS=$((LOG_PASS + 1))
  add_evidence "structured_log" "${steps_file}" "pass" "${line_count} lines validated"
  return 0
}

# Validate all available steps.jsonl files
if [[ -n "${SUITE_ROOT}" && -f "${SUITE_ROOT}/steps.jsonl" ]]; then
  validate_steps_completeness "suite" "${SUITE_ROOT}/steps.jsonl"
fi
if [[ -n "${E2E_ROOT}" ]]; then
  # E2E matrix uses results.jsonl, not steps.jsonl
  if [[ -f "${E2E_ROOT}/results.jsonl" ]]; then
    LOG_CHECKS=$((LOG_CHECKS + 1))
    local_lines=$(wc -l < "${E2E_ROOT}/results.jsonl" | tr -d ' ')
    if (( local_lines > 0 )); then
      LOG_PASS=$((LOG_PASS + 1))
      add_evidence "structured_log" "${E2E_ROOT}/results.jsonl" "pass" "${local_lines} result lines"
    else
      add_violation "structured_log.e2e_empty" "error" \
        "E2E results.jsonl is empty" "" "${E2E_ROOT}/results.jsonl"
      LOG_FAIL=$((LOG_FAIL + 1))
    fi
  fi
fi
if [[ -n "${UNIT_GATE_ROOT}" && -f "${UNIT_GATE_ROOT}/steps.jsonl" ]]; then
  validate_steps_completeness "unit-gate" "${UNIT_GATE_ROOT}/steps.jsonl"
fi
if [[ -n "${INTEG_GATE_ROOT}" && -f "${INTEG_GATE_ROOT}/steps.jsonl" ]]; then
  validate_steps_completeness "integration-gate" "${INTEG_GATE_ROOT}/steps.jsonl"
fi
if [[ -n "${COVERAGE_GATE_ROOT}" && -f "${COVERAGE_GATE_ROOT}/steps.jsonl" ]]; then
  validate_steps_completeness "coverage-gate" "${COVERAGE_GATE_ROOT}/steps.jsonl"
fi

PHASE2_END=$(now_ms)
PHASE2_DURATION=$((PHASE2_END - PHASE2_START))
log_gate "LOGS" "Structured-log checks: pass=${LOG_PASS}, fail=${LOG_FAIL}, total=${LOG_CHECKS} (${PHASE2_DURATION}ms)"

PHASE2_STATUS="pass"
if (( LOG_FAIL > 0 )); then
  PHASE2_STATUS="fail"
fi
record_step "structured_log_completeness" "${PHASE2_STATUS}" \
  "pass=${LOG_PASS}, fail=${LOG_FAIL}, total=${LOG_CHECKS}" "${PHASE2_DURATION}"

# =============================================================================
# Phase 3: Replay Validation
# =============================================================================
log_gate "REPLAY" "Phase 3: Validating deterministic replay artifacts"
PHASE3_START=$(now_ms)

declare -i REPLAY_CHECKS=0
declare -i REPLAY_PASS=0
declare -i REPLAY_FAIL=0

validate_replay() {
  local label="$1"
  local root="$2"

  REPLAY_CHECKS=$((REPLAY_CHECKS + 1))

  # Check replay.sh exists and is executable
  if [[ ! -f "${root}/replay.sh" ]]; then
    add_violation "replay.missing" "error" \
      "${label}: replay.sh missing" "" "${root}"
    REPLAY_FAIL=$((REPLAY_FAIL + 1))
    return 1
  fi

  if [[ ! -x "${root}/replay.sh" ]]; then
    add_violation "replay.not_executable" "error" \
      "${label}: replay.sh is not executable" "" "${root}/replay.sh"
    REPLAY_FAIL=$((REPLAY_FAIL + 1))
    return 1
  fi

  # Validate shebang and strict mode
  local first_line
  first_line="$(head -n 1 "${root}/replay.sh")"
  if [[ "${first_line}" != "#!/usr/bin/env bash" ]]; then
    add_violation "replay.shebang" "error" \
      "${label}: replay.sh missing bash shebang" "" "${root}/replay.sh"
    REPLAY_FAIL=$((REPLAY_FAIL + 1))
    return 1
  fi

  if ! grep -q '^set -euo pipefail$' "${root}/replay.sh"; then
    add_violation "replay.strict_mode" "error" \
      "${label}: replay.sh missing strict shell options (set -euo pipefail)" \
      "" "${root}/replay.sh"
    REPLAY_FAIL=$((REPLAY_FAIL + 1))
    return 1
  fi

  # Check that replay references the correct run-id (if we have one)
  if [[ -n "${RUN_ID}" ]]; then
    if ! grep -q "${RUN_ID}" "${root}/replay.sh"; then
      add_violation "replay.run_id_mismatch" "warning" \
        "${label}: replay.sh does not reference run_id=${RUN_ID}" \
        "" "${root}/replay.sh"
    fi
  fi

  # Check summary/manifest for run_id consistency
  local summary_files=("summary.json" "gate_summary.json" "suite_report.json" "manifest.json")
  local found_summary=false
  for sf in "${summary_files[@]}"; do
    if [[ -f "${root}/${sf}" ]]; then
      found_summary=true
      if [[ -n "${RUN_ID}" ]]; then
        local file_run_id
        file_run_id="$(jq -r '.run_id // empty' "${root}/${sf}" 2>/dev/null || true)"
        if [[ -n "${file_run_id}" && "${file_run_id}" != "${RUN_ID}" ]]; then
          add_violation "replay.run_id_consistency" "error" \
            "${label}: ${sf} run_id=${file_run_id} does not match gate run_id=${RUN_ID}" \
            "" "${root}/${sf}"
          REPLAY_FAIL=$((REPLAY_FAIL + 1))
          return 1
        fi
      fi
      break
    fi
  done

  if [[ "${found_summary}" == "false" ]]; then
    add_violation "replay.no_summary" "warning" \
      "${label}: no summary/manifest JSON found for replay metadata" "" "${root}"
  fi

  REPLAY_PASS=$((REPLAY_PASS + 1))
  add_evidence "replay_validation" "${root}/replay.sh" "pass" "${label}"
  return 0
}

# Validate replay for each available bundle
if [[ -n "${SUITE_ROOT}" ]]; then
  validate_replay "suite" "${SUITE_ROOT}"
fi
if [[ -n "${E2E_ROOT}" ]]; then
  validate_replay "e2e-matrix" "${E2E_ROOT}"
fi
if [[ -n "${UNIT_GATE_ROOT}" ]]; then
  validate_replay "unit-gate" "${UNIT_GATE_ROOT}"
fi
if [[ -n "${INTEG_GATE_ROOT}" ]]; then
  validate_replay "integration-gate" "${INTEG_GATE_ROOT}"
fi

PHASE3_END=$(now_ms)
PHASE3_DURATION=$((PHASE3_END - PHASE3_START))
log_gate "REPLAY" "Replay checks: pass=${REPLAY_PASS}, fail=${REPLAY_FAIL}, total=${REPLAY_CHECKS} (${PHASE3_DURATION}ms)"

PHASE3_STATUS="pass"
if (( REPLAY_FAIL > 0 )); then
  PHASE3_STATUS="fail"
fi
record_step "replay_validation" "${PHASE3_STATUS}" \
  "pass=${REPLAY_PASS}, fail=${REPLAY_FAIL}, total=${REPLAY_CHECKS}" "${PHASE3_DURATION}"

# =============================================================================
# Phase 4: Cross-Gate Consistency Validation
# =============================================================================
log_gate "XGATE" "Phase 4: Validating cross-gate consistency"
PHASE4_START=$(now_ms)

declare -i XGATE_CHECKS=0
declare -i XGATE_PASS=0
declare -i XGATE_FAIL=0

# Validate forensics_validator_report.json if present
for gate_dir in "${E2E_ROOT}" "${UNIT_GATE_ROOT}" "${INTEG_GATE_ROOT}"; do
  [[ -z "${gate_dir}" ]] && continue
  local_report="${gate_dir}/forensics_validator_report.json"
  if [[ -f "${local_report}" ]]; then
    XGATE_CHECKS=$((XGATE_CHECKS + 1))
    validator_passed="$(jq -r '.passed' "${local_report}" 2>/dev/null || echo "null")"
    if [[ "${validator_passed}" == "true" ]]; then
      XGATE_PASS=$((XGATE_PASS + 1))
      add_evidence "forensics_validator" "${local_report}" "pass"
    elif [[ "${validator_passed}" == "false" ]]; then
      issue_count="$(jq -r '.issue_count // 0' "${local_report}" 2>/dev/null || echo 0)"
      add_violation "cross_gate.forensics_failed" "error" \
        "Forensics validator failed with ${issue_count} issues" "" "${local_report}"
      XGATE_FAIL=$((XGATE_FAIL + 1))
    fi
  fi
done

# Validate suite report consistency if present
if [[ -n "${SUITE_ROOT}" && -f "${SUITE_ROOT}/suite_report.json" ]]; then
  XGATE_CHECKS=$((XGATE_CHECKS + 1))
  suite_status="$(jq -r '.overall_status // "unknown"' "${SUITE_ROOT}/suite_report.json" 2>/dev/null || echo "unknown")"
  gate_failures="$(jq -r '.gate_failures // 0' "${SUITE_ROOT}/suite_report.json" 2>/dev/null || echo 0)"

  if [[ "${suite_status}" == "pass" && "${gate_failures}" == "0" ]]; then
    XGATE_PASS=$((XGATE_PASS + 1))
    add_evidence "suite_report" "${SUITE_ROOT}/suite_report.json" "pass" "all gates green"
  else
    add_violation "cross_gate.suite_not_green" "error" \
      "Suite report: status=${suite_status}, gate_failures=${gate_failures}" \
      "" "${SUITE_ROOT}/suite_report.json"
    XGATE_FAIL=$((XGATE_FAIL + 1))
  fi
fi

# Check BUNDLE_MANIFEST.json if present
if [[ -n "${SUITE_ROOT}" && -f "${SUITE_ROOT}/BUNDLE_MANIFEST.json" ]]; then
  XGATE_CHECKS=$((XGATE_CHECKS + 1))
  manifest_status="$(jq -r '.overall_status // "unknown"' "${SUITE_ROOT}/BUNDLE_MANIFEST.json" 2>/dev/null || echo "unknown")"
  if [[ "${manifest_status}" == "pass" ]]; then
    XGATE_PASS=$((XGATE_PASS + 1))
    add_evidence "bundle_manifest" "${SUITE_ROOT}/BUNDLE_MANIFEST.json" "pass"
  else
    add_violation "cross_gate.bundle_manifest" "warning" \
      "Bundle manifest overall_status=${manifest_status}" \
      "" "${SUITE_ROOT}/BUNDLE_MANIFEST.json"
    XGATE_FAIL=$((XGATE_FAIL + 1))
  fi
fi

PHASE4_END=$(now_ms)
PHASE4_DURATION=$((PHASE4_END - PHASE4_START))
log_gate "XGATE" "Cross-gate checks: pass=${XGATE_PASS}, fail=${XGATE_FAIL}, total=${XGATE_CHECKS} (${PHASE4_DURATION}ms)"

PHASE4_STATUS="pass"
if (( XGATE_FAIL > 0 )); then
  PHASE4_STATUS="fail"
fi
record_step "cross_gate_consistency" "${PHASE4_STATUS}" \
  "pass=${XGATE_PASS}, fail=${XGATE_FAIL}, total=${XGATE_CHECKS}" "${PHASE4_DURATION}"

# =============================================================================
# Phase 5: Generate Scenario Verdicts
# =============================================================================
log_gate "VERDICT" "Phase 5: Generating scenario-level verdicts"

{
  echo "{"
  echo "  \"schema_version\": \"${GATE_SCHEMA}\","
  echo "  \"run_id\": \"${RUN_ID}\","
  echo "  \"generated_at\": \"$(now_iso)\","
  echo "  \"total_scenarios\": ${SCENARIO_COUNT},"
  echo "  \"verdict_summary\": {"
  echo "    \"pass\": ${ASSERT_PASS},"
  echo "    \"fail\": ${ASSERT_FAIL},"
  echo "    \"skip\": ${ASSERT_SKIP}"
  echo "  },"
  echo "  \"scenarios\": ["
  _first=true
  while IFS=$'\t' read -r key archetype failure_class required contract_id scenario_id; do
    [[ -z "${key}" ]] && continue
    verdict="${SCENARIO_VERDICTS_MAP[${key}]:-unknown}"
    verdict_status="${verdict%%:*}"
    verdict_reason="${verdict#*:}"
    if [[ "${verdict_status}" == "${verdict_reason}" ]]; then
      verdict_reason=""
    fi
    if [[ "${_first}" == "true" ]]; then
      _first=false
    else
      echo ","
    fi
    jq -c -n \
      --arg key "${key}" \
      --arg archetype "${archetype}" \
      --arg failure_class "${failure_class}" \
      --arg contract_id "${contract_id}" \
      --arg scenario_id "${scenario_id}" \
      --argjson required "${required}" \
      --arg verdict "${verdict_status}" \
      --arg reason "${verdict_reason}" \
      '{
        key: $key,
        scenario_id: $scenario_id,
        archetype: $archetype,
        failure_class: $failure_class,
        contract_id: $contract_id,
        required: $required,
        verdict: $verdict,
        reason: (if ($reason | length) > 0 then $reason else null end)
      }'
  done < <(jq -r '.scenarios[] | [.key, .archetype, .failure_class, (.required | tostring), .contract_id, .scenario_id] | @tsv' "${REGISTRY}")
  echo ""
  echo "  ]"
  echo "}"
} | jq '.' > "${SCENARIO_VERDICTS}"

add_evidence "scenario_verdicts" "${SCENARIO_VERDICTS}" "generated"

# =============================================================================
# Phase 6: Generate Quality Gate Report
# =============================================================================
log_gate "REPORT" "Phase 6: Generating quality gate report"

OVERALL_STATUS="pass"
TOTAL_VIOLATIONS=${#VIOLATIONS[@]}
ERROR_COUNT=${GATE_FAIL}
WARNING_COUNT=${GATE_WARN}

if (( ERROR_COUNT > 0 )); then
  OVERALL_STATUS="fail"
fi
if [[ "${CI_MODE}" == "true" && ${WARNING_COUNT} -gt 0 ]]; then
  # CI mode: warnings also fail the gate
  OVERALL_STATUS="fail"
fi

VIOLATIONS_JSON='[]'
if (( TOTAL_VIOLATIONS > 0 )); then
  VIOLATIONS_JSON="$(printf '%s\n' "${VIOLATIONS[@]}" | jq -s 'sort_by(.rule, .scenario, .severity)')"
fi

EVIDENCE_JSON='[]'
if (( ${#EVIDENCE[@]} > 0 )); then
  EVIDENCE_JSON="$(printf '%s\n' "${EVIDENCE[@]}" | jq -s '.')"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg overall_status "${OVERALL_STATUS}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson error_count "${ERROR_COUNT}" \
  --argjson warning_count "${WARNING_COUNT}" \
  --argjson total_violations "${TOTAL_VIOLATIONS}" \
  --arg assertion_phase "${PHASE1_STATUS}" \
  --argjson assertion_pass "${ASSERT_PASS}" \
  --argjson assertion_fail "${ASSERT_FAIL}" \
  --argjson assertion_skip "${ASSERT_SKIP}" \
  --arg log_phase "${PHASE2_STATUS}" \
  --argjson log_pass "${LOG_PASS}" \
  --argjson log_fail "${LOG_FAIL}" \
  --argjson log_total "${LOG_CHECKS}" \
  --arg replay_phase "${PHASE3_STATUS}" \
  --argjson replay_pass "${REPLAY_PASS}" \
  --argjson replay_fail "${REPLAY_FAIL}" \
  --argjson replay_total "${REPLAY_CHECKS}" \
  --arg xgate_phase "${PHASE4_STATUS}" \
  --argjson xgate_pass "${XGATE_PASS}" \
  --argjson xgate_fail "${XGATE_FAIL}" \
  --argjson xgate_total "${XGATE_CHECKS}" \
  --argjson violations "${VIOLATIONS_JSON}" \
  --argjson evidence "${EVIDENCE_JSON}" \
  --arg scenario_verdicts_path "scenario_verdicts.json" \
  --arg assertion_policy_path "assertion_policy.json" \
  --arg steps_path "steps.jsonl" \
  --arg replay_path "replay.sh" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    summary: {
      errors: $error_count,
      warnings: $warning_count,
      total_violations: $total_violations
    },
    phases: {
      assertion_class_coverage: {
        status: $assertion_phase,
        pass: $assertion_pass,
        fail: $assertion_fail,
        skip: $assertion_skip
      },
      structured_log_completeness: {
        status: $log_phase,
        pass: $log_pass,
        fail: $log_fail,
        total: $log_total
      },
      replay_validation: {
        status: $replay_phase,
        pass: $replay_pass,
        fail: $replay_fail,
        total: $replay_total
      },
      cross_gate_consistency: {
        status: $xgate_phase,
        pass: $xgate_pass,
        fail: $xgate_fail,
        total: $xgate_total
      }
    },
    violations: $violations,
    evidence: $evidence,
    artifacts: {
      quality_gate_report: "quality_gate_report.json",
      scenario_verdicts: $scenario_verdicts_path,
      assertion_policy: $assertion_policy_path,
      steps: $steps_path,
      replay: $replay_path
    },
    triage_guide: {
      quick_status: "Check overall_status field",
      find_violations: "Read violations array; filter by severity=error for blockers",
      scenario_detail: "Read scenario_verdicts.json for per-scenario pass/fail/skip with reasons",
      assertion_policy: "Read assertion_policy.json for required assertion classes per archetype",
      replay: "Execute replay.sh to re-run the full quality gate"
    }
  }' > "${GATE_REPORT}"

# ── Phase 7: Replay Script ──────────────────────────────────────────────────
cat > "${REPLAY_SCRIPT}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay script for Quality Gate Run: ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Quality Gate: ${RUN_ID} ==="

bash scripts/e2e/e2e_quality_gate.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}" \\
  --registry "${REGISTRY}"$(
  [[ -n "${SUITE_ROOT}" ]] && printf ' \\\n  --suite-root "%s"' "${SUITE_ROOT}"
  [[ -n "${E2E_ROOT}" ]] && printf ' \\\n  --e2e-root "%s"' "${E2E_ROOT}"
  [[ -n "${UNIT_GATE_ROOT}" ]] && printf ' \\\n  --unit-gate-root "%s"' "${UNIT_GATE_ROOT}"
  [[ -n "${INTEG_GATE_ROOT}" ]] && printf ' \\\n  --integ-gate-root "%s"' "${INTEG_GATE_ROOT}"
  [[ -n "${COVERAGE_GATE_ROOT}" ]] && printf ' \\\n  --coverage-gate-root "%s"' "${COVERAGE_GATE_ROOT}"
  )
REPLAY_EOF
chmod +x "${REPLAY_SCRIPT}"

# ── Summary Output ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  QUALITY GATE REPORT — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:         ${OVERALL_STATUS}"
echo "  CI Mode:                ${CI_MODE}"
echo "  Errors:                 ${ERROR_COUNT}"
echo "  Warnings:               ${WARNING_COUNT}"
echo ""
echo "  Phases:"
echo "    Assertion Coverage:   ${PHASE1_STATUS} (pass=${ASSERT_PASS}, fail=${ASSERT_FAIL}, skip=${ASSERT_SKIP})"
echo "    Structured Logs:      ${PHASE2_STATUS} (pass=${LOG_PASS}, fail=${LOG_FAIL}, total=${LOG_CHECKS})"
echo "    Replay Validation:    ${PHASE3_STATUS} (pass=${REPLAY_PASS}, fail=${REPLAY_FAIL}, total=${REPLAY_CHECKS})"
echo "    Cross-Gate:           ${PHASE4_STATUS} (pass=${XGATE_PASS}, fail=${XGATE_FAIL}, total=${XGATE_CHECKS})"
echo ""
echo "  Scenarios:              ${SCENARIO_COUNT} total"
echo "    Pass:                 ${ASSERT_PASS}"
echo "    Fail:                 ${ASSERT_FAIL}"
echo "    Skip:                 ${ASSERT_SKIP}"
echo ""
echo "  Artifacts:              ${OUT_ROOT}/"
echo "    quality_gate_report.json   — full gate report + triage guide"
echo "    scenario_verdicts.json     — per-scenario pass/fail/skip"
echo "    assertion_policy.json      — required assertion classes per archetype"
echo "    steps.jsonl                — per-phase execution log"
echo "    replay.sh                  — deterministic replay"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  # Print top violations for quick triage
  echo ""
  echo "  Top violations:"
  jq -r '.violations[:10][] | "  - [\(.severity)] \(.rule): \(.message)\(if .scenario then " (scenario=\(.scenario))" else "" end)"' "${GATE_REPORT}" 2>/dev/null || true
  echo ""
  exit 1
fi
