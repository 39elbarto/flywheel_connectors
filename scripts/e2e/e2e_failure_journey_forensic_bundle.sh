#!/usr/bin/env bash
# =============================================================================
# e2e_failure_journey_forensic_bundle.sh — Failure-Journey E2E + Forensic Bundle
# =============================================================================
# Bead:     235t.33.4 (ASUPERSYNC-UX Failure-Journey Forensic Validation Bundle)
# Schema:   asupersync-failure-journey-forensic-bundle/v1
#
# Convergence gate proving user-facing error and recovery semantics hold under
# realistic adversity. Orchestrates multi-scenario failure journeys, validates
# forensic bundles, cross-references error taxonomy + recovery guidance, and
# produces a comprehensive evidence bundle.
#
# Failure Journey Phases:
#   1. Pre-flight: validate dependencies (33.2, 33.3, 26.7.3, 27.4 artifacts)
#   2. Network fault journeys: timeout chain + polling backoff storm
#   3. Retry exhaustion journeys: webhook retry storm + cursor gap recovery
#   4. Degraded repair journeys: offline repair + targeted repair
#   5. Cancellation storm journeys: cancel chain + streaming reconnect
#   6. Forensic schema validation: all scenario forensics against forensics/v1
#   7. User-impact semantics validation: error taxonomy + recovery guidance
#   8. Evidence bundle generation: BUNDLE_MANIFEST.json + drift report
#
# Usage:
#   bash scripts/e2e/e2e_failure_journey_forensic_bundle.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing scenarios
#   --only-journeys <csv>   Filter: network_faults,retry_exhaustion,
#                           degraded_repair,cancellation_storms
#   --ci                    CI mode (strict)
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-failure-journey-forensic-bundle/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"
ONLY_JOURNEYS=""

declare -i JOURNEY_PASS=0
declare -i JOURNEY_FAIL=0
declare -i JOURNEY_SKIP=0
declare -i JOURNEY_WARN=0
declare -a FINDING_RECORDS=()
declare -a SCENARIO_RESULTS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_failure_journey_forensic_bundle.sh [options]

Failure-Journey E2E + Forensic Validation Bundle

Orchestrates multi-scenario failure journeys (network faults, retry exhaustion,
degraded repair, cancellation storms), validates forensic bundles, and produces
a comprehensive evidence bundle proving user-facing error semantics hold.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/failure-journey/<run-id>)
  --dry-run               Emit plan without executing scenarios
  --only-journeys <csv>   Filter: network_faults,retry_exhaustion,
                          degraded_repair,cancellation_storms
  --ci                    CI mode (strict: no waivers)
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
  printf '[%s] [FAILURE-JOURNEY/%s] %s\n' "$(now_iso)" "$1" "$2"
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

should_run_journey() {
  local journey="$1"
  if [[ -z "${ONLY_JOURNEYS}" ]]; then
    return 0
  fi
  echo ",${ONLY_JOURNEYS}," | grep -q ",${journey}," && return 0
  return 1
}

add_scenario_result() {
  local key="$1"
  local scenario_id="$2"
  local script="$3"
  local contract_id="$4"
  local journey_class="$5"
  local status="$6"
  local step_count="$7"
  local duration_ms="$8"
  local forensics_path="$9"
  local user_impact="${10}"
  local error_categories="${11}"

  local r
  r="$(jq -c -n \
    --arg key "${key}" \
    --arg scenario_id "${scenario_id}" \
    --arg script "${script}" \
    --arg contract_id "${contract_id}" \
    --arg journey_class "${journey_class}" \
    --arg status "${status}" \
    --argjson step_count "${step_count}" \
    --argjson duration_ms "${duration_ms}" \
    --arg forensics_path "${forensics_path}" \
    --arg user_impact "${user_impact}" \
    --arg error_categories "${error_categories}" \
    '{
      key: $key,
      scenario_id: $scenario_id,
      script: $script,
      contract_id: $contract_id,
      journey_class: $journey_class,
      status: $status,
      step_count: $step_count,
      duration_ms: $duration_ms,
      forensics_path: $forensics_path,
      user_impact: $user_impact,
      error_categories: ($error_categories | split(","))
    }')"
  SCENARIO_RESULTS+=("${r}")
}

run_e2e_scenario() {
  local label="$1"
  local script_path="$2"
  local contract_id="$3"
  local journey_class="$4"
  local user_impact="$5"
  local error_categories="$6"
  local scenario_id="failure_journey.${label}"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_out="${OUT_ROOT}/scenarios/${label}"
  local forensics_path="scenarios/${label}/forensics.jsonl"

  mkdir -p "${OUT_ROOT}/logs" "${scenario_out}"

  local full_script="${SCRIPT_DIR}/${script_path}"
  if [[ ! -f "${full_script}" ]]; then
    log_step "${label}" "SKIP — script not found: ${script_path}"
    JOURNEY_SKIP=$((JOURNEY_SKIP + 1))
    record_step "${scenario_id}" "e2e_scenario" "planned" 0 "${contract_id}" \
      "script_not_found: ${script_path}" "${log_file}"
    add_scenario_result "${label}" "${scenario_id}" "${script_path}" \
      "${contract_id}" "${journey_class}" "skip" 0 0 "${forensics_path}" \
      "${user_impact}" "${error_categories}"
    return 0
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] bash ${script_path}"
    echo "[dry-run] bash ${full_script} --out-dir=${scenario_out}" > "${log_file}"
    record_step "${scenario_id}" "e2e_scenario" "planned" 0 "${contract_id}" \
      "dry_run" "${log_file}"
    JOURNEY_SKIP=$((JOURNEY_SKIP + 1))
    add_scenario_result "${label}" "${scenario_id}" "${script_path}" \
      "${contract_id}" "${journey_class}" "planned" 0 0 "${forensics_path}" \
      "${user_impact}" "${error_categories}"
    return 0
  fi

  local start end elapsed status
  start=$(now_ms)
  if OUT_DIR="${scenario_out}" bash "${full_script}" > "${log_file}" 2>&1; then
    status="pass"
  else
    status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  # Count forensic steps in scenario output
  local step_count=0
  if [[ -f "${scenario_out}/forensics.jsonl" ]]; then
    step_count=$(wc -l < "${scenario_out}/forensics.jsonl" | tr -d ' ')
  fi

  if [[ "${status}" == "pass" ]]; then
    JOURNEY_PASS=$((JOURNEY_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms, ${step_count} steps)"
    record_step "${scenario_id}" "e2e_scenario" "pass" "${elapsed}" \
      "${contract_id}" "" "${log_file}"
  else
    JOURNEY_FAIL=$((JOURNEY_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "e2e_scenario" "fail" "${elapsed}" \
      "${contract_id}" "${reason}" "${log_file}"
    add_finding "${journey_class}" "${label}" "high" \
      "Failure journey scenario failed: ${reason}" \
      "bash ${full_script}"
  fi

  add_scenario_result "${label}" "${scenario_id}" "${script_path}" \
    "${contract_id}" "${journey_class}" "${status}" "${step_count}" \
    "${elapsed}" "${forensics_path}" "${user_impact}" "${error_categories}"
}

run_cargo_check() {
  local label="$1"
  local package="$2"
  local test_filter="$3"
  local contract_id="$4"
  local phase_name="$5"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="failure_journey.${label}"

  mkdir -p "${OUT_ROOT}/logs"

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] cargo test -p ${package} ${test_filter}"
    echo "[dry-run] cargo test -p ${package} ${test_filter}" > "${log_file}"
    record_step "${scenario_id}" "cargo_test" "planned" 0 "${contract_id}" "dry_run" "${log_file}"
    JOURNEY_SKIP=$((JOURNEY_SKIP + 1))
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
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-failure-journey}" \
      cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1 && status="pass" || status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    JOURNEY_PASS=$((JOURNEY_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "cargo_test" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    JOURNEY_FAIL=$((JOURNEY_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "cargo_test" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_finding "${phase_name}" "${label}" "high" "${reason}" \
      "cargo test -p ${package} ${test_filter} -- --nocapture"
  fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)         RUN_ID="$2"; shift 2;;
    --out-root)       OUT_ROOT="$2"; shift 2;;
    --dry-run)        DRY_RUN=true; shift;;
    --only-journeys)  ONLY_JOURNEYS="$2"; shift 2;;
    --ci)             CI_MODE=true; shift;;
    -h|--help)        usage; exit 0;;
    *)                echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd cargo

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/failure-journey/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/scenarios" "${OUT_ROOT}/evidence" "${OUT_ROOT}/forensics"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
SUMMARY_FILE="${OUT_ROOT}/summary.json"
FINDINGS_FILE="${OUT_ROOT}/findings.json"
BUNDLE_MANIFEST="${OUT_ROOT}/BUNDLE_MANIFEST.json"
DRIFT_REPORT="${OUT_ROOT}/user_impact_drift_report.json"
REPLAY_FILE="${OUT_ROOT}/replay.sh"

: > "${STEPS_FILE}"

log_step "INIT" "Failure-Journey Forensic Bundle v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"
echo ""

# =============================================================================
# Phase 1: Pre-flight — Validate Dependency Artifacts
# =============================================================================
log_step "PREFLIGHT" "Phase 1: Validating dependency artifacts"

phase_start=$(now_ms)
preflight_ok=true
preflight_notes=""

# Check error contract tests exist (33.2)
if [[ -f "${REPO_ROOT}/crates/fcp-sdk/tests/error_contract_tests.rs" ]]; then
  log_step "PREFLIGHT" "  [ok] error_contract_tests.rs present (235t.33.2)"
else
  preflight_ok=false
  preflight_notes="${preflight_notes}Missing 235t.33.2 error_contract_tests.rs. "
fi

# Check recovery guidance script exists (33.3)
if [[ -f "${SCRIPT_DIR}/e2e_recovery_guidance_validation.sh" ]]; then
  log_step "PREFLIGHT" "  [ok] recovery_guidance_validation.sh present (235t.33.3)"
else
  preflight_ok=false
  preflight_notes="${preflight_notes}Missing 235t.33.3 recovery_guidance_validation.sh. "
fi

# Check forensics validation script exists (26.7.3)
if [[ -f "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" ]]; then
  log_step "PREFLIGHT" "  [ok] validate_asupersync_forensics_bundle.sh present (235t.26.7.3)"
else
  preflight_ok=false
  preflight_notes="${preflight_notes}Missing 235t.26.7.3 forensics validator. "
fi

# Check unified validation report script exists (27.4)
if [[ -f "${SCRIPT_DIR}/e2e_unified_validation_report.sh" ]]; then
  log_step "PREFLIGHT" "  [ok] unified_validation_report.sh present (235t.27.4)"
else
  preflight_ok=false
  preflight_notes="${preflight_notes}Missing 235t.27.4 unified_validation_report.sh. "
fi

# Check error taxonomy doc exists
if [[ -f "${REPO_ROOT}/docs/ASUPERSYNC_Error_Taxonomy.md" ]]; then
  log_step "PREFLIGHT" "  [ok] Error taxonomy documentation present"
else
  preflight_ok=false
  preflight_notes="${preflight_notes}Missing Error_Taxonomy.md. "
fi

# Check failure-journey scripts exist
FAILURE_SCRIPTS=(
  "request_timeout_chain.sh"
  "polling_timeout_backoff_storm.sh"
  "webhook_retry_storm.sh"
  "polling_cursor_gap_recovery.sh"
  "offline_repair_flow.sh"
  "targeted_repair_flow.sh"
  "bidirectional_cancel_chain.sh"
  "streaming_reconnect_storm.sh"
)
missing_scripts=0
for fs in "${FAILURE_SCRIPTS[@]}"; do
  if [[ -f "${SCRIPT_DIR}/${fs}" ]]; then
    log_step "PREFLIGHT" "  [ok] ${fs}"
  else
    missing_scripts=$((missing_scripts + 1))
    preflight_notes="${preflight_notes}Missing ${fs}. "
  fi
done

phase_end=$(now_ms)
phase_elapsed=$((phase_end - phase_start))

if [[ "${preflight_ok}" == "true" && "${missing_scripts}" -eq 0 ]]; then
  JOURNEY_PASS=$((JOURNEY_PASS + 1))
  record_step "failure_journey.preflight" "dependency_validation" "pass" "${phase_elapsed}" \
    "contract.failure_journey_dependency_artifacts"
  log_step "PREFLIGHT" "PASS — all dependency artifacts present"
else
  if [[ "${missing_scripts}" -gt 0 ]]; then
    JOURNEY_WARN=$((JOURNEY_WARN + 1))
    record_step "failure_journey.preflight" "dependency_validation" "pass" "${phase_elapsed}" \
      "contract.failure_journey_dependency_artifacts" \
      "${missing_scripts} scenario scripts missing (will skip)"
    log_step "PREFLIGHT" "WARN — ${missing_scripts} scenario scripts missing, will skip those journeys"
  else
    JOURNEY_FAIL=$((JOURNEY_FAIL + 1))
    record_step "failure_journey.preflight" "dependency_validation" "fail" "${phase_elapsed}" \
      "contract.failure_journey_dependency_artifacts" "${preflight_notes}"
    log_step "PREFLIGHT" "FAIL — ${preflight_notes}"
    add_finding "preflight" "dependency_artifacts" "critical" \
      "${preflight_notes}" "Ensure 33.2, 33.3, 26.7.3, 27.4 beads are closed"
  fi
fi
echo ""

# =============================================================================
# Phase 2: Network Fault Journeys
# =============================================================================
# Timeout chains + polling backoff storms. These validate that network faults
# produce correct error taxonomy (7xxx External, 408 Timeout) and that recovery
# guidance (retry with backoff) actually leads to recovery.
# =============================================================================
if should_run_journey "network_faults"; then
  log_step "NETWORK_FAULTS" "Phase 2: Network fault journeys (timeout + backoff)"

  # 2a: Request timeout chain — cascading timeout across request/response
  run_e2e_scenario "timeout_chain" \
    "request_timeout_chain.sh" \
    "contract.request_timeout_chain_bounded_failure" \
    "network_faults" \
    "availability" \
    "External,Resource"

  # 2b: Polling timeout backoff storm — sustained timeout + bounded backoff
  run_e2e_scenario "polling_backoff_storm" \
    "polling_timeout_backoff_storm.sh" \
    "contract.polling_timeout_backoff_bounded_recovery" \
    "network_faults" \
    "availability" \
    "External,Connector"

  echo ""
else
  log_step "NETWORK_FAULTS" "Skipped (--only-journeys filter)"
fi

# =============================================================================
# Phase 3: Retry Exhaustion Journeys
# =============================================================================
# Webhook retry storms + cursor gap recovery. These validate that retry
# exhaustion produces correct error taxonomy (5xxx Connector, 6xxx Resource)
# and that recovery guidance (wait, then retry; check idempotency) works.
# =============================================================================
if should_run_journey "retry_exhaustion"; then
  log_step "RETRY_EXHAUSTION" "Phase 3: Retry exhaustion journeys (storm + gap recovery)"

  # 3a: Webhook retry storm — sustained 503 + bounded retries + idempotency
  run_e2e_scenario "webhook_retry_storm" \
    "webhook_retry_storm.sh" \
    "contract.webhook_retry_storm_idempotent_delivery" \
    "retry_exhaustion" \
    "availability" \
    "Connector,External"

  # 3b: Polling cursor gap recovery — gap detection + gap-fill + forward progress
  run_e2e_scenario "cursor_gap_recovery" \
    "polling_cursor_gap_recovery.sh" \
    "contract.polling_cursor_gap_detection_recovery" \
    "retry_exhaustion" \
    "correctness" \
    "Resource,Connector"

  echo ""
else
  log_step "RETRY_EXHAUSTION" "Skipped (--only-journeys filter)"
fi

# =============================================================================
# Phase 4: Degraded Repair Journeys
# =============================================================================
# Offline repair + targeted repair. These validate that degraded mesh/store
# conditions produce correct error taxonomy (6xxx Resource) and that
# RaptorQ repair convergence succeeds.
# =============================================================================
if should_run_journey "degraded_repair"; then
  log_step "DEGRADED_REPAIR" "Phase 4: Degraded repair journeys (offline + targeted)"

  # 4a: Offline repair flow — partial loss coverage + repair convergence
  run_e2e_scenario "offline_repair" \
    "offline_repair_flow.sh" \
    "contract.offline_repair_recovery" \
    "degraded_repair" \
    "availability" \
    "Resource,Internal"

  # 4b: Targeted repair flow — symbol request + decode status
  run_e2e_scenario "targeted_repair" \
    "targeted_repair_flow.sh" \
    "contract.targeted_symbol_repair" \
    "degraded_repair" \
    "availability" \
    "Resource"

  echo ""
else
  log_step "DEGRADED_REPAIR" "Skipped (--only-journeys filter)"
fi

# =============================================================================
# Phase 5: Cancellation Storm Journeys
# =============================================================================
# Bidirectional cancel chain + streaming reconnect storm. These validate that
# cancellation propagation and reconnect behavior produce clean shutdown without
# resource leaks, and recovery guidance leads to session re-establishment.
# =============================================================================
if should_run_journey "cancellation_storms"; then
  log_step "CANCELLATION_STORMS" "Phase 5: Cancellation storm journeys (cancel + reconnect)"

  # 5a: Bidirectional cancel chain — clean shutdown under cancel cascade
  run_e2e_scenario "cancel_chain" \
    "bidirectional_cancel_chain.sh" \
    "contract.bidirectional_cancel_chain_clean_shutdown" \
    "cancellation_storms" \
    "availability" \
    "Resource,External"

  # 5b: Streaming reconnect storm — bounded reconnect + ordering preservation
  run_e2e_scenario "reconnect_storm" \
    "streaming_reconnect_storm.sh" \
    "contract.ws_reconnect_storm_bounded_recovery" \
    "cancellation_storms" \
    "availability" \
    "Connector,External"

  echo ""
else
  log_step "CANCELLATION_STORMS" "Skipped (--only-journeys filter)"
fi

# =============================================================================
# Phase 6: Forensic Schema Validation
# =============================================================================
# Validate all scenario forensics against forensics/v1 schema, proving
# replay artifacts satisfy logging requirements.
# =============================================================================
log_step "FORENSIC_VALIDATION" "Phase 6: Forensic schema validation"

phase_start=$(now_ms)
forensic_issues=0
forensic_steps_validated=0

for scenario_dir in "${OUT_ROOT}"/scenarios/*/; do
  if [[ ! -d "${scenario_dir}" ]]; then
    continue
  fi
  scenario_name="$(basename "${scenario_dir}")"
  forensics_file="${scenario_dir}/forensics.jsonl"

  if [[ ! -f "${forensics_file}" ]]; then
    log_step "FORENSIC_VALIDATION" "  [skip] ${scenario_name}: no forensics.jsonl"
    continue
  fi

  local_issues=0
  line_num=0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_num=$((line_num + 1))
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi

    # Validate required forensics/v1 fields
    schema_ok=true
    for field in schema_version run_id scenario_id trace_id correlation_id \
                 connector zone operation outcome elapsed_ms; do
      val="$(printf '%s' "${line}" | jq -r ".${field} // empty" 2>/dev/null || true)"
      if [[ -z "${val}" ]]; then
        schema_ok=false
        local_issues=$((local_issues + 1))
        break
      fi
    done

    # Validate schema_version matches
    sv="$(printf '%s' "${line}" | jq -r '.schema_version // empty' 2>/dev/null || true)"
    if [[ -n "${sv}" && "${sv}" != "${FORENSICS_SCHEMA}" ]]; then
      schema_ok=false
      local_issues=$((local_issues + 1))
    fi

    forensic_steps_validated=$((forensic_steps_validated + 1))
  done < "${forensics_file}"

  if [[ "${local_issues}" -gt 0 ]]; then
    forensic_issues=$((forensic_issues + local_issues))
    log_step "FORENSIC_VALIDATION" "  [warn] ${scenario_name}: ${local_issues} schema issues"
  else
    log_step "FORENSIC_VALIDATION" "  [ok] ${scenario_name}: ${line_num} steps valid"
  fi
done

phase_end=$(now_ms)
phase_elapsed=$((phase_end - phase_start))

if [[ "${forensic_issues}" -eq 0 ]]; then
  JOURNEY_PASS=$((JOURNEY_PASS + 1))
  log_step "FORENSIC_VALIDATION" "PASS — ${forensic_steps_validated} steps validated"
  record_step "failure_journey.forensic_validation" "schema_check" "pass" "${phase_elapsed}" \
    "contract.failure_journey_forensic_schema" "" ""
else
  JOURNEY_FAIL=$((JOURNEY_FAIL + 1))
  log_step "FORENSIC_VALIDATION" "FAIL — ${forensic_issues} schema issues across scenarios"
  record_step "failure_journey.forensic_validation" "schema_check" "fail" "${phase_elapsed}" \
    "contract.failure_journey_forensic_schema" \
    "${forensic_issues} forensic schema violations"
  add_finding "forensic_validation" "schema_compliance" "high" \
    "${forensic_issues} forensics/v1 schema violations in scenario forensics" \
    "Review scenario forensics.jsonl for missing required fields"
fi
echo ""

# =============================================================================
# Phase 7: User-Impact Semantics Validation
# =============================================================================
# Cross-reference error taxonomy + recovery guidance: verify that failure
# scenarios produce correct error categories, retryability flags hold, and
# recovery hints are actionable.
# =============================================================================
log_step "USER_IMPACT" "Phase 7: User-impact semantics validation"

# 7a: Error contract tests — all 8 categories, retryability matrix, wire format
run_cargo_check "error_contracts_full" "fcp-sdk" \
  "--test error_contract_tests" \
  "contract.failure_journey_error_contracts" \
  "user_impact_semantics"

# 7b: Core error module — FcpError variants + to_response
run_cargo_check "error_core_variants" "fcp-core" \
  "--lib error::" \
  "contract.failure_journey_error_core" \
  "user_impact_semantics"

# 7c: Recovery guidance validation (33.3 re-verification)
recovery_log="${OUT_ROOT}/logs/recovery_guidance_revalidation.log"
if [[ "${DRY_RUN}" == "true" ]]; then
  log_step "USER_IMPACT" "[dry-run] recovery guidance revalidation"
  echo "[dry-run] bash e2e_recovery_guidance_validation.sh --dry-run" > "${recovery_log}"
  record_step "failure_journey.recovery_revalidation" "e2e_script" "planned" 0 \
    "contract.failure_journey_recovery_guidance" "dry_run" "${recovery_log}"
  JOURNEY_SKIP=$((JOURNEY_SKIP + 1))
else
  phase_start=$(now_ms)
  recovery_out="${OUT_ROOT}/recovery_guidance"
  if bash "${SCRIPT_DIR}/e2e_recovery_guidance_validation.sh" \
       --run-id "${RUN_ID}-recovery" \
       --out-root "${recovery_out}" > "${recovery_log}" 2>&1; then
    phase_end=$(now_ms)
    phase_elapsed=$((phase_end - phase_start))
    JOURNEY_PASS=$((JOURNEY_PASS + 1))
    log_step "USER_IMPACT" "Recovery guidance revalidation: PASS (${phase_elapsed}ms)"
    record_step "failure_journey.recovery_revalidation" "e2e_script" "pass" "${phase_elapsed}" \
      "contract.failure_journey_recovery_guidance" "" "${recovery_log}"
  else
    phase_end=$(now_ms)
    phase_elapsed=$((phase_end - phase_start))
    JOURNEY_FAIL=$((JOURNEY_FAIL + 1))
    reason="$(tail -5 "${recovery_log}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "USER_IMPACT" "Recovery guidance revalidation: FAIL (${phase_elapsed}ms)"
    record_step "failure_journey.recovery_revalidation" "e2e_script" "fail" "${phase_elapsed}" \
      "contract.failure_journey_recovery_guidance" "${reason}" "${recovery_log}"
    add_finding "user_impact_semantics" "recovery_guidance_revalidation" "high" \
      "Recovery guidance validation failed: ${reason}" \
      "bash scripts/e2e/e2e_recovery_guidance_validation.sh"
  fi
fi

# 7d: Error taxonomy doc completeness — verify all 8 categories + recovery sections
phase_start=$(now_ms)
taxonomy_log="${OUT_ROOT}/logs/taxonomy_completeness.log"
taxonomy_ok=true
taxonomy_details=""

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "[dry-run] taxonomy completeness check" > "${taxonomy_log}"
  record_step "failure_journey.taxonomy_completeness" "doc_check" "planned" 0 \
    "contract.failure_journey_taxonomy_completeness" "dry_run" "${taxonomy_log}"
  JOURNEY_SKIP=$((JOURNEY_SKIP + 1))
else
  taxonomy_doc="${REPO_ROOT}/docs/ASUPERSYNC_Error_Taxonomy.md"
  if [[ -f "${taxonomy_doc}" ]]; then
    {
      echo "Error Taxonomy Completeness Check"
      echo "================================="
      for cat in "Protocol" "Auth" "Capability" "Zone" "Connector" "Resource" "External" "Internal"; do
        if grep -qi "${cat}" "${taxonomy_doc}"; then
          echo "  [ok] ${cat} category documented"
        else
          echo "  [MISSING] ${cat} category"
          taxonomy_ok=false
          taxonomy_details="${taxonomy_details}Missing ${cat}. "
        fi
      done
      # Check for recovery/remediation sections
      if grep -qi "recover\|remediat\|retry\|resolution" "${taxonomy_doc}"; then
        echo "  [ok] Recovery/remediation guidance present"
      else
        echo "  [MISSING] Recovery/remediation guidance"
        taxonomy_ok=false
        taxonomy_details="${taxonomy_details}Missing recovery guidance sections. "
      fi
    } > "${taxonomy_log}"
  else
    echo "Error taxonomy document not found" > "${taxonomy_log}"
    taxonomy_ok=false
    taxonomy_details="Error taxonomy document not found"
  fi

  phase_end=$(now_ms)
  phase_elapsed=$((phase_end - phase_start))

  if [[ "${taxonomy_ok}" == "true" ]]; then
    JOURNEY_PASS=$((JOURNEY_PASS + 1))
    log_step "USER_IMPACT" "Taxonomy completeness: PASS"
    record_step "failure_journey.taxonomy_completeness" "doc_check" "pass" "${phase_elapsed}" \
      "contract.failure_journey_taxonomy_completeness" "" "${taxonomy_log}"
  else
    JOURNEY_FAIL=$((JOURNEY_FAIL + 1))
    log_step "USER_IMPACT" "Taxonomy completeness: FAIL — ${taxonomy_details}"
    record_step "failure_journey.taxonomy_completeness" "doc_check" "fail" "${phase_elapsed}" \
      "contract.failure_journey_taxonomy_completeness" "${taxonomy_details}" "${taxonomy_log}"
    add_finding "user_impact_semantics" "taxonomy_completeness" "medium" \
      "${taxonomy_details}" "Review docs/ASUPERSYNC_Error_Taxonomy.md"
  fi
fi
echo ""

# =============================================================================
# Phase 8: Evidence Bundle Generation
# =============================================================================
log_step "EVIDENCE" "Phase 8: Generating failure-journey evidence bundle"

# 8a: User-impact drift report
# Map each failure journey to its error categories and recovery semantics
JOURNEY_MAP='[]'
if (( ${#SCENARIO_RESULTS[@]} > 0 )); then
  JOURNEY_MAP="$(printf '%s\n' "${SCENARIO_RESULTS[@]}" | jq -s '.')"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson journeys "${JOURNEY_MAP}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    description: "User-impact drift report: maps failure journeys to error categories and recovery semantics",
    journey_to_error_mapping: [
      {
        journey_class: "network_faults",
        primary_error_categories: ["External (7xxx)", "Resource (6xxx)"],
        expected_recovery: "Retry with bounded exponential backoff; check upstream health",
        user_impact: "Temporary unavailability; bounded by timeout budget",
        retryability: "conditional (depends on status code and timeout budget)"
      },
      {
        journey_class: "retry_exhaustion",
        primary_error_categories: ["Connector (5xxx)", "External (7xxx)"],
        expected_recovery: "Wait for service recovery; verify idempotency on retry",
        user_impact: "Extended unavailability; bounded by max retry attempts",
        retryability: "true (bounded by retry ceiling)"
      },
      {
        journey_class: "degraded_repair",
        primary_error_categories: ["Resource (6xxx)", "Internal (9xxx)"],
        expected_recovery: "RaptorQ repair convergence; wait for symbol availability",
        user_impact: "Data access latency; bounded by repair budget",
        retryability: "true (repair controller drives convergence)"
      },
      {
        journey_class: "cancellation_storms",
        primary_error_categories: ["Resource (6xxx)", "External (7xxx)"],
        expected_recovery: "Session re-establishment after clean shutdown",
        user_impact: "Session interruption; no resource leaks post-recovery",
        retryability: "false (must re-establish session)"
      }
    ],
    scenario_results: $journeys,
    drift_summary: {
      total_journeys: ($journeys | length),
      passed: ($journeys | map(select(.status == "pass")) | length),
      failed: ($journeys | map(select(.status == "fail")) | length),
      skipped: ($journeys | map(select(.status == "planned" or .status == "skip")) | length),
      error_categories_exercised: ($journeys | map(.error_categories) | flatten | unique),
      user_impact_categories: ($journeys | map(.user_impact) | unique)
    }
  }' > "${DRIFT_REPORT}"

log_step "EVIDENCE" "Generated user-impact drift report"

# 8b: BUNDLE_MANIFEST.json
TOTAL_CHECKS=$((JOURNEY_PASS + JOURNEY_FAIL + JOURNEY_SKIP))
FINDING_COUNT=${#FINDING_RECORDS[@]}

jq -n \
  --arg schema_version "asupersync-bundle-manifest/v1" \
  --arg run_id "${RUN_ID}" \
  --arg created_at "$(now_iso)" \
  --arg bundle_type "failure-journey-forensic" \
  --argjson bundle_version 1 \
  --arg mode "e2e-failure-journey" \
  --argjson scenario_results "${JOURNEY_MAP}" \
  --argjson journey_pass "${JOURNEY_PASS}" \
  --argjson journey_fail "${JOURNEY_FAIL}" \
  --argjson journey_skip "${JOURNEY_SKIP}" \
  --argjson journey_warn "${JOURNEY_WARN}" \
  --argjson total_checks "${TOTAL_CHECKS}" \
  --argjson finding_count "${FINDING_COUNT}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    created_at: $created_at,
    bundle_type: $bundle_type,
    bundle_version: $bundle_version,
    mode: $mode,

    artifacts: [
      { name: "summary.json", type: "gate_summary", required: true },
      { name: "steps.jsonl", type: "forensic_steps", required: true },
      { name: "findings.json", type: "finding_report", required: true },
      { name: "user_impact_drift_report.json", type: "drift_report", required: true },
      { name: "BUNDLE_MANIFEST.json", type: "manifest", required: true },
      { name: "replay.sh", type: "replay_script", required: true },
      { name: "logs/", type: "execution_logs", required: true },
      { name: "scenarios/", type: "scenario_outputs", required: true },
      { name: "evidence/failure_journey_evidence.json", type: "evidence_catalog", required: true },
      { name: "forensics/consolidated.jsonl", type: "consolidated_forensics", required: false }
    ],

    scenarios: $scenario_results,

    metadata: {
      total_checks: $total_checks,
      passed: $journey_pass,
      failed: $journey_fail,
      skipped: $journey_skip,
      warned: $journey_warn,
      findings: $finding_count,
      journey_classes: ["network_faults", "retry_exhaustion", "degraded_repair", "cancellation_storms"],
      error_categories_covered: ["Protocol", "Auth", "Capability", "Zone", "Connector", "Resource", "External", "Internal"],
      contracts_verified: ($scenario_results | map(.contract_id) | unique | length)
    },

    dependency_evidence: {
      "235t.33.2": "crates/fcp-sdk/tests/error_contract_tests.rs",
      "235t.33.3": "scripts/e2e/e2e_recovery_guidance_validation.sh",
      "235t.26.7.3": "scripts/e2e/validate_asupersync_forensics_bundle.sh",
      "235t.27.4": "scripts/e2e/e2e_unified_validation_report.sh"
    },

    consumers: {
      "235t.34.1": "Canary scenario matrix (reads journey results for canary abort thresholds)",
      "235t.34.2": "Rollback drill (reads recovery semantics for state consistency validation)",
      "235t.34.3": "Rehearsal automation (reads forensic bundle for artifact enforcement)",
      "235t.34.4": "Go/no-go gate (reads overall pass/fail for release decision)",
      "235t.34": "Canary rollout parent (aggregates from 34.1-34.4)",
      "235t.29": "Final cutover (requires all parent gates green)"
    },

    replay_instructions: {
      full_suite: "bash scripts/e2e/e2e_failure_journey_forensic_bundle.sh --run-id <run-id>",
      single_journey: "bash scripts/e2e/e2e_failure_journey_forensic_bundle.sh --only-journeys <class>",
      dry_run: "bash scripts/e2e/e2e_failure_journey_forensic_bundle.sh --dry-run"
    }
  }' > "${BUNDLE_MANIFEST}"

log_step "EVIDENCE" "Generated BUNDLE_MANIFEST.json"

# 8c: Failure journey evidence catalog
jq -n \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson scenario_results "${JOURNEY_MAP}" \
  '{
    run_id: $run_id,
    generated_at: $generated_at,
    description: "Failure journey evidence catalog: maps scenarios to error categories, recovery semantics, and forensic traces",
    journey_classes: {
      network_faults: {
        description: "Network fault injection (timeouts, latency, partition)",
        scenarios: ["timeout_chain", "polling_backoff_storm"],
        error_taxonomy: "External (7xxx): UpstreamTimeout, DependencyUnavailable",
        recovery_guidance: "Retry with exponential backoff; verify timeout budget",
        user_journey: "Request fails with timeout → receives FCP-7001 with retry hint → waits → retries → upstream recovers → success"
      },
      retry_exhaustion: {
        description: "Retry budget exhaustion under sustained failures",
        scenarios: ["webhook_retry_storm", "cursor_gap_recovery"],
        error_taxonomy: "Connector (5xxx): ConnectorUnavailable; Resource (6xxx): ResourceExhausted",
        recovery_guidance: "Wait for service recovery; check idempotency on retry",
        user_journey: "Service returns 503 → retries with backoff → max retries reached → user sees bounded failure → service recovers → deferred delivery succeeds"
      },
      degraded_repair: {
        description: "Degraded mesh/store conditions requiring RaptorQ repair",
        scenarios: ["offline_repair", "targeted_repair"],
        error_taxonomy: "Resource (6xxx): ResourceExhausted, BudgetExceeded",
        recovery_guidance: "Wait for repair convergence; check decode status",
        user_journey: "Symbol loss detected → repair controller initiated → symbols reconstructed → data access restored"
      },
      cancellation_storms: {
        description: "Cancellation propagation and streaming reconnect",
        scenarios: ["cancel_chain", "reconnect_storm"],
        error_taxonomy: "Resource (6xxx): ResourceExhausted; External (7xxx): connection reset",
        recovery_guidance: "Re-establish session after clean shutdown; verify no resource leaks",
        user_journey: "Cancel propagates → clean shutdown → session terminated → client reconnects → new session established → ordering preserved"
      }
    },
    scenario_details: $scenario_results
  }' > "${OUT_ROOT}/evidence/failure_journey_evidence.json"

log_step "EVIDENCE" "Generated failure journey evidence catalog"

# 8d: Consolidate all scenario forensics
: > "${OUT_ROOT}/forensics/consolidated.jsonl"
for scenario_dir in "${OUT_ROOT}"/scenarios/*/; do
  if [[ -f "${scenario_dir}/forensics.jsonl" ]]; then
    cat "${scenario_dir}/forensics.jsonl" >> "${OUT_ROOT}/forensics/consolidated.jsonl"
  fi
done
consolidated_count=$(wc -l < "${OUT_ROOT}/forensics/consolidated.jsonl" | tr -d ' ')
log_step "EVIDENCE" "Consolidated ${consolidated_count} forensic records"

JOURNEY_PASS=$((JOURNEY_PASS + 1))
record_step "failure_journey.evidence_bundle" "generate" "pass" 0 \
  "contract.failure_journey_evidence_bundle"

# =============================================================================
# Generate Findings Report
# =============================================================================
log_step "FINDINGS" "Generating findings report"

TOTAL_CHECKS=$((JOURNEY_PASS + JOURNEY_FAIL + JOURNEY_SKIP))
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
log_step "SUMMARY" "Generating failure-journey summary"

OVERALL_STATUS="pass"
if (( JOURNEY_FAIL > 0 )); then
  OVERALL_STATUS="fail"
elif (( JOURNEY_WARN > 0 )); then
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
  --argjson pass "${JOURNEY_PASS}" \
  --argjson fail "${JOURNEY_FAIL}" \
  --argjson skip "${JOURNEY_SKIP}" \
  --argjson warn "${JOURNEY_WARN}" \
  --argjson finding_count "${FINDING_COUNT}" \
  --arg only_journeys "${ONLY_JOURNEYS}" \
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
    filters: {
      only_journeys: (if ($only_journeys | length) > 0 then $only_journeys else null end)
    },
    phases: {
      preflight: "Dependency artifact validation (33.2, 33.3, 26.7.3, 27.4)",
      network_faults: "Network fault journeys: timeout chain + polling backoff storm",
      retry_exhaustion: "Retry exhaustion journeys: webhook retry storm + cursor gap recovery",
      degraded_repair: "Degraded repair journeys: offline repair + targeted repair",
      cancellation_storms: "Cancellation storm journeys: cancel chain + reconnect storm",
      forensic_validation: "Forensic schema validation across all scenario outputs",
      user_impact_semantics: "Error taxonomy + recovery guidance cross-reference",
      evidence_bundle: "BUNDLE_MANIFEST + drift report + evidence catalog generation"
    },
    artifacts: {
      summary: "summary.json",
      steps: "steps.jsonl",
      findings: "findings.json",
      drift_report: "user_impact_drift_report.json",
      bundle_manifest: "BUNDLE_MANIFEST.json",
      evidence: "evidence/failure_journey_evidence.json",
      consolidated_forensics: "forensics/consolidated.jsonl",
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
# Replay: Failure-Journey Forensic Bundle ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Failure-Journey Forensic Bundle: ${RUN_ID} ==="

bash scripts/e2e/e2e_failure_journey_forensic_bundle.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"$(
  [[ -n "${ONLY_JOURNEYS}" ]] && printf ' \\\n  --only-journeys "%s"' "${ONLY_JOURNEYS}"
  [[ "${CI_MODE}" == "true" ]] && printf ' \\\n  --ci'
  )
REPLAY_EOF
chmod +x "${REPLAY_FILE}"

# =============================================================================
# Summary Output
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  FAILURE-JOURNEY FORENSIC BUNDLE — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:       ${OVERALL_STATUS}"
echo "  CI Mode:              ${CI_MODE}"
echo "  Dry Run:              ${DRY_RUN}"
echo ""
echo "  Checks:               ${TOTAL_CHECKS} total"
echo "    Pass:               ${JOURNEY_PASS}"
echo "    Fail:               ${JOURNEY_FAIL}"
echo "    Skip:               ${JOURNEY_SKIP}"
echo "    Warn:               ${JOURNEY_WARN}"
echo ""
echo "  Findings:             ${FINDING_COUNT}"
if [[ -n "${ONLY_JOURNEYS}" ]]; then
  echo "  Filter:               ${ONLY_JOURNEYS}"
fi
echo ""
echo "  Journey Phases:"
echo "    1. preflight            — Dependency artifact validation"
echo "    2. network_faults       — Timeout chain + polling backoff storm"
echo "    3. retry_exhaustion     — Webhook retry storm + cursor gap recovery"
echo "    4. degraded_repair      — Offline repair + targeted repair"
echo "    5. cancellation_storms  — Cancel chain + reconnect storm"
echo "    6. forensic_validation  — Forensic schema compliance"
echo "    7. user_impact_semantics — Error taxonomy + recovery guidance"
echo "    8. evidence_bundle      — BUNDLE_MANIFEST + drift report + evidence"
echo ""
echo "  Artifacts:            ${OUT_ROOT}/"
echo "    summary.json                                — gate summary"
echo "    steps.jsonl                                 — per-check forensic steps"
echo "    findings.json                               — identified issues"
echo "    user_impact_drift_report.json               — user-impact drift analysis"
echo "    BUNDLE_MANIFEST.json                        — artifact index + consumers"
echo "    evidence/failure_journey_evidence.json      — journey evidence catalog"
echo "    forensics/consolidated.jsonl                — all scenario forensics"
echo "    scenarios/                                  — per-scenario outputs"
echo "    replay.sh                                   — deterministic replay"
echo "    logs/                                       — per-check execution logs"
echo ""
echo "  Consumer Beads:"
echo "    235t.34.1  — Canary scenario matrix + abort thresholds"
echo "    235t.34.2  — Rollback drill: state consistency + service recovery"
echo "    235t.34.3  — Rehearsal automation + artifact enforcement"
echo "    235t.34.4  — Go/no-go decision gate + operator runbook"
echo "    235t.29    — Final cutover"
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
