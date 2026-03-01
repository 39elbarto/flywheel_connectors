#!/usr/bin/env bash
# =============================================================================
# e2e_conformance_revalidation.sh — Protocol Conformance Matrix Revalidation
# =============================================================================
# Bead:     235t.27.1 (ASUPERSYNC-VALIDATION Conformance Revalidation)
# Schema:   asupersync-conformance-revalidation/v1
#
# Revalidates full protocol conformance against the migrated async runtime.
# Classifies observed drift as expected/approved vs regression, keyed to
# parity contract IDs with actionable remediation paths.
#
# Conformance Matrices:
#   1. Golden vectors (canonical encoding/decoding, byte-exact)
#   2. Schema validation (FZPF, policy bundle, supply chain, log migration)
#   3. Integration scenarios (network partition, revocation, zone rotation)
#   4. Compliance checks (static manifest + dynamic connector contracts)
#   5. Datagram vectors (FCPS envelope, MAC computation)
#
# Usage:
#   bash scripts/e2e/e2e_conformance_revalidation.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --dry-run               Emit plan without executing cargo test
#   --only-matrices <csv>   Filter matrices (golden,schema,integration,compliance,datagram)
#   --ci                    CI mode
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
GATE_SCHEMA="asupersync-conformance-revalidation/v1"
FORENSICS_SCHEMA="asupersync-forensics/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
CI_MODE="${CI:-false}"
ONLY_MATRICES=""

declare -i MATRIX_PASS=0
declare -i MATRIX_FAIL=0
declare -i MATRIX_SKIP=0
declare -a DRIFT_RECORDS=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/e2e_conformance_revalidation.sh [options]

Protocol Conformance Matrix Revalidation + Drift Classification

Re-runs all conformance suites against the migrated async runtime and
classifies drift with contract-keyed rationale.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/conformance/<run-id>)
  --dry-run               Emit plan without executing cargo test
  --only-matrices <csv>   Filter: golden,schema,integration,compliance,datagram
  --ci                    CI mode
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
  printf '[%s] [CONFORMANCE/%s] %s\n' "$(now_iso)" "$1" "$2"
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

add_drift() {
  local matrix="$1"
  local test_name="$2"
  local classification="$3"
  local contract_id="$4"
  local reason="$5"
  local rerun_cmd="$6"
  local d
  d="$(jq -c -n \
    --arg matrix "${matrix}" \
    --arg test_name "${test_name}" \
    --arg classification "${classification}" \
    --arg contract_id "${contract_id}" \
    --arg reason "${reason}" \
    --arg rerun_command "${rerun_cmd}" \
    --arg run_id "${RUN_ID}" \
    '{
      matrix: $matrix,
      test_name: $test_name,
      classification: $classification,
      contract_id: $contract_id,
      reason: $reason,
      rerun_command: $rerun_command,
      run_id: $run_id
    }')"
  DRIFT_RECORDS+=("${d}")
}

should_run_matrix() {
  local matrix="$1"
  if [[ -z "${ONLY_MATRICES}" ]]; then
    return 0
  fi
  echo ",${ONLY_MATRICES}," | grep -q ",${matrix}," && return 0
  return 1
}

run_cargo_test() {
  local label="$1"
  local package="$2"
  local test_filter="$3"
  local contract_id="$4"
  local log_file="${OUT_ROOT}/logs/${label}.log"
  local scenario_id="conformance.${label}"

  mkdir -p "${OUT_ROOT}/logs"
  local start end elapsed status

  if [[ "${DRY_RUN}" == "true" ]]; then
    log_step "${label}" "[dry-run] cargo test -p ${package} ${test_filter}"
    echo "[dry-run] cargo test -p ${package} ${test_filter}" > "${log_file}"
    record_step "${scenario_id}" "cargo_test" "planned" 0 "${contract_id}" "" "${log_file}"
    MATRIX_SKIP=$((MATRIX_SKIP + 1))
    return 0
  fi

  start=$(now_ms)
  # Use rch if available, else fallback with isolated target dir
  if command -v rch >/dev/null 2>&1; then
    if rch exec -- cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1; then
      status="pass"
    else
      status="fail"
    fi
  else
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-conformance-reval}" \
      cargo test -p "${package}" ${test_filter} -- --nocapture > "${log_file}" 2>&1 && status="pass" || status="fail"
  fi
  end=$(now_ms)
  elapsed=$((end - start))

  if [[ "${status}" == "pass" ]]; then
    MATRIX_PASS=$((MATRIX_PASS + 1))
    log_step "${label}" "PASS (${elapsed}ms)"
    record_step "${scenario_id}" "cargo_test" "pass" "${elapsed}" "${contract_id}" "" "${log_file}"
  else
    MATRIX_FAIL=$((MATRIX_FAIL + 1))
    local reason
    reason="$(tail -5 "${log_file}" | head -3 | tr '\n' ' ' | head -c 200)"
    log_step "${label}" "FAIL (${elapsed}ms): ${reason}"
    record_step "${scenario_id}" "cargo_test" "fail" "${elapsed}" "${contract_id}" "${reason}" "${log_file}"
    add_drift "${label}" "${test_filter}" "regression" "${contract_id}" "${reason}" \
      "cargo test -p ${package} ${test_filter} -- --nocapture"
  fi
}

# ── Parse arguments ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)          RUN_ID="$2"; shift 2;;
    --out-root)        OUT_ROOT="$2"; shift 2;;
    --dry-run)         DRY_RUN=true; shift;;
    --only-matrices)   ONLY_MATRICES="$2"; shift 2;;
    --ci)              CI_MODE=true; shift;;
    -h|--help)         usage; exit 0;;
    *)                 echo "Unknown option: $1" >&2; usage; exit 1;;
  esac
done

# ── Pre-flight ──────────────────────────────────────────────────────────────
require_cmd jq
require_cmd cargo

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/conformance/${RUN_ID}"
fi
mkdir -p "${OUT_ROOT}/logs"

STEPS_FILE="${OUT_ROOT}/steps.jsonl"
SUMMARY_FILE="${OUT_ROOT}/summary.json"
DRIFT_FILE="${OUT_ROOT}/drift_classification.json"
REPLAY_FILE="${OUT_ROOT}/replay.sh"

: > "${STEPS_FILE}"

log_step "INIT" "Conformance Revalidation v1 — run_id=${RUN_ID}"
log_step "INIT" "Output: ${OUT_ROOT}"

# =============================================================================
# Matrix 1: Golden Vectors
# =============================================================================
if should_run_matrix "golden"; then
  log_step "GOLDEN" "Matrix 1: Golden vector tests (canonical encoding/decoding)"

  # fcp-conformance unit tests for vectors
  run_cargo_test "golden_vectors_unit" "fcp-conformance" \
    "--lib vectors::" \
    "contract.golden_vector_encoding"

  # fcp-conformance datagram golden vectors integration test
  run_cargo_test "golden_vectors_datagram" "fcp-conformance" \
    "--test datagram_golden_vectors" \
    "contract.datagram_golden_vectors"

  # fcp-raptorq golden vectors
  run_cargo_test "golden_raptorq" "fcp-raptorq" \
    "--lib golden::" \
    "contract.raptorq_golden_vectors"
else
  log_step "GOLDEN" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 2: Schema Validation
# =============================================================================
if should_run_matrix "schema"; then
  log_step "SCHEMA" "Matrix 2: Schema validation tests"

  # FZPF schema validation
  run_cargo_test "schema_fzpf" "fcp-conformance" \
    "--test fzpf_schema_validation" \
    "contract.fzpf_schema_conformance"

  # Policy bundle schema
  run_cargo_test "schema_policy_bundle" "fcp-conformance" \
    "--test policy_bundle_schema" \
    "contract.policy_bundle_schema"

  # Supply chain schema
  run_cargo_test "schema_supply_chain" "fcp-conformance" \
    "--test supply_chain_schema" \
    "contract.supply_chain_schema"

  # Log migration E2E schema
  run_cargo_test "schema_log_migration" "fcp-conformance" \
    "--test log_migration_e2e" \
    "contract.log_migration_schema"

  # Schema hash determinism
  run_cargo_test "schema_hash_determinism" "fcp-conformance" \
    "--test schema_hash_determinism" \
    "contract.schema_hash_determinism"

  # Schemas module unit tests
  run_cargo_test "schema_unit" "fcp-conformance" \
    "--lib schemas::" \
    "contract.schema_validation_unit"
else
  log_step "SCHEMA" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 3: Integration Scenarios
# =============================================================================
if should_run_matrix "integration"; then
  log_step "INTEG" "Matrix 3: Integration scenario tests"

  run_cargo_test "integration_scenarios" "fcp-conformance" \
    "--test integration_scenarios" \
    "contract.conformance_integration_scenarios"
else
  log_step "INTEG" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 4: Compliance Checks
# =============================================================================
if should_run_matrix "compliance"; then
  log_step "COMPLIANCE" "Matrix 4: Compliance contract checks"

  # Compliance module unit tests (static + dynamic)
  run_cargo_test "compliance_unit" "fcp-conformance" \
    "--lib compliance::" \
    "contract.compliance_static_dynamic"

  # Harness infrastructure tests
  run_cargo_test "harness_unit" "fcp-conformance" \
    "--lib harness::" \
    "contract.test_harness_infrastructure"
else
  log_step "COMPLIANCE" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Matrix 5: Datagram Vectors
# =============================================================================
if should_run_matrix "datagram"; then
  log_step "DATAGRAM" "Matrix 5: Datagram envelope tests"

  # Datagram vector module
  run_cargo_test "datagram_vectors_unit" "fcp-conformance" \
    "--lib vectors::datagram" \
    "contract.datagram_encoding"

  # Core vectors
  run_cargo_test "core_vectors_unit" "fcp-conformance" \
    "--lib vectors::core" \
    "contract.core_canonical_encoding"
else
  log_step "DATAGRAM" "Skipped (--only-matrices filter)"
fi

# =============================================================================
# Generate Drift Classification
# =============================================================================
log_step "DRIFT" "Generating drift classification report"

TOTAL_MATRICES=$((MATRIX_PASS + MATRIX_FAIL + MATRIX_SKIP))
DRIFT_COUNT=${#DRIFT_RECORDS[@]}

DRIFT_JSON='[]'
if (( DRIFT_COUNT > 0 )); then
  DRIFT_JSON="$(printf '%s\n' "${DRIFT_RECORDS[@]}" | jq -s 'sort_by(.matrix, .test_name)')"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --argjson total_matrices "${TOTAL_MATRICES}" \
  --argjson pass "${MATRIX_PASS}" \
  --argjson fail "${MATRIX_FAIL}" \
  --argjson skip "${MATRIX_SKIP}" \
  --argjson drift_count "${DRIFT_COUNT}" \
  --argjson drift_records "${DRIFT_JSON}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    summary: {
      total_matrices: $total_matrices,
      pass: $pass,
      fail: $fail,
      skip: $skip,
      drift_count: $drift_count
    },
    classification_legend: {
      "regression": "Unexpected behavioral change requiring investigation and fix",
      "expected_drift": "Known drift from migration — approved via contract review",
      "approved_variance": "Intentional behavior change documented in migration plan"
    },
    drift_records: $drift_records
  }' > "${DRIFT_FILE}"

# =============================================================================
# Generate Summary
# =============================================================================
log_step "SUMMARY" "Generating revalidation summary"

OVERALL_STATUS="pass"
if (( MATRIX_FAIL > 0 )); then
  OVERALL_STATUS="fail"
fi

jq -n \
  --arg schema_version "${GATE_SCHEMA}" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(now_iso)" \
  --arg overall_status "${OVERALL_STATUS}" \
  --argjson ci_mode "${CI_MODE}" \
  --argjson total "${TOTAL_MATRICES}" \
  --argjson pass "${MATRIX_PASS}" \
  --argjson fail "${MATRIX_FAIL}" \
  --argjson skip "${MATRIX_SKIP}" \
  --argjson drift_count "${DRIFT_COUNT}" \
  --arg only_matrices "${ONLY_MATRICES}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    overall_status: $overall_status,
    ci_mode: $ci_mode,
    matrices: {
      total: $total,
      pass: $pass,
      fail: $fail,
      skip: $skip
    },
    drift_count: $drift_count,
    filters: {
      only_matrices: (if ($only_matrices | length) > 0 then $only_matrices else null end)
    },
    artifacts: {
      summary: "summary.json",
      steps: "steps.jsonl",
      drift_classification: "drift_classification.json",
      replay: "replay.sh",
      logs: "logs/"
    }
  }' > "${SUMMARY_FILE}"

# =============================================================================
# Generate Replay Script
# =============================================================================
cat > "${REPLAY_FILE}" <<REPLAY_EOF
#!/usr/bin/env bash
# Replay: Conformance Revalidation ${RUN_ID}
# Generated: $(now_iso)
set -euo pipefail

echo "=== Replaying Conformance Revalidation: ${RUN_ID} ==="

bash scripts/e2e/e2e_conformance_revalidation.sh \\
  --run-id "${RUN_ID}" \\
  --out-root "${OUT_ROOT}"$(
  [[ -n "${ONLY_MATRICES}" ]] && printf ' \\\n  --only-matrices "%s"' "${ONLY_MATRICES}"
  )
REPLAY_EOF
chmod +x "${REPLAY_FILE}"

# =============================================================================
# Summary Output
# =============================================================================
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  CONFORMANCE REVALIDATION — ${RUN_ID}"
echo "════════════════════════════════════════════════════════════════════"
echo ""
echo "  Overall Status:       ${OVERALL_STATUS}"
echo "  CI Mode:              ${CI_MODE}"
echo ""
echo "  Matrices:             ${TOTAL_MATRICES} total"
echo "    Pass:               ${MATRIX_PASS}"
echo "    Fail:               ${MATRIX_FAIL}"
echo "    Skip:               ${MATRIX_SKIP}"
echo ""
echo "  Drift Records:        ${DRIFT_COUNT}"
if [[ -n "${ONLY_MATRICES}" ]]; then
  echo "  Filter:               ${ONLY_MATRICES}"
fi
echo ""
echo "  Artifacts:            ${OUT_ROOT}/"
echo "    summary.json             — revalidation summary"
echo "    steps.jsonl              — per-matrix forensic steps"
echo "    drift_classification.json — drift records with contract IDs"
echo "    replay.sh                — deterministic replay"
echo "    logs/                    — per-matrix execution logs"
echo ""
echo "════════════════════════════════════════════════════════════════════"

if [[ "${OVERALL_STATUS}" == "fail" ]]; then
  echo ""
  echo "  Drift records requiring investigation:"
  jq -r '.drift_records[] | "  - [\(.classification)] \(.matrix)/\(.test_name): \(.reason[:120])"' \
    "${DRIFT_FILE}" 2>/dev/null || true
  echo ""
  exit 1
fi
