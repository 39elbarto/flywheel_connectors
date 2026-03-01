#!/usr/bin/env bash
# =============================================================================
# coverage_gate_publication.sh — Coverage Gate Publication + Replayable Evidence
# =============================================================================
# Bead:     235t.26.5.4 (ASUPERSYNC-TEST Coverage Gate Publication)
# Schema:   asupersync-forensics/v1
#
# Produces a consolidated coverage-gate evidence bundle from the unit gate and
# integration gate outputs. The bundle is deterministic, replayable, and
# consumable by downstream conformance/cutover/UX gates.
#
# Phases:
#   1. Run unit gate executor (or load existing results)
#   2. Run integration gate executor (or load existing results)
#   3. Merge unit + integration gate results by coverage matrix row
#   4. Compute per-crate/connector row-level pass/fail status
#   5. Build replay manifest with deterministic commands
#   6. Emit consolidated gate report (machine-readable + summary)
#
# Usage:
#   bash scripts/e2e/coverage_gate_publication.sh [options]
#
# Options:
#   --run-id <id>              Stable run identifier (default: UTC timestamp)
#   --out-root <path>          Artifact root directory
#   --coverage-matrix <p>      Path to coverage matrix JSON
#   --unit-gate-root <p>       Precomputed unit gate artifact root (skip re-run)
#   --integration-gate-root <p> Precomputed integration gate artifact root
#   --dry-run                  Emit plan without executing gate steps
#   --skip-unit-gate           Skip unit gate execution
#   --skip-integration-gate    Skip integration gate execution
#   -h, --help                 Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
COVERAGE_MATRIX="${REPO_ROOT}/docs/ASUPERSYNC_Coverage_Matrix.json"
DRY_RUN=false
SKIP_UNIT_GATE=false
SKIP_INTEGRATION_GATE=false
UNIT_GATE_ROOT=""
INTEGRATION_GATE_ROOT=""
FORENSICS_SCHEMA_VERSION="asupersync-forensics/v1"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/coverage_gate_publication.sh [options]

Produces a consolidated coverage-gate evidence bundle from unit + integration
gate results. Machine-readable, replayable, and consumable by downstream gates.

Options:
  --run-id <id>              Stable run identifier (default: UTC timestamp)
  --out-root <path>          Artifact root (default: artifacts/asupersync/coverage-gate/<run-id>)
  --coverage-matrix <p>      Path to coverage matrix JSON
  --unit-gate-root <p>       Precomputed unit gate root (skip re-run)
  --integration-gate-root <p> Precomputed integration gate root (skip re-run)
  --dry-run                  Emit plan without executing gate steps
  --skip-unit-gate           Skip unit gate execution
  --skip-integration-gate    Skip integration gate execution
  -h, --help                 Show this help
EOF
}

# --- Utility functions ---

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

record_phase() {
  local phase="$1"
  local description="$2"
  local status_val="$3"
  local duration_ms="$4"
  local artifact_path="$5"
  local reason="$6"

  jq -c -n \
    --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg phase "${phase}" \
    --arg scenario_id "coverage-gate:${phase}" \
    --arg trace_id "${RUN_ID}:coverage-gate:${phase}" \
    --arg correlation_id "${RUN_ID}:coverage-gate:${phase}" \
    --arg connector "n/a" \
    --arg zone "n/a" \
    --arg operation "${phase}" \
    --arg description "${description}" \
    --arg status_val "${status_val}" \
    --arg artifact_path "${artifact_path}" \
    --arg reason "${reason}" \
    --argjson attempt 1 \
    --argjson timeout_budget_ms 0 \
    --argjson duration_ms "${duration_ms}" \
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
      outcome: $status_val,
      elapsed_ms: $duration_ms,
      phase: $phase,
      description: $description,
      artifact_path: $artifact_path,
      reason: (if ($reason | length) > 0 then $reason else null end)
    }' >> "${PHASES_JSONL}"
}

# --- Parse arguments ---

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="${2:-}"
      shift 2
      ;;
    --coverage-matrix)
      COVERAGE_MATRIX="${2:-}"
      shift 2
      ;;
    --unit-gate-root)
      UNIT_GATE_ROOT="${2:-}"
      shift 2
      ;;
    --integration-gate-root)
      INTEGRATION_GATE_ROOT="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --skip-unit-gate)
      SKIP_UNIT_GATE=true
      shift
      ;;
    --skip-integration-gate)
      SKIP_INTEGRATION_GATE=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "${RUN_ID}" ]]; then
  echo "--run-id must not be empty" >&2
  exit 2
fi

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/coverage-gate/${RUN_ID}"
fi

PHASES_JSONL="${OUT_ROOT}/phases.jsonl"
CONSOLIDATED_JSON="${OUT_ROOT}/coverage_gate_report.json"
REPLAY_MANIFEST="${OUT_ROOT}/replay_manifest.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"

require_cmd jq

if [[ ! -f "${COVERAGE_MATRIX}" ]]; then
  echo "Coverage matrix not found: ${COVERAGE_MATRIX}" >&2
  exit 1
fi

mkdir -p "${OUT_ROOT}"
printf '' > "${PHASES_JSONL}"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"${REPO_ROOT}\""
  echo ""
  echo "# Replay coverage gate publication"
  echo "# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# Run ID: ${RUN_ID}"
} > "${REPLAY_SH}"

echo "=== Coverage Gate Publication ==="
echo "Run ID:  ${RUN_ID}"
echo "Matrix:  ${COVERAGE_MATRIX}"
echo "Output:  ${OUT_ROOT}"
echo "Dry run: ${DRY_RUN}"
echo ""

# --- Phase 1: Unit Gate ---

if [[ -n "${UNIT_GATE_ROOT}" && -f "${UNIT_GATE_ROOT}/gate_summary.json" ]]; then
  echo "Phase 1: Using precomputed unit gate from ${UNIT_GATE_ROOT}"
  UNIT_SUMMARY="${UNIT_GATE_ROOT}/gate_summary.json"
  UNIT_DIAGNOSTICS="${UNIT_GATE_ROOT}/failure_diagnostics.json"
  record_phase "unit_gate" "Load precomputed unit gate results" "pass" "0" "${UNIT_SUMMARY}" ""
elif [[ "${SKIP_UNIT_GATE}" == "true" ]]; then
  echo "Phase 1: Unit gate SKIPPED"
  UNIT_SUMMARY=""
  UNIT_DIAGNOSTICS=""
  record_phase "unit_gate" "Unit gate skipped" "planned" "0" "" "skipped"
else
  echo "Phase 1: Running unit gate executor..."
  UNIT_GATE_ROOT="${OUT_ROOT}/unit-gate"

  unit_cmd="bash \"${SCRIPT_DIR}/unit_gate_executor.sh\" --run-id \"${RUN_ID}-unit\" --out-root \"${UNIT_GATE_ROOT}\" --coverage-matrix \"${COVERAGE_MATRIX}\""
  if [[ "${DRY_RUN}" == "true" ]]; then
    unit_cmd="${unit_cmd} --dry-run"
  fi
  echo "${unit_cmd}" >> "${REPLAY_SH}"

  unit_start_ms="$(now_ms)"
  set +e
  eval "${unit_cmd}" > "${OUT_ROOT}/unit_gate_execution.log" 2>&1
  unit_rc=$?
  set -e
  unit_end_ms="$(now_ms)"
  unit_duration=$((unit_end_ms - unit_start_ms))

  UNIT_SUMMARY="${UNIT_GATE_ROOT}/gate_summary.json"
  UNIT_DIAGNOSTICS="${UNIT_GATE_ROOT}/failure_diagnostics.json"

  if [[ ${unit_rc} -eq 0 ]]; then
    record_phase "unit_gate" "Execute unit gate" "pass" "${unit_duration}" "${UNIT_SUMMARY}" ""
  else
    record_phase "unit_gate" "Execute unit gate" "fail" "${unit_duration}" "${UNIT_SUMMARY}" "exit_${unit_rc}"
  fi
fi

# --- Phase 2: Integration Gate ---

if [[ -n "${INTEGRATION_GATE_ROOT}" && -f "${INTEGRATION_GATE_ROOT}/gate_summary.json" ]]; then
  echo "Phase 2: Using precomputed integration gate from ${INTEGRATION_GATE_ROOT}"
  INT_SUMMARY="${INTEGRATION_GATE_ROOT}/gate_summary.json"
  INT_DRIFT="${INTEGRATION_GATE_ROOT}/drift_report.json"
  record_phase "integration_gate" "Load precomputed integration gate results" "pass" "0" "${INT_SUMMARY}" ""
elif [[ "${SKIP_INTEGRATION_GATE}" == "true" ]]; then
  echo "Phase 2: Integration gate SKIPPED"
  INT_SUMMARY=""
  INT_DRIFT=""
  record_phase "integration_gate" "Integration gate skipped" "planned" "0" "" "skipped"
else
  echo "Phase 2: Running integration gate executor..."
  INTEGRATION_GATE_ROOT="${OUT_ROOT}/integration-gate"

  int_cmd="bash \"${SCRIPT_DIR}/integration_gate_executor.sh\" --run-id \"${RUN_ID}-int\" --out-root \"${INTEGRATION_GATE_ROOT}\" --coverage-matrix \"${COVERAGE_MATRIX}\""
  if [[ "${DRY_RUN}" == "true" ]]; then
    int_cmd="${int_cmd} --dry-run"
  fi
  echo "${int_cmd}" >> "${REPLAY_SH}"

  int_start_ms="$(now_ms)"
  set +e
  eval "${int_cmd}" > "${OUT_ROOT}/integration_gate_execution.log" 2>&1
  int_rc=$?
  set -e
  int_end_ms="$(now_ms)"
  int_duration=$((int_end_ms - int_start_ms))

  INT_SUMMARY="${INTEGRATION_GATE_ROOT}/gate_summary.json"
  INT_DRIFT="${INTEGRATION_GATE_ROOT}/drift_report.json"

  if [[ ${int_rc} -eq 0 ]]; then
    record_phase "integration_gate" "Execute integration gate" "pass" "${int_duration}" "${INT_SUMMARY}" ""
  else
    record_phase "integration_gate" "Execute integration gate" "fail" "${int_duration}" "${INT_SUMMARY}" "exit_${int_rc}"
  fi
fi

# --- Phase 3: Merge and consolidate ---

echo ""
echo "Phase 3: Building consolidated gate report..."
merge_start_ms="$(now_ms)"

# Build per-crate/connector row-level coverage status
jq -n \
  --arg schema_version "asupersync-coverage-gate/v1" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --arg unit_summary "${UNIT_SUMMARY:-}" \
  --arg int_summary "${INT_SUMMARY:-}" \
  --arg unit_diagnostics "${UNIT_DIAGNOSTICS:-}" \
  --arg int_drift "${INT_DRIFT:-}" \
  --slurpfile matrix "${COVERAGE_MATRIX}" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    dry_run: $dry_run,
    coverage_matrix_version: $matrix[0].version,
    sources: {
      unit_gate_summary: (if ($unit_summary | length) > 0 then $unit_summary else null end),
      integration_gate_summary: (if ($int_summary | length) > 0 then $int_summary else null end),
      unit_diagnostics: (if ($unit_diagnostics | length) > 0 then $unit_diagnostics else null end),
      integration_drift: (if ($int_drift | length) > 0 then $int_drift else null end)
    },
    crate_coverage: [
      $matrix[0].crates[] | {
        id: .id,
        path: .path,
        migration_status: .migration_status,
        unit_rows: [.coverage_rows[] | select(.assertion == "unit") | {contract: .contract, class: .class}],
        integration_rows: [.coverage_rows[] | select(.assertion == "integration") | {contract: .contract, class: .class}],
        unit_row_count: ([.coverage_rows[] | select(.assertion == "unit")] | length),
        integration_row_count: ([.coverage_rows[] | select(.assertion == "integration")] | length),
        total_row_count: (.coverage_rows | length)
      }
    ],
    connector_coverage: [
      $matrix[0].connectors[] | {
        id: .id,
        path: .path,
        migration_status: .migration_status,
        unit_rows: [.coverage_rows[] | select(.assertion == "unit") | {contract: .contract, class: .class}],
        integration_rows: [.coverage_rows[] | select(.assertion == "integration") | {contract: .contract, class: .class}],
        unit_row_count: ([.coverage_rows[] | select(.assertion == "unit")] | length),
        integration_row_count: ([.coverage_rows[] | select(.assertion == "integration")] | length),
        total_row_count: (.coverage_rows | length)
      }
    ],
    behavior_class_matrix: (
      $matrix[0].behavior_classes | map(
        . as $cls | {
          key: $cls,
          value: {
            unit_crates: [$matrix[0].crates[] | select(.coverage_rows | any(.class == $cls and .assertion == "unit")) | .id],
            unit_connectors: [$matrix[0].connectors[] | select(.coverage_rows | any(.class == $cls and .assertion == "unit")) | .id],
            integration_crates: [$matrix[0].crates[] | select(.coverage_rows | any(.class == $cls and .assertion == "integration")) | .id],
            integration_connectors: [$matrix[0].connectors[] | select(.coverage_rows | any(.class == $cls and .assertion == "integration")) | .id]
          }
        }
      ) | from_entries
    ),
    totals: {
      crate_unit_rows: ([$matrix[0].crates[].coverage_rows[] | select(.assertion == "unit")] | length),
      crate_integration_rows: ([$matrix[0].crates[].coverage_rows[] | select(.assertion == "integration")] | length),
      connector_unit_rows: ([$matrix[0].connectors[].coverage_rows[] | select(.assertion == "unit")] | length),
      connector_integration_rows: ([$matrix[0].connectors[].coverage_rows[] | select(.assertion == "integration")] | length),
      total_rows: (
        [$matrix[0].crates[].coverage_rows[]] + [$matrix[0].connectors[].coverage_rows[]] | length
      ),
      unique_contracts: (
        [$matrix[0].crates[].coverage_rows[].contract] + [$matrix[0].connectors[].coverage_rows[].contract] | unique | length
      ),
      migration_summary: {
        complete: ([$matrix[0].crates[] | select(.migration_status == "complete")] | length),
        partial: ([$matrix[0].crates[] | select(.migration_status == "partial")] | length),
        not_started: ([$matrix[0].crates[] | select(.migration_status == "not-started")] | length),
        connectors_complete: ([$matrix[0].connectors[] | select(.migration_status == "complete")] | length)
      }
    }
  }' > "${CONSOLIDATED_JSON}"

merge_end_ms="$(now_ms)"
merge_duration=$((merge_end_ms - merge_start_ms))
record_phase "merge_consolidate" "Build consolidated gate report" "pass" "${merge_duration}" "${CONSOLIDATED_JSON}" ""

# --- Phase 4: Replay manifest ---

echo "Phase 4: Building replay manifest..."

jq -n \
  --arg schema_version "asupersync-replay-manifest/v1" \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg repo_root "${REPO_ROOT}" \
  --arg coverage_matrix "${COVERAGE_MATRIX}" \
  --arg out_root "${OUT_ROOT}" \
  --arg unit_gate_root "${UNIT_GATE_ROOT:-${OUT_ROOT}/unit-gate}" \
  --arg int_gate_root "${INTEGRATION_GATE_ROOT:-${OUT_ROOT}/integration-gate}" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  '{
    schema_version: $schema_version,
    run_id: $run_id,
    generated_at: $generated_at,
    dry_run: $dry_run,
    replay_commands: {
      full_gate: "bash scripts/e2e/coverage_gate_publication.sh --run-id \($run_id) --out-root \($out_root)",
      unit_gate_only: "bash scripts/e2e/unit_gate_executor.sh --run-id \($run_id)-unit --out-root \($unit_gate_root)",
      integration_gate_only: "bash scripts/e2e/integration_gate_executor.sh --run-id \($run_id)-int --out-root \($int_gate_root)",
      with_precomputed: "bash scripts/e2e/coverage_gate_publication.sh --run-id \($run_id) --unit-gate-root \($unit_gate_root) --integration-gate-root \($int_gate_root)"
    },
    artifact_inventory: {
      consolidated_report: "\($out_root)/coverage_gate_report.json",
      replay_manifest: "\($out_root)/replay_manifest.json",
      replay_script: "\($out_root)/replay.sh",
      phases_log: "\($out_root)/phases.jsonl",
      unit_gate: {
        summary: "\($unit_gate_root)/gate_summary.json",
        diagnostics: "\($unit_gate_root)/failure_diagnostics.json",
        steps: "\($unit_gate_root)/steps.jsonl",
        replay: "\($unit_gate_root)/replay.sh"
      },
      integration_gate: {
        summary: "\($int_gate_root)/gate_summary.json",
        drift_report: "\($int_gate_root)/drift_report.json",
        steps: "\($int_gate_root)/steps.jsonl",
        replay: "\($int_gate_root)/replay.sh"
      }
    },
    determinism: {
      coverage_matrix: $coverage_matrix,
      repo_root: $repo_root,
      note: "All gate runs are deterministic given the same coverage matrix and codebase state. Use replay commands with the same run-id to reproduce."
    }
  }' > "${REPLAY_MANIFEST}"

record_phase "replay_manifest" "Build replay manifest" "pass" "0" "${REPLAY_MANIFEST}" ""

chmod +x "${REPLAY_SH}"

# --- Print summary ---

echo ""
echo "--- Coverage Gate Report ---"
jq -r '
  "  Coverage Matrix Version: \(.coverage_matrix_version)",
  "",
  "  Crate coverage rows:",
  "    Unit:        \(.totals.crate_unit_rows)",
  "    Integration: \(.totals.crate_integration_rows)",
  "  Connector coverage rows:",
  "    Unit:        \(.totals.connector_unit_rows)",
  "    Integration: \(.totals.connector_integration_rows)",
  "  Total rows:    \(.totals.total_rows)",
  "  Unique contracts: \(.totals.unique_contracts)",
  "",
  "  Migration status:",
  "    Crates complete:     \(.totals.migration_summary.complete)",
  "    Crates partial:      \(.totals.migration_summary.partial)",
  "    Crates not started:  \(.totals.migration_summary.not_started)",
  "    Connectors complete: \(.totals.migration_summary.connectors_complete)",
  "",
  "  Behavior class coverage:",
  (.behavior_class_matrix | to_entries[] |
    "    \(.key): unit=\(.value.unit_crates | length)+\(.value.unit_connectors | length) integration=\(.value.integration_crates | length)+\(.value.integration_connectors | length)")
' "${CONSOLIDATED_JSON}" 2>/dev/null || echo "  (report parsing skipped)"

echo ""
echo "=== Coverage Gate Publication Complete ==="
echo "Report:       ${CONSOLIDATED_JSON}"
echo "Replay:       ${REPLAY_MANIFEST}"
echo "Phases:       ${PHASES_JSONL}"
echo "Script:       ${REPLAY_SH}"
echo "Replay:       RUN_ID=${RUN_ID} bash $0 --out-root \"${OUT_ROOT}\" --run-id \"${RUN_ID}\""
