#!/usr/bin/env bash
# =============================================================================
# integration_gate_executor.sh — Integration Gate + Cross-Connector Drift Check
# =============================================================================
# Bead:     235t.26.5.3 (ASUPERSYNC-TEST Integration Gate Executor)
# Schema:   asupersync-forensics/v1
#
# Enforces integration-level coverage completion and detects cross-connector
# behavioral drift against parity contracts declared in the Coverage Matrix.
#
# Phases:
#   1. Load coverage matrix and extract required integration rows
#   2. Run crate integration tests (host, sdk, conformance)
#   3. Run connector integration tests (anthropic, openai, discord, etc.)
#   4. Cross-connector drift check (compare observed vs expected contracts)
#   5. Emit gate report with pass/fail, drift summary, and replay manifest
#
# Usage:
#   bash scripts/e2e/integration_gate_executor.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --coverage-matrix <p>   Path to coverage matrix JSON
#   --dry-run               Emit commands/artifacts without executing
#   --only-crates <list>    Comma-separated crate filter (e.g., fcp-host,fcp-sdk)
#   --only-connectors <l>   Comma-separated connector filter
#   --skip-crate-tests      Skip crate integration test steps
#   --skip-connector-tests  Skip connector test steps
#   --skip-drift-check      Skip cross-connector drift analysis
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
COVERAGE_MATRIX="${REPO_ROOT}/docs/ASUPERSYNC_Coverage_Matrix.json"
DRY_RUN=false
SKIP_CRATE_TESTS=false
SKIP_CONNECTOR_TESTS=false
SKIP_DRIFT_CHECK=false
ONLY_CRATES=""
ONLY_CONNECTORS=""
FORENSICS_SCHEMA_VERSION="asupersync-forensics/v1"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/integration_gate_executor.sh [options]

Runs the ASUPERSYNC integration gate and cross-connector drift check.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/integration-gate/<run-id>)
  --coverage-matrix <p>   Path to coverage matrix JSON (default: docs/ASUPERSYNC_Coverage_Matrix.json)
  --dry-run               Emit plan without executing heavy steps
  --only-crates <list>    Comma-separated crate filter
  --only-connectors <l>   Comma-separated connector filter
  --skip-crate-tests      Skip crate integration test steps
  --skip-connector-tests  Skip connector test steps
  --skip-drift-check      Skip cross-connector drift analysis
  -h, --help              Show this help
EOF
}

# --- Utility functions (shared pattern) ---

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

record_step() {
  local step="$1"
  local description="$2"
  local required="$3"
  local command="$4"
  local status="$5"
  local duration_ms="$6"
  local log_path="$7"
  local reason="$8"

  jq -c -n \
    --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg step "${step}" \
    --arg scenario_id "${step}" \
    --arg trace_id "${RUN_ID}:${step}" \
    --arg correlation_id "${RUN_ID}:${step}" \
    --arg connector "n/a" \
    --arg zone "n/a" \
    --arg operation "${step}" \
    --arg description "${description}" \
    --arg command "${command}" \
    --arg status "${status}" \
    --arg log_path "${log_path}" \
    --arg reason "${reason}" \
    --argjson required "${required}" \
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
      cancellation_reason: (if ($reason | startswith("cancel")) then $reason else null end),
      queue_depth: null,
      decode_budget: null,
      outcome: $status,
      elapsed_ms: $duration_ms,
      step: $step,
      description: $description,
      required: $required,
      command: $command,
      status: $status,
      duration_ms: $duration_ms,
      log_path: $log_path,
      reason: (if ($reason | length) > 0 then $reason else null end)
    }' >> "${STEPS_JSONL}"
}

validate_step_record() {
  local record="$1"
  local line_no="$2"

  if ! jq -e \
    --arg expected_run_id "${RUN_ID}" \
    --arg expected_schema "${FORENSICS_SCHEMA_VERSION}" \
    '{
      ok: (
        .schema_version == $expected_schema
        and .run_id == $expected_run_id
        and (.scenario_id | type == "string")
        and (.trace_id | type == "string")
        and (.correlation_id | type == "string")
        and (.connector | type == "string")
        and (.zone | type == "string")
        and (.operation | type == "string")
        and (.attempt | type == "number")
        and (.timeout_budget_ms | type == "number")
        and (.outcome | IN("pass", "fail", "planned"))
        and (.elapsed_ms | type == "number")
      )
    } | .ok' <<< "${record}" >/dev/null; then
    echo "Invalid forensics step record at line ${line_no}: ${record}" >&2
    exit 1
  fi
}

validate_steps_jsonl() {
  local line_no=0
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_no=$((line_no + 1))
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi
    validate_step_record "${line}" "${line_no}"
  done < "${STEPS_JSONL}"
}

run_step() {
  local step="$1"
  local description="$2"
  local required="$3"
  local command="$4"

  local step_dir="${OUT_ROOT}/${step}"
  local log_path="${step_dir}/execution.log"
  local start_ms end_ms duration_ms rc status reason

  mkdir -p "${step_dir}"
  printf '%s\n' "${command}" > "${step_dir}/command.txt"

  if [[ "${DRY_RUN}" == "true" ]]; then
    status="planned"
    reason="dry_run"
    duration_ms=0
    record_step "${step}" "${description}" "${required}" "${command}" "${status}" "${duration_ms}" "${log_path}" "${reason}"
    return 0
  fi

  start_ms="$(now_ms)"
  set +e
  bash -lc "set -euo pipefail; cd \"${REPO_ROOT}\"; ${command}" >"${log_path}" 2>&1
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    status="pass"
    reason=""
  else
    status="fail"
    reason="exit_${rc}"
  fi

  record_step "${step}" "${description}" "${required}" "${command}" "${status}" "${duration_ms}" "${log_path}" "${reason}"
}

# Filter check: is this crate/connector in the --only filter?
in_filter() {
  local name="$1"
  local filter="$2"
  if [[ -z "${filter}" ]]; then
    return 0
  fi
  echo "${filter}" | tr ',' '\n' | grep -qxF "${name}"
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
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --only-crates)
      ONLY_CRATES="${2:-}"
      shift 2
      ;;
    --only-connectors)
      ONLY_CONNECTORS="${2:-}"
      shift 2
      ;;
    --skip-crate-tests)
      SKIP_CRATE_TESTS=true
      shift
      ;;
    --skip-connector-tests)
      SKIP_CONNECTOR_TESTS=true
      shift
      ;;
    --skip-drift-check)
      SKIP_DRIFT_CHECK=true
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
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/integration-gate/${RUN_ID}"
fi

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
SUMMARY_JSON="${OUT_ROOT}/gate_summary.json"
DRIFT_JSON="${OUT_ROOT}/drift_report.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"

require_cmd jq
require_cmd rch

if [[ ! -f "${COVERAGE_MATRIX}" ]]; then
  echo "Coverage matrix not found: ${COVERAGE_MATRIX}" >&2
  exit 1
fi

mkdir -p "${OUT_ROOT}"
printf '' > "${STEPS_JSONL}"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"${REPO_ROOT}\""
} > "${REPLAY_SH}"

echo "=== Integration Gate Executor ==="
echo "Run ID:  ${RUN_ID}"
echo "Matrix:  ${COVERAGE_MATRIX}"
echo "Output:  ${OUT_ROOT}"
echo "Dry run: ${DRY_RUN}"
echo ""

# --- Step 1: Matrix validation ---

run_step \
  "matrix_validation" \
  "Validate coverage matrix schema and extract integration rows" \
  "true" \
  "jq -e '.crates | length > 0' \"${COVERAGE_MATRIX}\" && jq -e '.connectors | length > 0' \"${COVERAGE_MATRIX}\""

# --- Step 2: Extract integration contracts from matrix ---

INTEGRATION_CONTRACTS_JSON="${OUT_ROOT}/integration_contracts.json"

# Build the expected integration contracts list from the matrix
jq '{
  crate_contracts: [
    .crates[] | {
      id: .id,
      path: .path,
      migration_status: .migration_status,
      rows: [.coverage_rows[] | select(.assertion == "integration")]
    } | select(.rows | length > 0)
  ],
  connector_contracts: [
    .connectors[] | {
      id: .id,
      path: .path,
      migration_status: .migration_status,
      rows: .coverage_rows
    }
  ],
  behavior_classes: .behavior_classes,
  total_integration_rows: (
    [.crates[].coverage_rows[] | select(.assertion == "integration")] | length
  ),
  total_connector_rows: (
    [.connectors[].coverage_rows[]] | length
  )
}' "${COVERAGE_MATRIX}" > "${INTEGRATION_CONTRACTS_JSON}"

echo "Integration contracts extracted:"
jq -r '"  Crate integration rows: \(.total_integration_rows)"' "${INTEGRATION_CONTRACTS_JSON}"
jq -r '"  Connector coverage rows: \(.total_connector_rows)"' "${INTEGRATION_CONTRACTS_JSON}"
echo ""

# --- Step 3: Crate integration tests ---

if [[ "${SKIP_CRATE_TESTS}" != "true" ]]; then
  # Crates with integration-level coverage rows
  CRATE_IDS=$(jq -r '.crate_contracts[].id' "${INTEGRATION_CONTRACTS_JSON}")

  for crate_id in ${CRATE_IDS}; do
    if ! in_filter "${crate_id}" "${ONLY_CRATES}"; then
      continue
    fi

    contracts=$(jq -r --arg id "${crate_id}" '.crate_contracts[] | select(.id == $id) | [.rows[].contract] | join(", ")' "${INTEGRATION_CONTRACTS_JSON}")

    CMD="rch exec -- cargo test -p ${crate_id} --test '*' -- --nocapture"
    echo "${CMD}" >> "${REPLAY_SH}"

    run_step \
      "crate_integration_${crate_id}" \
      "Integration tests for ${crate_id} (contracts: ${contracts})" \
      "true" \
      "${CMD}"
  done

  # Also run unit tests for crates that have only unit-level rows but are
  # integration-critical (fcp-sdk error contracts, fcp-streaming, fcp-ratelimit)
  UNIT_CRITICAL_CRATES="fcp-sdk fcp-streaming fcp-ratelimit fcp-store fcp-crypto"
  for crate_id in ${UNIT_CRITICAL_CRATES}; do
    if ! in_filter "${crate_id}" "${ONLY_CRATES}"; then
      continue
    fi

    # Check this crate is in the matrix
    if ! jq -e --arg id "${crate_id}" '.crates[] | select(.id == $id)' "${COVERAGE_MATRIX}" >/dev/null 2>&1; then
      continue
    fi

    contracts=$(jq -r --arg id "${crate_id}" '.crates[] | select(.id == $id) | [.coverage_rows[].contract] | join(", ")' "${COVERAGE_MATRIX}")

    CMD="rch exec -- cargo test -p ${crate_id} --all-targets -- --nocapture"
    echo "${CMD}" >> "${REPLAY_SH}"

    run_step \
      "crate_unit_${crate_id}" \
      "Unit+integration tests for ${crate_id} (contracts: ${contracts})" \
      "true" \
      "${CMD}"
  done
fi

# --- Step 4: Connector tests ---

if [[ "${SKIP_CONNECTOR_TESTS}" != "true" ]]; then
  CONNECTOR_IDS=$(jq -r '.connector_contracts[].id' "${INTEGRATION_CONTRACTS_JSON}")

  for conn_id in ${CONNECTOR_IDS}; do
    if ! in_filter "${conn_id}" "${ONLY_CONNECTORS}"; then
      continue
    fi

    contracts=$(jq -r --arg id "${conn_id}" '.connector_contracts[] | select(.id == $id) | [.rows[].contract] | join(", ")' "${INTEGRATION_CONTRACTS_JSON}")

    CMD="rch exec -- cargo test -p connector-${conn_id} --all-targets -- --nocapture"
    echo "${CMD}" >> "${REPLAY_SH}"

    run_step \
      "connector_${conn_id}" \
      "Connector tests for ${conn_id} (contracts: ${contracts})" \
      "true" \
      "${CMD}"
  done
fi

# --- Step 5: Cross-connector drift check ---

if [[ "${SKIP_DRIFT_CHECK}" != "true" ]]; then
  echo "Running cross-connector drift check..."
  DRIFT_STEP_DIR="${OUT_ROOT}/drift_check"
  mkdir -p "${DRIFT_STEP_DIR}"

  # Build drift report by analyzing step results against expected contracts
  if [[ "${DRY_RUN}" == "true" ]]; then
    # Emit skeleton drift report
    jq -n \
      --arg run_id "${RUN_ID}" \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{
        schema_version: "asupersync-drift-report/v1",
        run_id: $run_id,
        generated_at: $generated_at,
        mode: "dry_run",
        crate_drift: [],
        connector_drift: [],
        cross_connector_analysis: {
          shared_contracts: [],
          archetype_coverage: {},
          behavior_class_coverage: {}
        },
        summary: {
          total_expected_contracts: 0,
          verified_contracts: 0,
          missing_contracts: 0,
          drift_detected: false
        }
      }' > "${DRIFT_JSON}"
    record_step "drift_check" "Cross-connector drift analysis (dry run)" "true" "jq (drift analysis)" "planned" "0" "${DRIFT_STEP_DIR}/execution.log" "dry_run"
  else
    local_start_ms="$(now_ms)"
    set +e
    (
      # Parse step results to determine which test suites passed
      passed_crates=""
      failed_crates=""
      passed_connectors=""
      failed_connectors=""

      while IFS= read -r line; do
        step=$(jq -r '.step' <<< "${line}")
        status=$(jq -r '.status' <<< "${line}")

        case "${step}" in
          crate_integration_*|crate_unit_*)
            crate_name="${step#crate_integration_}"
            crate_name="${crate_name#crate_unit_}"
            if [[ "${status}" == "pass" ]]; then
              passed_crates="${passed_crates} ${crate_name}"
            else
              failed_crates="${failed_crates} ${crate_name}"
            fi
            ;;
          connector_*)
            conn_name="${step#connector_}"
            if [[ "${status}" == "pass" ]]; then
              passed_connectors="${passed_connectors} ${conn_name}"
            else
              failed_connectors="${failed_connectors} ${conn_name}"
            fi
            ;;
        esac
      done < "${STEPS_JSONL}"

      # Build drift analysis JSON
      # For each connector, check if shared contracts (rate-limited-retry,
      # connector-lifecycle, etc.) are consistently present
      jq -n \
        --arg run_id "${RUN_ID}" \
        --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg passed_crates "${passed_crates}" \
        --arg failed_crates "${failed_crates}" \
        --arg passed_connectors "${passed_connectors}" \
        --arg failed_connectors "${failed_connectors}" \
        --slurpfile matrix "${COVERAGE_MATRIX}" \
        '{
          schema_version: "asupersync-drift-report/v1",
          run_id: $run_id,
          generated_at: $generated_at,
          mode: "live",
          crate_drift: [
            $matrix[0].crates[] |
            . as $crate |
            {
              id: .id,
              migration_status: .migration_status,
              contracts: [.coverage_rows[].contract],
              test_status: (
                if ($passed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id))
                then "pass"
                elif ($failed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id))
                then "fail"
                else "not_tested"
                end
              ),
              drift: (
                if ($failed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id))
                then "regression"
                elif (.migration_status == "complete") and
                     (($passed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id)) | not)
                then "coverage_gap"
                else "none"
                end
              )
            }
          ],
          connector_drift: [
            $matrix[0].connectors[] |
            . as $conn |
            {
              id: .id,
              migration_status: .migration_status,
              contracts: [.coverage_rows[].contract],
              test_status: (
                if ($passed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id))
                then "pass"
                elif ($failed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id))
                then "fail"
                else "not_tested"
                end
              ),
              drift: (
                if ($failed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id))
                then "regression"
                elif (.migration_status == "complete") and
                     (($passed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id)) | not)
                then "coverage_gap"
                else "none"
                end
              )
            }
          ],
          cross_connector_analysis: {
            shared_contracts: (
              $matrix[0].connectors | map(.coverage_rows[].contract) | group_by(.) |
              map({contract: .[0], count: length}) | sort_by(-.count) |
              map(select(.count > 1))
            ),
            archetype_coverage: {
              request_response: [$matrix[0].connectors[] | select(.coverage_rows | any(.class == "happy-path")) | .id],
              failure_handling: [$matrix[0].connectors[] | select(.coverage_rows | any(.class == "failure")) | .id],
              edge_cases: [$matrix[0].connectors[] | select(.coverage_rows | any(.class == "edge-case")) | .id]
            },
            behavior_class_coverage: (
              $matrix[0].behavior_classes | map(
                . as $cls |
                {
                  key: $cls,
                  value: {
                    crates: [$matrix[0].crates[] | select(.coverage_rows | any(.class == $cls)) | .id],
                    connectors: [$matrix[0].connectors[] | select(.coverage_rows | any(.class == $cls)) | .id]
                  }
                }
              ) | from_entries
            )
          },
          summary: {
            total_expected_contracts: (
              [$matrix[0].crates[].coverage_rows[].contract] +
              [$matrix[0].connectors[].coverage_rows[].contract] | unique | length
            ),
            crates_passed: ($passed_crates | split(" ") | map(select(length > 0)) | length),
            crates_failed: ($failed_crates | split(" ") | map(select(length > 0)) | length),
            connectors_passed: ($passed_connectors | split(" ") | map(select(length > 0)) | length),
            connectors_failed: ($failed_connectors | split(" ") | map(select(length > 0)) | length),
            drift_detected: (
              ($failed_crates | split(" ") | map(select(length > 0)) | length > 0) or
              ($failed_connectors | split(" ") | map(select(length > 0)) | length > 0)
            )
          }
        }' > "${DRIFT_JSON}"
    ) > "${DRIFT_STEP_DIR}/execution.log" 2>&1
    drift_rc=$?
    set -e
    local_end_ms="$(now_ms)"
    local_duration=$((local_end_ms - local_start_ms))

    if [[ ${drift_rc} -eq 0 ]]; then
      record_step "drift_check" "Cross-connector drift analysis" "true" "jq (drift analysis)" "pass" "${local_duration}" "${DRIFT_STEP_DIR}/execution.log" ""
    else
      record_step "drift_check" "Cross-connector drift analysis" "true" "jq (drift analysis)" "fail" "${local_duration}" "${DRIFT_STEP_DIR}/execution.log" "exit_${drift_rc}"
    fi
  fi

  # Print drift summary
  if [[ -f "${DRIFT_JSON}" ]]; then
    echo ""
    echo "--- Drift Report Summary ---"
    jq -r '
      "  Total unique contracts: \(.summary.total_expected_contracts // "N/A")",
      "  Crates passed/failed: \(.summary.crates_passed // 0)/\(.summary.crates_failed // 0)",
      "  Connectors passed/failed: \(.summary.connectors_passed // 0)/\(.summary.connectors_failed // 0)",
      "  Drift detected: \(.summary.drift_detected // false)",
      "",
      "  Shared contracts (cross-connector):",
      (.cross_connector_analysis.shared_contracts[:5][] |
        "    \(.contract): \(.count) connectors"),
      "",
      "  Behavior class coverage:",
      (.cross_connector_analysis.behavior_class_coverage | to_entries[] |
        "    \(.key): \(.value.crates | length) crates, \(.value.connectors | length) connectors")
    ' "${DRIFT_JSON}" 2>/dev/null || echo "  (drift report parsing skipped)"
  fi
fi

# --- Finalize: validate steps, build summary ---

chmod +x "${REPLAY_SH}"
validate_steps_jsonl

overall_passed=true
required_failed=false
total_steps=0
passed_steps=0
failed_steps=0
planned_steps=0

while IFS= read -r line; do
  status=$(jq -r '.status' <<< "${line}")
  required=$(jq -r '.required' <<< "${line}")
  total_steps=$((total_steps + 1))
  case "${status}" in
    pass) passed_steps=$((passed_steps + 1)) ;;
    fail)
      failed_steps=$((failed_steps + 1))
      overall_passed=false
      if [[ "${required}" == "true" ]]; then
        required_failed=true
      fi
      ;;
    planned) planned_steps=$((planned_steps + 1)) ;;
  esac
done < "${STEPS_JSONL}"

# Build gate summary
jq -s \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg drift_json "${DRIFT_JSON}" \
  --arg coverage_matrix "${COVERAGE_MATRIX}" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson required_failed "$([[ "${required_failed}" == "true" ]] && echo true || echo false)" \
  --argjson total_steps "${total_steps}" \
  --argjson passed_steps "${passed_steps}" \
  --argjson failed_steps "${failed_steps}" \
  --argjson planned_steps "${planned_steps}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    gate: "integration",
    out_root: $out_root,
    dry_run: $dry_run,
    passed: $passed,
    required_failed: $required_failed,
    coverage_matrix: $coverage_matrix,
    step_counts: {
      total: $total_steps,
      passed: $passed_steps,
      failed: $failed_steps,
      planned: $planned_steps
    },
    replay_script: $replay_sh,
    drift_report: $drift_json,
    steps: .
  }' "${STEPS_JSONL}" > "${SUMMARY_JSON}"

echo ""
echo "=== Integration Gate Result ==="
if [[ "${overall_passed}" == "true" ]]; then
  echo "GATE: PASS (${passed_steps}/${total_steps} steps passed)"
else
  echo "GATE: FAIL (${failed_steps}/${total_steps} steps failed)"
  if [[ "${required_failed}" == "true" ]]; then
    echo "  Required steps failed — gate blocked."
  fi
fi
echo ""
echo "Summary:   ${SUMMARY_JSON}"
echo "Drift:     ${DRIFT_JSON}"
echo "Steps:     ${STEPS_JSONL}"
echo "Replay:    ${REPLAY_SH}"
echo "Replay:    RUN_ID=${RUN_ID} bash $0 --out-root \"${OUT_ROOT}\" --run-id \"${RUN_ID}\""
