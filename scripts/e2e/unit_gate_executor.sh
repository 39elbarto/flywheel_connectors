#!/usr/bin/env bash
# =============================================================================
# unit_gate_executor.sh — Unit Gate Executor + Deterministic Failure Diagnostics
# =============================================================================
# Bead:     235t.26.5.2 (ASUPERSYNC-TEST Unit Gate Executor)
# Schema:   asupersync-forensics/v1
#
# Enforces unit-level coverage-row obligations from the ASUPERSYNC Coverage
# Matrix. Each crate/connector with assertion=="unit" coverage rows is tested,
# and failures are mapped back to their contract ID and behavior class for
# actionable diagnostics.
#
# Phases:
#   1. Load coverage matrix and extract required unit-assertion rows
#   2. Run crate unit tests for all crates with unit coverage rows
#   3. Run connector unit tests for all connectors with unit coverage rows
#   4. Map test outcomes to coverage row IDs and contract IDs
#   5. Emit deterministic failure diagnostics and stable fingerprints
#   6. Generate gate report, replay manifest, and rerun commands
#
# Usage:
#   bash scripts/e2e/unit_gate_executor.sh [options]
#
# Options:
#   --run-id <id>           Stable run identifier (default: UTC timestamp)
#   --out-root <path>       Artifact root directory
#   --coverage-matrix <p>   Path to coverage matrix JSON
#   --dry-run               Emit commands/artifacts without executing
#   --only-crates <list>    Comma-separated crate filter (e.g., fcp-sdk,fcp-crypto)
#   --only-connectors <l>   Comma-separated connector filter
#   --skip-crate-tests      Skip crate unit test steps
#   --skip-connector-tests  Skip connector unit test steps
#   -h, --help              Show this help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
COVERAGE_MATRIX="${REPO_ROOT}/docs/ASUPERSYNC_Coverage_Matrix.json"
DRY_RUN=false
ALLOW_PARTIAL=false
SKIP_CRATE_TESTS=false
SKIP_CONNECTOR_TESTS=false
ONLY_CRATES=""
ONLY_CONNECTORS=""
FORENSICS_SCHEMA_VERSION="asupersync-forensics/v1"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/unit_gate_executor.sh [options]

Runs the ASUPERSYNC unit gate: validates that all unit-level coverage-row
obligations from the Coverage Matrix are satisfied.

Options:
  --run-id <id>           Stable run identifier (default: UTC timestamp)
  --out-root <path>       Artifact root (default: artifacts/asupersync/unit-gate/<run-id>)
  --coverage-matrix <p>   Path to coverage matrix JSON (default: docs/ASUPERSYNC_Coverage_Matrix.json)
  --dry-run               Emit plan without executing heavy steps
  --allow-partial         Allow unowned coverage rows (for targeted/debug runs)
  --only-crates <list>    Comma-separated crate filter
  --only-connectors <l>   Comma-separated connector filter
  --skip-crate-tests      Skip crate unit test steps
  --skip-connector-tests  Skip connector unit test steps
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

# Deterministic failure fingerprint from a stable seed
failure_fingerprint() {
  local seed="$1"
  local hex
  hex=$(printf '%s' "${seed}" | hash256 | awk '{print $1}')
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

sanitize_target_id() {
  local raw="$1"
  raw="${raw//[^a-zA-Z0-9_]/_}"
  printf '%s' "${raw}"
}

target_dir_for() {
  local entity="$1"
  printf 'target_rch_unit_gate_%s_%s' \
    "$(sanitize_target_id "${RUN_ID}")" \
    "$(sanitize_target_id "${entity}")"
}

jq_number_or_zero() {
  local filter="$1"
  local file="$2"
  local value
  value="$(jq -r "${filter}" "${file}" 2>/dev/null || true)"
  if [[ -z "${value//[[:space:]]/}" ]]; then
    value="0"
  fi
  printf '%s' "${value}"
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
    --arg fingerprint "$(failure_fingerprint "step:${step}")" \
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
      cancellation_reason: null,
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
      fingerprint: $fingerprint,
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
    --allow-partial)
      ALLOW_PARTIAL=true
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
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/unit-gate/${RUN_ID}"
fi

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
SUMMARY_JSON="${OUT_ROOT}/gate_summary.json"
DIAGNOSTICS_JSON="${OUT_ROOT}/failure_diagnostics.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"
FORENSICS_VALIDATOR_REPORT="${OUT_ROOT}/forensics_validator_report.json"

require_cmd jq
require_cmd rch
if [[ ! -x "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" ]]; then
  echo "Expected executable script not found: ${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" >&2
  exit 1
fi

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

echo "=== Unit Gate Executor ==="
echo "Run ID:  ${RUN_ID}"
echo "Matrix:  ${COVERAGE_MATRIX}"
echo "Output:  ${OUT_ROOT}"
echo "Dry run: ${DRY_RUN}"
echo "Allow partial: ${ALLOW_PARTIAL}"
echo ""

# --- Step 1: Matrix validation ---

run_step \
  "matrix_validation" \
  "Validate coverage matrix schema and extract unit rows" \
  "true" \
  "jq -e '.crates | length > 0' \"${COVERAGE_MATRIX}\""

# --- Step 2: Extract unit contracts from matrix ---

UNIT_CONTRACTS_JSON="${OUT_ROOT}/unit_contracts.json"

jq '{
  crate_contracts: [
    .crates[] | {
      id: .id,
      path: .path,
      migration_status: .migration_status,
      rows: [.coverage_rows[] | select(.assertion == "unit")]
    } | select(.rows | length > 0)
  ],
  connector_contracts: [
    .connectors[] | {
      id: .id,
      path: .path,
      migration_status: .migration_status,
      rows: [.coverage_rows[] | select(.assertion == "unit")]
    } | select(.rows | length > 0)
  ],
  behavior_classes: .behavior_classes,
  total_unit_crate_rows: (
    [.crates[].coverage_rows[] | select(.assertion == "unit")] | length
  ),
  total_unit_connector_rows: (
    [.connectors[].coverage_rows[] | select(.assertion == "unit")] | length
  )
}' "${COVERAGE_MATRIX}" > "${UNIT_CONTRACTS_JSON}"

echo "Unit contracts extracted:"
jq -r '"  Crate unit rows: \(.total_unit_crate_rows)"' "${UNIT_CONTRACTS_JSON}"
jq -r '"  Connector unit rows: \(.total_unit_connector_rows)"' "${UNIT_CONTRACTS_JSON}"
echo ""

# --- Step 3: Crate unit tests ---

if [[ "${SKIP_CRATE_TESTS}" != "true" ]]; then
  CRATE_IDS=$(jq -r '.crate_contracts[].id' "${UNIT_CONTRACTS_JSON}")

  for crate_id in ${CRATE_IDS}; do
    if ! in_filter "${crate_id}" "${ONLY_CRATES}"; then
      continue
    fi

    contracts=$(jq -r --arg id "${crate_id}" \
      '.crate_contracts[] | select(.id == $id) | [.rows[].contract] | join(", ")' \
      "${UNIT_CONTRACTS_JSON}")

    classes=$(jq -r --arg id "${crate_id}" \
      '.crate_contracts[] | select(.id == $id) | [.rows[].class] | unique | join(", ")' \
      "${UNIT_CONTRACTS_JSON}")

    row_count=$(jq -r --arg id "${crate_id}" \
      '.crate_contracts[] | select(.id == $id) | .rows | length' \
      "${UNIT_CONTRACTS_JSON}")

    # fcp-cli has no library target, use --bins
    local_target_flag="--lib --tests"
    if [[ "${crate_id}" == "fcp-cli" ]]; then
      local_target_flag="--bins --tests"
    fi

    target_dir="$(target_dir_for "crate_${crate_id}")"
    CMD="CARGO_TARGET_DIR=${target_dir} rch exec -- cargo test -p ${crate_id} ${local_target_flag} -- --nocapture"
    echo "${CMD}" >> "${REPLAY_SH}"

    run_step \
      "unit_${crate_id}" \
      "Unit tests for ${crate_id} (${row_count} rows: ${contracts}) [classes: ${classes}]" \
      "true" \
      "${CMD}"
  done
fi

# --- Step 4: Connector unit tests ---

if [[ "${SKIP_CONNECTOR_TESTS}" != "true" ]]; then
  CONNECTOR_IDS=$(jq -r '.connector_contracts[].id' "${UNIT_CONTRACTS_JSON}")

  for conn_id in ${CONNECTOR_IDS}; do
    if ! in_filter "${conn_id}" "${ONLY_CONNECTORS}"; then
      continue
    fi

    contracts=$(jq -r --arg id "${conn_id}" \
      '.connector_contracts[] | select(.id == $id) | [.rows[].contract] | join(", ")' \
      "${UNIT_CONTRACTS_JSON}")

    classes=$(jq -r --arg id "${conn_id}" \
      '.connector_contracts[] | select(.id == $id) | [.rows[].class] | unique | join(", ")' \
      "${UNIT_CONTRACTS_JSON}")

    row_count=$(jq -r --arg id "${conn_id}" \
      '.connector_contracts[] | select(.id == $id) | .rows | length' \
      "${UNIT_CONTRACTS_JSON}")

    target_dir="$(target_dir_for "connector_${conn_id}")"
    CMD="CARGO_TARGET_DIR=${target_dir} rch exec -- cargo test -p connector-${conn_id} --lib --tests -- --nocapture"
    echo "${CMD}" >> "${REPLAY_SH}"

    run_step \
      "connector_unit_${conn_id}" \
      "Unit tests for connector-${conn_id} (${row_count} rows: ${contracts}) [classes: ${classes}]" \
      "true" \
      "${CMD}"
  done
fi

# --- Step 5: Deterministic failure diagnostics ---

echo "Building failure diagnostics..."
DIAG_STEP_DIR="${OUT_ROOT}/diagnostics"
mkdir -p "${DIAG_STEP_DIR}"

if [[ "${DRY_RUN}" == "true" ]]; then
  jq -n \
    --arg run_id "${RUN_ID}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
      schema_version: "asupersync-failure-diagnostics/v1",
      run_id: $run_id,
      generated_at: $generated_at,
      mode: "dry_run",
      crate_diagnostics: [],
      connector_diagnostics: [],
      unowned_rows: [],
      summary: {
        total_rows_checked: 0,
        rows_passed: 0,
        rows_failed: 0,
        rows_unowned: 0,
        deterministic: true
      }
    }' > "${DIAGNOSTICS_JSON}"
  record_step "failure_diagnostics" "Deterministic failure diagnostics (dry run)" "true" "jq (diagnostics)" "planned" "0" "${DIAG_STEP_DIR}/execution.log" "dry_run"
else
  diag_start_ms="$(now_ms)"
  set +e
  (
    # Parse step results to map test outcomes back to coverage rows
    passed_crates=""
    failed_crates=""
    passed_connectors=""
    failed_connectors=""

    while IFS= read -r line; do
      step=$(jq -r '.step' <<< "${line}")
      status=$(jq -r '.status' <<< "${line}")

      case "${step}" in
        unit_*)
          crate_name="${step#unit_}"
          if [[ "${status}" == "pass" ]]; then
            passed_crates="${passed_crates} ${crate_name}"
          else
            failed_crates="${failed_crates} ${crate_name}"
          fi
          ;;
        connector_unit_*)
          conn_name="${step#connector_unit_}"
          if [[ "${status}" == "pass" ]]; then
            passed_connectors="${passed_connectors} ${conn_name}"
          else
            failed_connectors="${failed_connectors} ${conn_name}"
          fi
          ;;
      esac
    done < "${STEPS_JSONL}"

    # Build diagnostics JSON with per-row contract mapping
    jq -n \
      --arg run_id "${RUN_ID}" \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg passed_crates "${passed_crates}" \
      --arg failed_crates "${failed_crates}" \
      --arg passed_connectors "${passed_connectors}" \
      --arg failed_connectors "${failed_connectors}" \
      --slurpfile matrix "${COVERAGE_MATRIX}" \
      '{
        schema_version: "asupersync-failure-diagnostics/v1",
        run_id: $run_id,
        generated_at: $generated_at,
        mode: "live",
        crate_diagnostics: [
          $matrix[0].crates[] |
          . as $crate |
          [.coverage_rows[] | select(.assertion == "unit")] as $unit_rows |
          select($unit_rows | length > 0) |
          {
            id: .id,
            path: .path,
            migration_status: .migration_status,
            test_status: (
              if ($passed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id))
              then "pass"
              elif ($failed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id))
              then "fail"
              else "not_tested"
              end
            ),
            coverage_rows: [
              $unit_rows[] | {
                contract: .contract,
                class: .class,
                row_id: "crate:\($crate.id):unit:\(.contract)",
                row_status: (
                  if ($passed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id))
                  then "satisfied"
                  elif ($failed_crates | split(" ") | map(select(length > 0)) | any(. == $crate.id))
                  then "failed"
                  else "unchecked"
                  end
                ),
                rerun_command: (
                  "CARGO_TARGET_DIR=target_rch_unit_gate_\($run_id | gsub("[^A-Za-z0-9_]"; "_"))_\($crate.id | gsub("[^A-Za-z0-9_]"; "_")) "
                  + "rch exec -- cargo test -p \($crate.id) "
                  + (if $crate.id == "fcp-cli" then "--bins --tests" else "--lib --tests" end)
                  + " -- --nocapture"
                )
              }
            ],
            fingerprint: (
              "diag:crate:\($crate.id):unit:"
              + ($unit_rows | map(.contract) | sort | join("|"))
            )
          }
        ],
        connector_diagnostics: [
          $matrix[0].connectors[] |
          . as $conn |
          [.coverage_rows[] | select(.assertion == "unit")] as $unit_rows |
          select($unit_rows | length > 0) |
          {
            id: .id,
            path: .path,
            migration_status: .migration_status,
            test_status: (
              if ($passed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id))
              then "pass"
              elif ($failed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id))
              then "fail"
              else "not_tested"
              end
            ),
            coverage_rows: [
              $unit_rows[] | {
                contract: .contract,
                class: .class,
                row_id: "connector:\($conn.id):unit:\(.contract)",
                row_status: (
                  if ($passed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id))
                  then "satisfied"
                  elif ($failed_connectors | split(" ") | map(select(length > 0)) | any(. == $conn.id))
                  then "failed"
                  else "unchecked"
                  end
                ),
                rerun_command: (
                  "CARGO_TARGET_DIR=target_rch_unit_gate_\($run_id | gsub("[^A-Za-z0-9_]"; "_"))_connector_\($conn.id | gsub("[^A-Za-z0-9_]"; "_")) "
                  + "rch exec -- cargo test -p connector-\($conn.id) --lib --tests -- --nocapture"
                )
              }
            ],
            fingerprint: (
              "diag:connector:\($conn.id):unit:"
              + ($unit_rows | map(.contract) | sort | join("|"))
            )
          }
        ],
        unowned_rows: (
          [
            $matrix[0].crates[] |
            . as $c |
            .coverage_rows[] |
            select(.assertion == "unit") |
            select(
              ($passed_crates + $failed_crates) | split(" ") |
              map(select(length > 0)) | any(. == $c.id) | not
            ) |
            {
              crate: $c.id,
              contract: .contract,
              class: .class,
              row_id: "crate:\($c.id):unit:\(.contract)",
              reason: "crate not tested in this run"
            }
          ] + [
            $matrix[0].connectors[] |
            . as $c |
            .coverage_rows[] |
            select(.assertion == "unit") |
            select(
              ($passed_connectors + $failed_connectors) | split(" ") |
              map(select(length > 0)) | any(. == $c.id) | not
            ) |
            {
              crate: ("connector-" + $c.id),
              contract: .contract,
              class: .class,
              row_id: "connector:\($c.id):unit:\(.contract)",
              reason: "connector not tested in this run"
            }
          ]
        ),
        summary: {
          total_rows_checked: (
            [
              $matrix[0].crates[].coverage_rows[] | select(.assertion == "unit")
            ] + [
              $matrix[0].connectors[].coverage_rows[] | select(.assertion == "unit")
            ] | length
          ),
          rows_passed: (
            [
              $matrix[0].crates[] | . as $c |
              select(
                $passed_crates | split(" ") | map(select(length > 0)) | any(. == $c.id)
              ) |
              [.coverage_rows[] | select(.assertion == "unit")] | length
            ] + [
              $matrix[0].connectors[] | . as $c |
              select(
                $passed_connectors | split(" ") | map(select(length > 0)) | any(. == $c.id)
              ) |
              [.coverage_rows[] | select(.assertion == "unit")] | length
            ] | add // 0
          ),
          rows_failed: (
            [
              $matrix[0].crates[] | . as $c |
              select(
                $failed_crates | split(" ") | map(select(length > 0)) | any(. == $c.id)
              ) |
              [.coverage_rows[] | select(.assertion == "unit")] | length
            ] + [
              $matrix[0].connectors[] | . as $c |
              select(
                $failed_connectors | split(" ") | map(select(length > 0)) | any(. == $c.id)
              ) |
              [.coverage_rows[] | select(.assertion == "unit")] | length
            ] | add // 0
          ),
          rows_unowned: (
            [
              $matrix[0].crates[] | . as $c |
              select(
                ($passed_crates + $failed_crates) | split(" ") |
                map(select(length > 0)) | any(. == $c.id) | not
              ) |
              [.coverage_rows[] | select(.assertion == "unit")] | length
            ] + [
              $matrix[0].connectors[] | . as $c |
              select(
                ($passed_connectors + $failed_connectors) | split(" ") |
                map(select(length > 0)) | any(. == $c.id) | not
              ) |
              [.coverage_rows[] | select(.assertion == "unit")] | length
            ] | add // 0
          ),
          deterministic: true
        }
      }' > "${DIAGNOSTICS_JSON}"

    printf 'diagnostics_generated_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'passed_crates=%s\n' "${passed_crates:-none}"
    printf 'failed_crates=%s\n' "${failed_crates:-none}"
    printf 'passed_connectors=%s\n' "${passed_connectors:-none}"
    printf 'failed_connectors=%s\n' "${failed_connectors:-none}"
  ) > "${DIAG_STEP_DIR}/execution.log" 2>&1
  diag_rc=$?
  set -e
  diag_end_ms="$(now_ms)"
  diag_duration=$((diag_end_ms - diag_start_ms))

  if [[ ${diag_rc} -eq 0 ]]; then
    record_step "failure_diagnostics" "Deterministic failure diagnostics" "true" "jq (diagnostics)" "pass" "${diag_duration}" "${DIAG_STEP_DIR}/execution.log" ""
  else
    record_step "failure_diagnostics" "Deterministic failure diagnostics" "true" "jq (diagnostics)" "fail" "${diag_duration}" "${DIAG_STEP_DIR}/execution.log" "exit_${diag_rc}"
  fi
fi

# Print diagnostics summary
if [[ -f "${DIAGNOSTICS_JSON}" ]]; then
  echo ""
  echo "--- Failure Diagnostics Summary ---"
  jq -r '
    "  Total unit rows: \(.summary.total_rows_checked)",
    "  Rows passed: \(.summary.rows_passed)",
    "  Rows failed: \(.summary.rows_failed)",
    "  Rows unowned: \(.summary.rows_unowned)",
    "  Deterministic: \(.summary.deterministic)"
  ' "${DIAGNOSTICS_JSON}" 2>/dev/null || echo "  (diagnostics parsing skipped)"

  # Print per-crate/connector failure details
  failed_count=$(jq '[.crate_diagnostics[], .connector_diagnostics[] | select(.test_status == "fail")] | length' "${DIAGNOSTICS_JSON}" 2>/dev/null || echo "0")
  if [[ "${failed_count}" -gt 0 ]]; then
    echo ""
    echo "  Failed crates/connectors:"
    jq -r '
      [.crate_diagnostics[], .connector_diagnostics[] | select(.test_status == "fail")] |
      .[] |
      "    \(.id): \([.coverage_rows[].contract] | join(", "))",
      "      fingerprint: \(.fingerprint)",
      "      rerun: \(.coverage_rows[0].rerun_command)"
    ' "${DIAGNOSTICS_JSON}" 2>/dev/null || true
  fi

  # Print behavior class coverage
  echo ""
  echo "  Behavior class breakdown:"
  jq -r '
    [.crate_diagnostics[], .connector_diagnostics[] | select(.test_status == "pass") | .coverage_rows[]] |
    group_by(.class) |
    map({class: .[0].class, count: length}) |
    sort_by(-.count) |
    .[] |
    "    \(.class): \(.count) rows satisfied"
  ' "${DIAGNOSTICS_JSON}" 2>/dev/null || echo "    (no data)"
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

diag_rows_checked=0
diag_rows_failed=0
diag_rows_unowned=0
if [[ -f "${DIAGNOSTICS_JSON}" ]]; then
  diag_rows_checked=$(jq_number_or_zero '.summary.total_rows_checked // 0' "${DIAGNOSTICS_JSON}")
  diag_rows_failed=$(jq_number_or_zero '.summary.rows_failed // 0' "${DIAGNOSTICS_JSON}")
  diag_rows_unowned=$(jq_number_or_zero '.summary.rows_unowned // 0' "${DIAGNOSTICS_JSON}")
fi

gate_blockers=()
if [[ "${DRY_RUN}" != "true" && "${diag_rows_checked}" -eq 0 ]]; then
  overall_passed=false
  required_failed=true
  gate_blockers+=("no_rows_checked")
fi
if [[ "${diag_rows_failed}" -gt 0 ]]; then
  overall_passed=false
  required_failed=true
  gate_blockers+=("failed_rows:${diag_rows_failed}")
fi
if [[ "${ALLOW_PARTIAL}" != "true" && "${diag_rows_unowned}" -gt 0 ]]; then
  overall_passed=false
  required_failed=true
  gate_blockers+=("unowned_rows:${diag_rows_unowned}")
fi

gate_blockers_json='[]'
if [[ ${#gate_blockers[@]} -gt 0 ]]; then
  gate_blockers_json=$(printf '%s\n' "${gate_blockers[@]}" | jq -R . | jq -s .)
fi

# Build gate summary
jq -s \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg diagnostics_json "${DIAGNOSTICS_JSON}" \
  --arg forensics_validator_report "${FORENSICS_VALIDATOR_REPORT}" \
  --arg coverage_matrix "${COVERAGE_MATRIX}" \
  --argjson allow_partial "$([[ "${ALLOW_PARTIAL}" == "true" ]] && echo true || echo false)" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson required_failed "$([[ "${required_failed}" == "true" ]] && echo true || echo false)" \
  --argjson total_steps "${total_steps}" \
  --argjson passed_steps "${passed_steps}" \
  --argjson failed_steps "${failed_steps}" \
  --argjson planned_steps "${planned_steps}" \
  --argjson diag_rows_checked "${diag_rows_checked}" \
  --argjson diag_rows_failed "${diag_rows_failed}" \
  --argjson diag_rows_unowned "${diag_rows_unowned}" \
  --argjson gate_blockers "${gate_blockers_json}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    gate: "unit",
    out_root: $out_root,
    allow_partial: $allow_partial,
    dry_run: $dry_run,
    passed: $passed,
    required_failed: $required_failed,
    coverage_matrix: $coverage_matrix,
    diagnostics_summary: {
      rows_checked: $diag_rows_checked,
      rows_failed: $diag_rows_failed,
      rows_unowned: $diag_rows_unowned
    },
    gate_blockers: $gate_blockers,
    step_counts: {
      total: $total_steps,
      passed: $passed_steps,
      failed: $failed_steps,
      planned: $planned_steps
    },
    replay_script: $replay_sh,
    diagnostics_report: $diagnostics_json,
    forensics_validator_report: $forensics_validator_report,
    steps: .
  }' "${STEPS_JSONL}" > "${SUMMARY_JSON}"

bash "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" \
  --mode "unit-gate" \
  --root "${OUT_ROOT}" \
  --run-id "${RUN_ID}" \
  --report "${FORENSICS_VALIDATOR_REPORT}"

echo ""
echo "=== Unit Gate Result ==="
if [[ "${overall_passed}" == "true" ]]; then
  echo "GATE: PASS (${passed_steps}/${total_steps} steps passed)"
else
  echo "GATE: FAIL (${failed_steps}/${total_steps} steps failed)"
  if [[ "${required_failed}" == "true" ]]; then
    echo "  Required steps failed — gate blocked."
  fi
  if [[ ${#gate_blockers[@]} -gt 0 ]]; then
    echo "  Gate blockers: ${gate_blockers[*]}"
  fi
fi
echo ""
echo "Summary:      ${SUMMARY_JSON}"
echo "Diagnostics:  ${DIAGNOSTICS_JSON}"
echo "Forensics:    ${FORENSICS_VALIDATOR_REPORT}"
echo "Steps:        ${STEPS_JSONL}"
echo "Replay:       ${REPLAY_SH}"
echo "Replay:       RUN_ID=${RUN_ID} bash $0 --out-root \"${OUT_ROOT}\" --run-id \"${RUN_ID}\""

if [[ "${overall_passed}" != "true" ]]; then
  exit 1
fi
