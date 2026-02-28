#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
SKIP_CONFORMANCE=false
SKIP_E2E=false
SKIP_FUZZ=false
FORENSICS_SCHEMA_VERSION="asupersync-forensics/v1"

usage() {
  cat <<'EOF'
Usage: scripts/e2e/asupersync_validation_pack.sh [options]

Runs the ASUPERSYNC validation pack workflow for bead flywheel_connectors-235t.27.

Options:
  --run-id <id>          Stable run identifier (default: UTC timestamp)
  --out-root <path>      Artifact root (default: artifacts/asupersync/validation/<run-id>)
  --dry-run              Emit commands/artifacts without executing heavy steps
  --skip-conformance     Skip conformance step
  --skip-e2e             Skip E2E matrix step
  --skip-fuzz            Skip fuzz boundary compile step
  -h, --help             Show this help
EOF
}

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
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --skip-conformance)
      SKIP_CONFORMANCE=true
      shift
      ;;
    --skip-e2e)
      SKIP_E2E=true
      shift
      ;;
    --skip-fuzz)
      SKIP_FUZZ=true
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
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/validation/${RUN_ID}"
fi

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"

require_cmd jq
require_cmd rch
if [[ ! -x "${SCRIPT_DIR}/run_matrix.sh" ]]; then
  echo "Expected executable script not found: ${SCRIPT_DIR}/run_matrix.sh" >&2
  exit 1
fi

mkdir -p "${OUT_ROOT}"
printf '' > "${STEPS_JSONL}"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"${REPO_ROOT}\""
} > "${REPLAY_SH}"

if [[ "${SKIP_CONFORMANCE}" != "true" ]]; then
  CONFORMANCE_CMD='rch exec -- cargo test -p fcp-conformance --all-targets'
  echo "${CONFORMANCE_CMD}" >> "${REPLAY_SH}"
  run_step \
    "conformance" \
    "Protocol conformance suite revalidation on migrated runtime" \
    "true" \
    "${CONFORMANCE_CMD}"
fi

if [[ "${SKIP_E2E}" != "true" ]]; then
  E2E_CMD="bash \"${SCRIPT_DIR}/run_matrix.sh\" --run-id \"${RUN_ID}-e2e-matrix\" --seed \"${RUN_ID}\" --out-root \"${OUT_ROOT}/scenarios/e2e-matrix\""
  echo "${E2E_CMD}" >> "${REPLAY_SH}"
  run_step \
    "e2e_matrix" \
    "Cross-component scripted E2E matrix with schema-validated logs" \
    "true" \
    "${E2E_CMD}"
fi

if [[ "${SKIP_FUZZ}" != "true" ]]; then
  FUZZ_CMD='rch exec -- cargo check --manifest-path fuzz/Cargo.toml --bins'
  echo "${FUZZ_CMD}" >> "${REPLAY_SH}"
  run_step \
    "fuzz_boundary" \
    "Fuzz/adversarial boundary target compile validation" \
    "true" \
    "${FUZZ_CMD}"
fi

chmod +x "${REPLAY_SH}"
validate_steps_jsonl

overall_passed=true
required_failed=false

while IFS= read -r line; do
  status=$(jq -r '.status' <<< "${line}")
  required=$(jq -r '.required' <<< "${line}")
  if [[ "${status}" == "fail" ]]; then
    overall_passed=false
    if [[ "${required}" == "true" ]]; then
      required_failed=true
    fi
  fi
done < "${STEPS_JSONL}"

jq -s \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson required_failed "$([[ "${required_failed}" == "true" ]] && echo true || echo false)" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    out_root: $out_root,
    dry_run: $dry_run,
    passed: $passed,
    required_failed: $required_failed,
    replay_script: $replay_sh,
    steps: .
  }' "${STEPS_JSONL}" > "${SUMMARY_JSON}"

echo "ASUPERSYNC validation pack complete. Summary: ${SUMMARY_JSON}"
