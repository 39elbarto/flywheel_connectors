#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="e2e_matrix_runner"
SCHEMA_VERSION="asupersync-e2e-harness/v1"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ROOT_SEED=""
OUT_ROOT="${OUT_ROOT:-}"
ONLY_SCENARIOS=""
DRY_RUN=false

SUMMARY_JSONL=""
SUMMARY_JSON=""
MANIFEST_JSON=""
SCENARIO_PLAN_JSON=""
REPLAY_SH=""
SCENARIOS_DIR=""

usage() {
  cat <<'EOF'
Usage: scripts/e2e/run_matrix.sh [options]

Runs the deterministic E2E scenario matrix and writes replayable artifacts.

Options:
  --run-id <id>            Stable run identifier (default: UTC timestamp)
  --seed <seed>            Root deterministic seed (default: derived from run-id)
  --out-root <path>        Artifact root (default: artifacts/asupersync/e2e/<run-id>)
  --only-scenarios <csv>   Run subset of scenario keys (comma-separated)
  --dry-run                Emit artifact plan without executing scenarios
  -h, --help               Show this help
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

normalized_hash() {
  local input="$1"
  printf '%s' "${input}" | hash256 | tr -cd '0-9a-fA-F' | head -c 64
}

seed_for_scenario() {
  local scenario_id="$1"
  local hash
  hash=$(normalized_hash "${RUN_ID}:${ROOT_SEED}:${scenario_id}")
  printf '0x%s' "${hash:0:16}"
}

is_selected_scenario() {
  local scenario="$1"
  local candidate
  local cleaned
  local -a selected_entries=()
  if [[ -z "${ONLY_SCENARIOS}" ]]; then
    return 0
  fi
  IFS=',' read -r -a selected_entries <<< "${ONLY_SCENARIOS}"
  for candidate in "${selected_entries[@]}"; do
    cleaned="${candidate//[[:space:]]/}"
    if [[ "${cleaned}" == "${scenario}" ]]; then
      return 0
    fi
  done
  return 1
}

record_result() {
  local scenario="$1"
  local scenario_id="$2"
  local scenario_seed="$3"
  local script_path="$4"
  local description="$5"
  local required="$6"
  local selected="$7"
  local status="$8"
  local duration_ms="$9"
  local log_path="${10}"
  local execution_log="${11}"
  local command_path="${12}"
  local replay_command="${13}"
  local reason="${14}"

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario "${scenario}" \
    --arg scenario_id "${scenario_id}" \
    --arg scenario_seed "${scenario_seed}" \
    --arg script "${script_path}" \
    --arg description "${description}" \
    --arg status "${status}" \
    --arg log "${log_path}" \
    --arg execution_log "${execution_log}" \
    --arg command_path "${command_path}" \
    --arg replay_command "${replay_command}" \
    --arg reason "${reason}" \
    --argjson duration_ms "${duration_ms}" \
    --argjson required "${required}" \
    --argjson selected "${selected}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      scenario: $scenario,
      scenario_id: $scenario_id,
      scenario_seed: $scenario_seed,
      script: $script,
      description: $description,
      required: $required,
      selected: $selected,
      status: $status,
      duration_ms: $duration_ms,
      log: $log,
      execution_log: $execution_log,
      command_path: $command_path,
      replay_command: $replay_command,
      reason: (if ($reason | length) > 0 then $reason else null end)
    }' >> "${SUMMARY_JSONL}"
}

run_scenario() {
  local scenario="$1"
  local script_path="$2"
  local description="$3"
  local required="$4"
  local resolved_script_path
  local selected="false"
  local scenario_id="asupersync.e2e.${scenario}"
  local scenario_seed
  local scenario_dir
  local payload_dir
  local log_jsonl
  local execution_log
  local command_path
  local replay_command
  local scenario_json
  local start_ms end_ms duration_ms rc status reason
  local command

  if [[ "${script_path}" = /* ]]; then
    resolved_script_path="${script_path}"
  else
    resolved_script_path="${SCRIPT_DIR}/${script_path}"
  fi

  scenario_seed="$(seed_for_scenario "${scenario_id}")"
  scenario_dir="${SCENARIOS_DIR}/${scenario}"
  payload_dir="${scenario_dir}/artifacts"
  log_jsonl="${payload_dir}/${scenario}.jsonl"
  execution_log="${scenario_dir}/execution.log"
  command_path="${scenario_dir}/command.txt"
  scenario_json="${scenario_dir}/scenario.json"
  replay_command="bash \"${SCRIPT_DIR}/run_matrix.sh\" --run-id \"${RUN_ID}\" --seed \"${ROOT_SEED}\" --out-root \"${OUT_ROOT}\" --only-scenarios \"${scenario}\""

  command="RUN_ID=\"${RUN_ID}\" SCENARIO_ID=\"${scenario_id}\" SEED=\"${scenario_seed}\" OUT_DIR=\"${payload_dir}\" LOG_JSONL=\"${log_jsonl}\" \"${resolved_script_path}\""

  mkdir -p "${scenario_dir}" "${payload_dir}"
  printf '%s\n' "${command}" > "${command_path}"

  if is_selected_scenario "${scenario}"; then
    selected="true"
  fi

  if [[ "${selected}" != "true" ]]; then
    status="skipped"
    reason="filtered"
    duration_ms=0
    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" "${description}" \
      "${required}" "${selected}" "${status}" "${duration_ms}" "${log_jsonl}" "${execution_log}" \
      "${command_path}" "${replay_command}" "${reason}"
  elif [[ ! -x "${resolved_script_path}" ]]; then
    status="skipped"
    reason="script_missing"
    duration_ms=0
    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" "${description}" \
      "${required}" "${selected}" "${status}" "${duration_ms}" "${log_jsonl}" "${execution_log}" \
      "${command_path}" "${replay_command}" "${reason}"
  elif [[ "${DRY_RUN}" == "true" ]]; then
    status="planned"
    reason="dry_run"
    duration_ms=0
    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" "${description}" \
      "${required}" "${selected}" "${status}" "${duration_ms}" "${log_jsonl}" "${execution_log}" \
      "${command_path}" "${replay_command}" "${reason}"
  else
    start_ms="$(now_ms)"
    set +e
    bash -lc "set -euo pipefail; ${command}" > "${execution_log}" 2>&1
    rc=$?
    set -e
    end_ms="$(now_ms)"
    duration_ms=$((end_ms - start_ms))

    if [[ ${rc} -eq 0 ]]; then
      status="pass"
      reason=""
      if [[ ! -f "${log_jsonl}" ]]; then
        status="fail"
        reason="log_missing"
      elif ! fcp-e2e --validate-log "${log_jsonl}" >/dev/null 2>&1; then
        status="fail"
        reason="log_invalid"
      fi
    else
      status="fail"
      reason="exit_${rc}"
    fi

    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" "${description}" \
      "${required}" "${selected}" "${status}" "${duration_ms}" "${log_jsonl}" "${execution_log}" \
      "${command_path}" "${replay_command}" "${reason}"
  fi

  jq -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario "${scenario}" \
    --arg scenario_id "${scenario_id}" \
    --arg script "${resolved_script_path}" \
    --arg description "${description}" \
    --arg scenario_seed "${scenario_seed}" \
    --arg out_dir "${payload_dir}" \
    --arg log_jsonl "${log_jsonl}" \
    --arg command_path "${command_path}" \
    --arg replay_command "${replay_command}" \
    --argjson required "${required}" \
    --argjson selected "${selected}" \
    '{
      schema_version: $schema_version,
      run_id: $run_id,
      scenario: $scenario,
      scenario_id: $scenario_id,
      required: $required,
      selected: $selected,
      script: $script,
      description: $description,
      scenario_seed: $scenario_seed,
      out_dir: $out_dir,
      log_jsonl: $log_jsonl,
      command_path: $command_path,
      replay_command: $replay_command
    }' > "${scenario_json}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --seed)
      ROOT_SEED="${2:-}"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="${2:-}"
      shift 2
      ;;
    --only-scenarios)
      ONLY_SCENARIOS="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=true
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
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/e2e/${RUN_ID}"
fi

if [[ -z "${ROOT_SEED}" ]]; then
  ROOT_SEED="0x$(normalized_hash "run-matrix:${RUN_ID}" | cut -c1-16)"
fi

SUMMARY_JSONL="${SUMMARY_JSONL:-${OUT_ROOT}/results.jsonl}"
SUMMARY_JSON="${SUMMARY_JSON:-${OUT_ROOT}/summary.json}"
MANIFEST_JSON="${MANIFEST_JSON:-${OUT_ROOT}/manifest.json}"
SCENARIO_PLAN_JSON="${SCENARIO_PLAN_JSON:-${OUT_ROOT}/scenario_plan.json}"
REPLAY_SH="${REPLAY_SH:-${OUT_ROOT}/replay.sh}"
SCENARIOS_DIR="${OUT_ROOT}/scenarios"

require_cmd jq
if [[ "${DRY_RUN}" != "true" ]]; then
  require_cmd fcp-e2e
fi

mkdir -p "${OUT_ROOT}" "${SCENARIOS_DIR}"
printf '' > "${SUMMARY_JSONL}"

SCENARIOS=(
  "happy_path|happy_path.sh|Install invoke receipt audit verify|true"
  "denial_path|denial_path.sh|Invoke without cap -> DecisionReceipt -> explain|true"
  "revocation_flow|revocation_flow.sh|Issue token -> revoke -> deny|true"
  "taint_approval|taint_approval.sh|Tainted input -> approval -> success|true"
  "offline_repair|offline_repair_flow.sh|Reduced availability -> repair -> recovery|true"
  "epoch_replay_mirror|epoch_replay_mirror_install.sh|Epoch replay + binary mirror install|true"
  "batch_invoke|batch_invoke_flow.sh|Batch invoke multi-operation flow|true"
  "progress_streaming|progress_streaming_flow.sh|Progress streaming updates|true"
  "cancellation_flow|cancellation_flow.sh|Operation cancellation flow|true"
  "rate_limit|rate_limit_flow.sh|Rate limit enforcement flow|true"
  "gossip_bounds|gossip_bounds_flow.sh|Gossip request bounds + config enforcement|true"
  "gossip_bootstrap_partition|gossip_bootstrap_partition.sh|Gossip bootstrap + partition/rejoin convergence|true"
  "transport_path_matrix|transport_path_matrix.sh|Transport path selection + multipath determinism|true"
  "targeted_repair_flow|targeted_repair_flow.sh|Targeted repair symbol requests + decode status/ack|true"
  "lease_coordination|lease_coordination_flow.sh|Lease coordination selection + conflict handling|true"
  "mesh_integration|mesh_integration_flow.sh|Mesh integration scenarios (routing/admission/gossip)|true"
  "admission_control|admission_control_flow.sh|Admission control budgets + limits|true"
  "policy_enforcement|policy_enforcement_flow.sh|Policy enforcement allow/deny decisions|true"
  "routing|routing_flow.sh|Routing selection and locality scoring|true"
  "meshnode_control_plane|meshnode_control_plane_flow.sh|MeshNode control-plane and multi-node flows|true"
  "budget|budget_flow.sh|Budget enforcement flow|false"
  "egress_denial|egress_denial.sh|Sandbox egress denial|true"
  "streaming_reconnect_storm|streaming_reconnect_storm.sh|WebSocket reconnect storm bounded recovery|true"
  "streaming_backpressure_stress|streaming_backpressure_stress.sh|Stream backpressure bounded queues|true"
  "bidirectional_cancel_chain|bidirectional_cancel_chain.sh|Bidirectional cancel chain clean shutdown|true"
  "sse_reconnect_ordering|sse_reconnect_ordering.sh|SSE reconnect ordering continuity|true"
  "integration_gate|integration_gate_executor.sh|Integration gate coverage drift check|true"
  "request_response_user_flow|request_response_user_flow.sh|Request-response user journey e2e|true"
  "polling_user_flow|polling_user_flow.sh|Polling archetype user journey e2e|true"
  "webhook_delivery_flow|webhook_delivery_flow.sh|Webhook delivery user journey e2e|true"
)

for entry in "${SCENARIOS[@]}"; do
  IFS='|' read -r scenario script_path description required <<< "${entry}"
  run_scenario "${scenario}" "${script_path}" "${description}" "${required}"
done

overall_passed=true
missing_required=false

while IFS= read -r line || [[ -n "${line}" ]]; do
  if [[ -z "${line//[[:space:]]/}" ]]; then
    continue
  fi
  status=$(jq -r '.status' <<< "${line}")
  required=$(jq -r '.required' <<< "${line}")
  reason=$(jq -r '.reason // ""' <<< "${line}")
  if [[ "${status}" == "fail" ]]; then
    overall_passed=false
  fi
  if [[ "${status}" == "skipped" && "${required}" == "true" && "${reason}" == "script_missing" ]]; then
    overall_passed=false
    missing_required=true
  fi
done < "${SUMMARY_JSONL}"

jq -s \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg schema_version "${SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg root_seed "${ROOT_SEED}" \
  --arg out_root "${OUT_ROOT}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    root_seed: $root_seed,
    out_root: $out_root,
    scenarios: (
      map({
        scenario: .scenario,
        scenario_id: .scenario_id,
        required: .required,
        selected: .selected,
        script: .script,
        description: .description,
        scenario_seed: .scenario_seed,
        replay_command: .replay_command
      })
    )
  }' "${SUMMARY_JSONL}" > "${SCENARIO_PLAN_JSON}"

jq -s \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg schema_version "${SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg root_seed "${ROOT_SEED}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg scenario_plan "${SCENARIO_PLAN_JSON}" \
  --arg git_commit "$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --arg only_scenarios "${ONLY_SCENARIOS}" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson missing_required "$([[ "${missing_required}" == "true" ]] && echo true || echo false)" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    root_seed: $root_seed,
    out_root: $out_root,
    git_commit: $git_commit,
    dry_run: $dry_run,
    passed: $passed,
    missing_required: $missing_required,
    replay_script: $replay_sh,
    scenario_plan_path: $scenario_plan,
    only_scenarios: (if ($only_scenarios | length) > 0 then $only_scenarios else null end),
    totals: {
      total: length,
      pass: (map(select(.status == "pass")) | length),
      fail: (map(select(.status == "fail")) | length),
      skipped: (map(select(.status == "skipped")) | length),
      planned: (map(select(.status == "planned")) | length)
    }
  }' "${SUMMARY_JSONL}" > "${MANIFEST_JSON}"

jq -s \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg schema_version "${SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg root_seed "${ROOT_SEED}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg manifest_path "${MANIFEST_JSON}" \
  --arg scenario_plan_path "${SCENARIO_PLAN_JSON}" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson missing_required "$([[ "${missing_required}" == "true" ]] && echo true || echo false)" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    root_seed: $root_seed,
    out_root: $out_root,
    dry_run: $dry_run,
    passed: $passed,
    missing_required: $missing_required,
    replay_script: $replay_sh,
    manifest_path: $manifest_path,
    scenario_plan_path: $scenario_plan_path,
    totals: {
      total: length,
      pass: (map(select(.status == "pass")) | length),
      fail: (map(select(.status == "fail")) | length),
      skipped: (map(select(.status == "skipped")) | length),
      planned: (map(select(.status == "planned")) | length)
    },
    results: .
  }' "${SUMMARY_JSONL}" > "${SUMMARY_JSON}"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"${REPO_ROOT}\""
  echo
  echo "# Full matrix replay"
  echo "bash \"${SCRIPT_DIR}/run_matrix.sh\" --run-id \"${RUN_ID}\" --seed \"${ROOT_SEED}\" --out-root \"${OUT_ROOT}\""
  echo
  echo "# Scenario-specific replay commands"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi
    scenario=$(jq -r '.scenario' <<< "${line}")
    replay_command=$(jq -r '.replay_command' <<< "${line}")
    echo "# ${scenario}"
    echo "${replay_command}"
  done < "${SUMMARY_JSONL}"
} > "${REPLAY_SH}"

chmod +x "${REPLAY_SH}"

echo "E2E scenario matrix complete. Summary: ${SUMMARY_JSON}"
