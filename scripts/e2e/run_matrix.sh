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
ONLY_SCENARIO_IDS=""
ONLY_ARCHETYPES=""
ONLY_CONNECTORS=""
ONLY_TRACKS=""
DRY_RUN=false

SUMMARY_JSONL=""
SUMMARY_JSON=""
MANIFEST_JSON=""
SCENARIO_PLAN_JSON=""
REPLAY_SH=""
FAILURE_INDEX_JSON=""
RERUN_FAILED_SH=""
SCENARIOS_DIR=""
FORENSICS_VALIDATOR_REPORT=""
REGISTRY_PATH=""

usage() {
  cat <<'EOF'
Usage: scripts/e2e/run_matrix.sh [options]

Runs the deterministic E2E scenario matrix and writes replayable artifacts.

Options:
  --run-id <id>            Stable run identifier (default: UTC timestamp)
  --seed <seed>            Root deterministic seed (default: derived from run-id)
  --out-root <path>        Artifact root (default: artifacts/asupersync/e2e/<run-id>)
  --only-scenarios <csv>   Run subset of scenario keys (comma-separated)
  --only-scenario-ids <csv> Run subset by scenario_id values (comma-separated)
  --only-archetypes <csv>  Run subset by archetype values (comma-separated)
  --only-connectors <csv>  Run subset by connector identifiers (comma-separated)
  --track <csv>            Run subset by execution tracks (comma-separated)
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

run_cargo() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- cargo "$@"
    return $?
  fi
  cargo "$@"
}

validate_log_jsonl() {
  local log_path="$1"
  if command -v fcp-e2e >/dev/null 2>&1; then
    fcp-e2e --validate-log "${log_path}"
    return $?
  fi
  run_cargo run -q -p fcp-e2e --bin fcp-e2e -- --validate-log "${log_path}"
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

csv_contains() {
  local csv="$1"
  local needle="$2"
  local candidate
  local cleaned
  local -a entries=()

  if [[ -z "${csv}" ]]; then
    return 0
  fi

  IFS=',' read -r -a entries <<< "${csv}"
  for candidate in "${entries[@]}"; do
    cleaned="${candidate//[[:space:]]/}"
    if [[ -n "${cleaned}" && "${cleaned}" == "${needle}" ]]; then
      return 0
    fi
  done
  return 1
}

detect_connector() {
  local script_path="$1"
  local line connector

  line="$(rg -m1 '^CONNECTOR=' "${script_path}" 2>/dev/null || true)"
  if [[ -z "${line}" ]]; then
    printf '%s' "unknown"
    return 0
  fi

  connector="$(sed -E \
    -e 's/^CONNECTOR="\$\{CONNECTOR:-([^}]+)\}"$/\1/' \
    -e 's/^CONNECTOR="([^"]+)".*$/\1/' \
    <<< "${line}")"

  if [[ -z "${connector}" ]]; then
    printf '%s' "unknown"
  else
    printf '%s' "${connector}"
  fi
}

track_for_scenario() {
  local scenario="$1"
  local archetype="$2"
  local failure_class="$3"

  case "${scenario}" in
    raptorq_*|targeted_repair_flow|offline_repair)
      printf '%s' "raptorq_repair"
      ;;
    request_response_user_flow|polling_user_flow|webhook_delivery_flow|happy_path|denial_path|revocation_flow|taint_approval)
      printf '%s' "user_journey"
      ;;
    integration_gate|unit_gate|coverage_gate_publication|cross_component_revalidation|fuzz_adversarial_revalidation|unified_validation_report|failure_journey_forensic_bundle|reliability_soak_adversarial_load|runtime_tuning_calibration|performance_reliability_gate|connector_rollout_flow|canary_scenario_matrix|rollback_drill_consistency|rehearsal_automation|go_nogo_decision_gate|final_cutover_gate)
      printf '%s' "quality_gates"
      ;;
    streaming_*|sse_reconnect_ordering|bidirectional_cancel_chain|cancellation_flow)
      printf '%s' "streaming_bidi"
      ;;
    polling_*)
      printf '%s' "polling_resilience"
      ;;
    webhook_*)
      printf '%s' "webhook_resilience"
      ;;
    *)
      if [[ "${failure_class}" == *"budget"* || "${failure_class}" == *"rate_limit"* ]]; then
        printf '%s' "resource_controls"
      else
        printf '%s' "${archetype}"
      fi
      ;;
  esac
}

seed_for_scenario() {
  local scenario_id="$1"
  local hash
  hash=$(normalized_hash "${RUN_ID}:${ROOT_SEED}:${scenario_id}")
  printf '0x%s' "${hash:0:16}"
}

is_selected_scenario() {
  local scenario="$1"
  local scenario_id="$2"
  local archetype="$3"
  local connector="$4"
  local track="$5"

  if ! csv_contains "${ONLY_SCENARIOS}" "${scenario}"; then
    return 1
  fi
  if ! csv_contains "${ONLY_SCENARIO_IDS}" "${scenario_id}"; then
    return 1
  fi
  if ! csv_contains "${ONLY_ARCHETYPES}" "${archetype}"; then
    return 1
  fi
  if ! csv_contains "${ONLY_CONNECTORS}" "${connector}"; then
    return 1
  fi
  if ! csv_contains "${ONLY_TRACKS}" "${track}"; then
    return 1
  fi

  return 0
}

record_result() {
  local scenario="$1"
  local scenario_id="$2"
  local scenario_seed="$3"
  local script_path="$4"
  local archetype="$5"
  local connector="$6"
  local track="$7"
  local description="$8"
  local required="$9"
  local selected="${10}"
  local status="${11}"
  local duration_ms="${12}"
  local log_path="${13}"
  local execution_log="${14}"
  local command_path="${15}"
  local replay_command="${16}"
  local reason="${17}"

  jq -c -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario "${scenario}" \
    --arg scenario_id "${scenario_id}" \
    --arg scenario_seed "${scenario_seed}" \
    --arg script "${script_path}" \
    --arg archetype "${archetype}" \
    --arg connector "${connector}" \
    --arg track "${track}" \
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
      archetype: $archetype,
      connector: $connector,
      track: $track,
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
  local registry_entry
  local registry_script
  local scenario_id
  local archetype
  local failure_class
  local connector
  local track
  local selected="false"
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

  registry_entry="$(jq -c --arg key "${scenario}" '.scenarios[] | select(.key == $key)' "${REGISTRY_PATH}")"
  if [[ -z "${registry_entry}" ]]; then
    registry_entry='{}'
  fi

  scenario_id="$(jq -r '.scenario_id // empty' <<< "${registry_entry}")"
  if [[ -z "${scenario_id}" ]]; then
    scenario_id="asupersync.e2e.${scenario}"
  fi
  archetype="$(jq -r '.archetype // "unknown"' <<< "${registry_entry}")"
  failure_class="$(jq -r '.failure_class // "unknown"' <<< "${registry_entry}")"
  registry_script="$(jq -r '.script // empty' <<< "${registry_entry}")"

  if [[ "${script_path}" = /* ]]; then
    resolved_script_path="${script_path}"
  elif [[ -n "${registry_script}" ]]; then
    resolved_script_path="${REPO_ROOT}/${registry_script}"
  else
    resolved_script_path="${SCRIPT_DIR}/${script_path}"
  fi

  connector="$(detect_connector "${resolved_script_path}")"
  track="$(track_for_scenario "${scenario}" "${archetype}" "${failure_class}")"

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

  if is_selected_scenario "${scenario}" "${scenario_id}" "${archetype}" "${connector}" "${track}"; then
    selected="true"
  fi

  if [[ "${selected}" != "true" ]]; then
    status="skipped"
    reason="filtered"
    duration_ms=0
    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" \
      "${archetype}" "${connector}" "${track}" "${description}" \
      "${required}" "${selected}" "${status}" "${duration_ms}" "${log_jsonl}" "${execution_log}" \
      "${command_path}" "${replay_command}" "${reason}"
  elif [[ ! -x "${resolved_script_path}" ]]; then
    status="skipped"
    reason="script_missing"
    duration_ms=0
    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" \
      "${archetype}" "${connector}" "${track}" "${description}" \
      "${required}" "${selected}" "${status}" "${duration_ms}" "${log_jsonl}" "${execution_log}" \
      "${command_path}" "${replay_command}" "${reason}"
  elif [[ "${DRY_RUN}" == "true" ]]; then
    status="planned"
    reason="dry_run"
    duration_ms=0
    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" \
      "${archetype}" "${connector}" "${track}" "${description}" \
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
      elif ! validate_log_jsonl "${log_jsonl}" >/dev/null 2>&1; then
        status="fail"
        reason="log_invalid"
      fi
    else
      status="fail"
      reason="exit_${rc}"
    fi

    record_result \
      "${scenario}" "${scenario_id}" "${scenario_seed}" "${resolved_script_path}" \
      "${archetype}" "${connector}" "${track}" "${description}" \
      "${required}" "${selected}" "${status}" "${duration_ms}" "${log_jsonl}" "${execution_log}" \
      "${command_path}" "${replay_command}" "${reason}"
  fi

  jq -n \
    --arg schema_version "${SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg scenario "${scenario}" \
    --arg scenario_id "${scenario_id}" \
    --arg script "${resolved_script_path}" \
    --arg archetype "${archetype}" \
    --arg connector "${connector}" \
    --arg track "${track}" \
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
      archetype: $archetype,
      connector: $connector,
      track: $track,
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
    --only-scenario-ids)
      ONLY_SCENARIO_IDS="${2:-}"
      shift 2
      ;;
    --only-archetypes)
      ONLY_ARCHETYPES="${2:-}"
      shift 2
      ;;
    --only-connectors)
      ONLY_CONNECTORS="${2:-}"
      shift 2
      ;;
    --track)
      ONLY_TRACKS="${2:-}"
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
FORENSICS_VALIDATOR_REPORT="${OUT_ROOT}/forensics_validator_report.json"
FAILURE_INDEX_JSON="${OUT_ROOT}/failure_index.json"
RERUN_FAILED_SH="${OUT_ROOT}/rerun_failed.sh"
REGISTRY_PATH="${SCRIPT_DIR}/scenario_registry.json"

require_cmd jq
[[ -f "${REGISTRY_PATH}" ]] || {
  echo "Registry file not found: ${REGISTRY_PATH}" >&2
  exit 1
}
if [[ "${DRY_RUN}" != "true" ]]; then
  if ! command -v fcp-e2e >/dev/null 2>&1; then
    require_cmd cargo
  fi
fi
if [[ ! -x "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" ]]; then
  echo "Expected executable script not found: ${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" >&2
  exit 1
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
  "unit_gate|unit_gate_executor.sh|Unit gate coverage enforcement|true"
  "coverage_gate_publication|coverage_gate_publication.sh|Coverage gate evidence bundle|true"
  "polling_timeout_backoff_storm|polling_timeout_backoff_storm.sh|Polling timeout backoff bounded recovery|true"
  "polling_cursor_gap_recovery|polling_cursor_gap_recovery.sh|Polling cursor gap detection recovery|true"
  "webhook_retry_storm|webhook_retry_storm.sh|Webhook retry storm idempotent delivery|true"
  "request_timeout_chain|request_timeout_chain.sh|Request timeout chain bounded failure|true"
  "raptorq_partial_symbol_recovery|raptorq_partial_symbol_recovery.sh|RaptorQ partial symbol loss repair convergence|true"
  "raptorq_adversarial_decode_stress|raptorq_adversarial_decode_stress.sh|RaptorQ adversarial decode budget bounds|true"
  "raptorq_multinode_repair_convergence|raptorq_multinode_repair_convergence.sh|RaptorQ multi-node placement repair convergence|true"
  "raptorq_degraded_network_recovery|raptorq_degraded_network_recovery.sh|RaptorQ degraded network graceful recovery|true"
  "cross_component_revalidation|e2e_cross_component_revalidation.sh|Cross-component E2E data path revalidation|true"
  "fuzz_adversarial_revalidation|e2e_fuzz_adversarial_revalidation.sh|Fuzz adversarial boundary revalidation|true"
  "unified_validation_report|e2e_unified_validation_report.sh|Unified validation report release gate|true"
  "recovery_guidance_validation|e2e_recovery_guidance_validation.sh|Recovery guidance user journey validation|true"
  "failure_journey_forensic_bundle|e2e_failure_journey_forensic_bundle.sh|Failure-journey E2E forensic evidence bundle|true"
  "reliability_soak_adversarial_load|e2e_reliability_soak_adversarial_load.sh|Reliability soak adversarial load stability|true"
  "runtime_tuning_calibration|e2e_runtime_tuning_calibration.sh|Runtime tuning risk-bounded calibration|true"
  "performance_reliability_gate|e2e_performance_reliability_gate.sh|Performance reliability gate config freeze|true"
  "connector_rollout_flow|connector_rollout_flow.sh|Connector staged rollout and automatic rollback audit flow|true"
  "canary_scenario_matrix|e2e_canary_scenario_matrix.sh|Canary scenario matrix abort thresholds|true"
  "rollback_drill_consistency|e2e_rollback_drill_consistency.sh|Rollback drill state consistency recovery|true"
  "rehearsal_automation|e2e_rehearsal_automation.sh|Rehearsal automation artifact log enforcement|true"
  "go_nogo_decision_gate|e2e_go_nogo_decision_gate.sh|Go no-go decision gate operator runbook|true"
  "final_cutover_gate|e2e_final_cutover_gate.sh|Final cutover tokio removal policy lock|true"
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
        archetype: .archetype,
        connector: .connector,
        track: .track,
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
  --arg forensics_validator_report "${FORENSICS_VALIDATOR_REPORT}" \
  --arg failure_index_path "${FAILURE_INDEX_JSON}" \
  --arg rerun_failed_path "${RERUN_FAILED_SH}" \
  --arg git_commit "$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --arg only_scenarios "${ONLY_SCENARIOS}" \
  --arg only_scenario_ids "${ONLY_SCENARIO_IDS}" \
  --arg only_archetypes "${ONLY_ARCHETYPES}" \
  --arg only_connectors "${ONLY_CONNECTORS}" \
  --arg only_tracks "${ONLY_TRACKS}" \
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
    forensics_validator_report: $forensics_validator_report,
    failure_index_path: $failure_index_path,
    rerun_failed_path: $rerun_failed_path,
    only_scenarios: (if ($only_scenarios | length) > 0 then $only_scenarios else null end),
    only_scenario_ids: (if ($only_scenario_ids | length) > 0 then $only_scenario_ids else null end),
    only_archetypes: (if ($only_archetypes | length) > 0 then $only_archetypes else null end),
    only_connectors: (if ($only_connectors | length) > 0 then $only_connectors else null end),
    only_tracks: (if ($only_tracks | length) > 0 then $only_tracks else null end),
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
  --arg forensics_validator_report "${FORENSICS_VALIDATOR_REPORT}" \
  --arg failure_index_path "${FAILURE_INDEX_JSON}" \
  --arg rerun_failed_path "${RERUN_FAILED_SH}" \
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
    forensics_validator_report: $forensics_validator_report,
    failure_index_path: $failure_index_path,
    rerun_failed_path: $rerun_failed_path,
    totals: {
      total: length,
      pass: (map(select(.status == "pass")) | length),
      fail: (map(select(.status == "fail")) | length),
      skipped: (map(select(.status == "skipped")) | length),
      planned: (map(select(.status == "planned")) | length)
    },
    results: .
  }' "${SUMMARY_JSONL}" > "${SUMMARY_JSON}"

jq -s \
  --arg schema_version "asupersync-e2e-failure-index/v1" \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --arg run_id "${RUN_ID}" \
  --arg root_seed "${ROOT_SEED}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    root_seed: $root_seed,
    fail_count: (map(select(.status == "fail")) | length),
    failures: (
      map(select(.status == "fail"))
      | sort_by(.scenario)
      | map({
          scenario,
          scenario_id,
          archetype,
          connector,
          track,
          reason,
          replay_command,
          execution_log,
          log,
          command_path
        })
    )
  }' "${SUMMARY_JSONL}" > "${FAILURE_INDEX_JSON}"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"${REPO_ROOT}\""
  echo
  echo "FAIL_COUNT=\$(jq -r '.fail_count' \"${FAILURE_INDEX_JSON}\")"
  echo 'if [[ "${FAIL_COUNT}" == "0" ]]; then'
  echo '  echo "No failed scenarios to rerun."'
  echo "  exit 0"
  echo "fi"
  echo
  echo 'echo "Replaying ${FAIL_COUNT} failed scenarios..."'
  while IFS= read -r cmd || [[ -n "${cmd}" ]]; do
    if [[ -n "${cmd}" ]]; then
      echo "${cmd}"
    fi
  done < <(jq -r '.failures[].replay_command' "${FAILURE_INDEX_JSON}")
} > "${RERUN_FAILED_SH}"
chmod +x "${RERUN_FAILED_SH}"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"${REPO_ROOT}\""
  echo
  full_replay_cmd="bash \"${SCRIPT_DIR}/run_matrix.sh\" --run-id \"${RUN_ID}\" --seed \"${ROOT_SEED}\" --out-root \"${OUT_ROOT}\""
  if [[ -n "${ONLY_SCENARIOS}" ]]; then
    full_replay_cmd="${full_replay_cmd} --only-scenarios \"${ONLY_SCENARIOS}\""
  fi
  if [[ -n "${ONLY_SCENARIO_IDS}" ]]; then
    full_replay_cmd="${full_replay_cmd} --only-scenario-ids \"${ONLY_SCENARIO_IDS}\""
  fi
  if [[ -n "${ONLY_ARCHETYPES}" ]]; then
    full_replay_cmd="${full_replay_cmd} --only-archetypes \"${ONLY_ARCHETYPES}\""
  fi
  if [[ -n "${ONLY_CONNECTORS}" ]]; then
    full_replay_cmd="${full_replay_cmd} --only-connectors \"${ONLY_CONNECTORS}\""
  fi
  if [[ -n "${ONLY_TRACKS}" ]]; then
    full_replay_cmd="${full_replay_cmd} --track \"${ONLY_TRACKS}\""
  fi
  echo "# Full matrix replay"
  echo "${full_replay_cmd}"
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

bash "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" \
  --mode "e2e-matrix" \
  --root "${OUT_ROOT}" \
  --run-id "${RUN_ID}" \
  --report "${FORENSICS_VALIDATOR_REPORT}"

echo "E2E scenario matrix complete. Summary: ${SUMMARY_JSON}"
echo "Failure index: ${FAILURE_INDEX_JSON}"
