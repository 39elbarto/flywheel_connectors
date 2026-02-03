#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="e2e_matrix_runner"
OUT_ROOT="${OUT_ROOT:-./out/${SCRIPT_NAME}}"
SUMMARY_JSONL="${SUMMARY_JSONL:-${OUT_ROOT}/summary.jsonl}"
SUMMARY_JSON="${SUMMARY_JSON:-${OUT_ROOT}/summary.json}"

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

record_result() {
  local scenario="$1"
  local script_path="$2"
  local description="$3"
  local required="$4"
  local status="$5"
  local duration_ms="$6"
  local log_path="$7"
  local reason="$8"

  jq -n \
    --arg scenario "${scenario}" \
    --arg script "${script_path}" \
    --arg description "${description}" \
    --arg status "${status}" \
    --arg log "${log_path}" \
    --arg reason "${reason}" \
    --argjson duration_ms "${duration_ms}" \
    --argjson required "${required}" \
    '{scenario: $scenario, script: $script, description: $description, required: $required, status: $status, duration_ms: $duration_ms, log: $log, reason: ($reason | select(length > 0))}' \
    >> "${SUMMARY_JSONL}"
}

run_scenario() {
  local scenario="$1"
  local script_path="$2"
  local description="$3"
  local required="$4"

  local out_dir="${OUT_ROOT}/${scenario}"
  local log_jsonl="${out_dir}/${scenario}.jsonl"
  local start_ms end_ms duration_ms rc status reason

  if [[ ! -x "${script_path}" ]]; then
    status="skipped"
    reason="script_missing"
    record_result "${scenario}" "${script_path}" "${description}" "${required}" "${status}" 0 "${log_jsonl}" "${reason}"
    return 0
  fi

  mkdir -p "${out_dir}"
  start_ms="$(now_ms)"
  set +e
  OUT_DIR="${out_dir}" LOG_JSONL="${log_jsonl}" "${script_path}"
  rc=$?
  set -e
  end_ms="$(now_ms)"
  duration_ms=$((end_ms - start_ms))

  if [[ ${rc} -eq 0 ]]; then
    status="pass"
    reason=""
    if [[ -f "${log_jsonl}" ]]; then
      if ! fcp-e2e --validate-log "${log_jsonl}" >/dev/null 2>&1; then
        status="fail"
        reason="log_invalid"
      fi
    fi
  else
    status="fail"
    reason="exit_${rc}"
  fi

  record_result "${scenario}" "${script_path}" "${description}" "${required}" "${status}" "${duration_ms}" "${log_jsonl}" "${reason}"
}

require_cmd jq
require_cmd fcp-e2e

mkdir -p "${OUT_ROOT}"
printf '' > "${SUMMARY_JSONL}"

overall_passed=true
missing_required=false

SCENARIOS=(
  "happy_path|./happy_path.sh|Install invoke receipt audit verify|true"
  "denial_path|./denial_path.sh|Invoke without cap -> DecisionReceipt -> explain|true"
  "revocation_flow|./revocation_flow.sh|Issue token -> revoke -> deny|true"
  "taint_approval|./taint_approval.sh|Tainted input -> approval -> success|true"
  "offline_repair|./offline_repair_flow.sh|Reduced availability -> repair -> recovery|true"
  "epoch_replay_mirror|./epoch_replay_mirror_install.sh|Epoch replay + binary mirror install|true"
  "batch_invoke|./batch_invoke_flow.sh|Batch invoke multi-operation flow|true"
  "progress_streaming|./progress_streaming_flow.sh|Progress streaming updates|true"
  "cancellation_flow|./cancellation_flow.sh|Operation cancellation flow|true"
  "rate_limit|./rate_limit_flow.sh|Rate limit enforcement flow|true"
  "gossip_bounds|./gossip_bounds_flow.sh|Gossip request bounds + config enforcement|true"
  "transport_path_matrix|./transport_path_matrix.sh|Transport path selection + multipath determinism|true"
  "targeted_repair_flow|./targeted_repair_flow.sh|Targeted repair symbol requests + decode status/ack|true"
  "lease_coordination|./lease_coordination_flow.sh|Lease coordination selection + conflict handling|true"
  "mesh_integration|./mesh_integration_flow.sh|Mesh integration scenarios (routing/admission/gossip)|true"
  "admission_control|./admission_control_flow.sh|Admission control budgets + limits|true"
  "policy_enforcement|./policy_enforcement_flow.sh|Policy enforcement allow/deny decisions|true"
  "routing|./routing_flow.sh|Routing selection and locality scoring|true"
  "meshnode_control_plane|./meshnode_control_plane_flow.sh|MeshNode control-plane and multi-node flows|true"
  "budget|./budget_flow.sh|Budget enforcement flow|false"
  "egress_denial|./egress_denial.sh|Sandbox egress denial|true"
)

for entry in "${SCENARIOS[@]}"; do
  IFS='|' read -r scenario script_path description required <<< "${entry}"
  run_scenario "${scenario}" "${script_path}" "${description}" "${required}"
done

while IFS= read -r line; do
  status=$(jq -r '.status' <<< "${line}")
  required=$(jq -r '.required' <<< "${line}")
  if [[ "${status}" == "fail" ]]; then
    overall_passed=false
  fi
  if [[ "${status}" == "skipped" && "${required}" == "true" ]]; then
    overall_passed=false
    missing_required=true
  fi
done < "${SUMMARY_JSONL}"

jq -s \
  --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --argjson passed "${overall_passed}" \
  --argjson missing_required "${missing_required}" \
  '{generated_at: $generated_at, passed: $passed, missing_required: $missing_required, results: .}' \
  "${SUMMARY_JSONL}" > "${SUMMARY_JSON}"

echo "E2E scenario matrix complete. Summary: ${SUMMARY_JSON}"
