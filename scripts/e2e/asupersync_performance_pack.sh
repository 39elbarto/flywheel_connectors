#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""
DRY_RUN=false
PRE_GATE=false
SKIP_GUARDRAIL=false
SKIP_BASELINE=false
SKIP_BENCH=false
SKIP_SOAK=false

usage() {
  cat <<'EOF'
Usage: scripts/e2e/asupersync_performance_pack.sh [options]

Runs the ASUPERSYNC performance/reliability pack for bead flywheel_connectors-235t.28.

Options:
  --run-id <id>          Stable run identifier (default: UTC timestamp)
  --out-root <path>      Artifact root (default: artifacts/asupersync/perf/<run-id>)
  --dry-run              Emit commands/artifacts without executing heavy steps
  --pre-gate             Mark run as pre-gate (dependencies not fully complete)
  --skip-guardrail       Skip tokio guardrail snapshot step
  --skip-baseline        Skip workspace baseline compile/check step
  --skip-bench           Skip benchmark-oriented crate checks
  --skip-soak            Skip scripted soak/adversarial matrix step
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
  local category="$2"
  local description="$3"
  local required="$4"
  local command="$5"
  local status="$6"
  local duration_ms="$7"
  local log_path="$8"
  local reason="$9"

  jq -c -n \
    --arg step "${step}" \
    --arg category "${category}" \
    --arg description "${description}" \
    --arg command "${command}" \
    --arg status "${status}" \
    --arg log_path "${log_path}" \
    --arg reason "${reason}" \
    --argjson required "${required}" \
    --argjson duration_ms "${duration_ms}" \
    '{
      step: $step,
      category: $category,
      description: $description,
      required: $required,
      command: $command,
      status: $status,
      duration_ms: $duration_ms,
      log_path: $log_path,
      reason: ($reason | select(length > 0))
    }' >> "${STEPS_JSONL}"
}

run_step() {
  local step="$1"
  local category="$2"
  local description="$3"
  local required="$4"
  local command="$5"

  local step_dir="${OUT_ROOT}/steps/${step}"
  local log_path="${step_dir}/execution.log"
  local start_ms end_ms duration_ms rc status reason

  mkdir -p "${step_dir}"
  printf '%s\n' "${command}" > "${step_dir}/command.txt"

  if [[ "${DRY_RUN}" == "true" ]]; then
    status="planned"
    reason="dry_run"
    duration_ms=0
    record_step "${step}" "${category}" "${description}" "${required}" "${command}" "${status}" "${duration_ms}" "${log_path}" "${reason}"
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

  record_step "${step}" "${category}" "${description}" "${required}" "${command}" "${status}" "${duration_ms}" "${log_path}" "${reason}"
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
    --pre-gate)
      PRE_GATE=true
      shift
      ;;
    --skip-guardrail)
      SKIP_GUARDRAIL=true
      shift
      ;;
    --skip-baseline)
      SKIP_BASELINE=true
      shift
      ;;
    --skip-bench)
      SKIP_BENCH=true
      shift
      ;;
    --skip-soak)
      SKIP_SOAK=true
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
  OUT_ROOT="${REPO_ROOT}/artifacts/asupersync/perf/${RUN_ID}"
fi

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
MANIFEST_JSON="${OUT_ROOT}/manifest.json"
METRICS_TEMPLATE_JSON="${OUT_ROOT}/metrics_template.json"
SCENARIO_PLAN_JSON="${OUT_ROOT}/scenario_plan.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"

require_cmd jq
require_cmd rch
if [[ ! -x "${SCRIPT_DIR}/run_matrix.sh" ]]; then
  echo "Expected executable script not found: ${SCRIPT_DIR}/run_matrix.sh" >&2
  exit 1
fi

mkdir -p "${OUT_ROOT}/steps" "${OUT_ROOT}/scenarios" "${OUT_ROOT}/tuning" "${OUT_ROOT}/gate"
printf '' > "${STEPS_JSONL}"

{
  echo "#!/usr/bin/env bash"
  echo "set -euo pipefail"
  echo "cd \"${REPO_ROOT}\""
} > "${REPLAY_SH}"

if [[ "${SKIP_GUARDRAIL}" != "true" ]]; then
  GUARDRAIL_CMD='bash scripts/ci/asupersync_tokio_guard.sh --ledger .config/asupersync/tokio_exception_ledger.json --report artifacts/asupersync/guardrails/tokio_guard_report.json'
  echo "${GUARDRAIL_CMD}" >> "${REPLAY_SH}"
  run_step \
    "guardrail_snapshot" \
    "policy" \
    "Tokio guardrail snapshot before perf run" \
    "true" \
    "${GUARDRAIL_CMD}"
fi

if [[ "${SKIP_BASELINE}" != "true" ]]; then
  BASELINE_CHECK_CMD='rch exec -- cargo check --workspace --all-targets'
  echo "${BASELINE_CHECK_CMD}" >> "${REPLAY_SH}"
  run_step \
    "baseline_workspace_check" \
    "baseline" \
    "Workspace compile baseline for perf/reliability track" \
    "true" \
    "${BASELINE_CHECK_CMD}"
fi

if [[ "${SKIP_BENCH}" != "true" ]]; then
  STREAMING_CMD='rch exec -- cargo test -p fcp-streaming -- --nocapture'
  E2E_CMD='rch exec -- cargo test -p fcp-e2e -- --nocapture'

  echo "${STREAMING_CMD}" >> "${REPLAY_SH}"
  run_step \
    "streaming_probe" \
    "benchmark" \
    "Streaming crate benchmark/reliability probe" \
    "true" \
    "${STREAMING_CMD}"

  echo "${E2E_CMD}" >> "${REPLAY_SH}"
  run_step \
    "e2e_probe" \
    "benchmark" \
    "E2E crate benchmark/reliability probe" \
    "true" \
    "${E2E_CMD}"
fi

if [[ "${SKIP_SOAK}" != "true" ]]; then
  SOAK_CMD="OUT_ROOT=\"${OUT_ROOT}/scenarios/soak-matrix\" bash \"${SCRIPT_DIR}/run_matrix.sh\""
  echo "${SOAK_CMD}" >> "${REPLAY_SH}"
  run_step \
    "soak_matrix" \
    "soak" \
    "Scripted soak/adversarial matrix capture" \
    "true" \
    "${SOAK_CMD}"
fi

chmod +x "${REPLAY_SH}"

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

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg pre_gate "${PRE_GATE}" \
  '{
    run_id: $run_id,
    metric_contract_version: "1",
    pre_gate: ($pre_gate == "true"),
    required_metrics: [
      "latency_p50_ms",
      "latency_p95_ms",
      "latency_p99_ms",
      "throughput_ops_s",
      "rss_mb",
      "queue_depth_p95",
      "reconnect_success_rate",
      "cancel_storm_recovery_ms",
      "error_budget_burn_rate"
    ],
    metrics: []
  }' > "${METRICS_TEMPLATE_JSON}"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson pre_gate "$([[ "${PRE_GATE}" == "true" ]] && echo true || echo false)" \
  '{
    run_id: $run_id,
    generated_at: $generated_at,
    pre_gate: $pre_gate,
    scenarios: [
      {id: "perf-rr-hotpath", phase: "baseline", category: "request_response"},
      {id: "perf-stream-steady", phase: "baseline", category: "streaming"},
      {id: "perf-stream-reconnect", phase: "baseline", category: "streaming"},
      {id: "perf-timeout-heavy", phase: "baseline", category: "timeout"},
      {id: "perf-cancel-heavy", phase: "baseline", category: "cancellation"},
      {id: "soak-steady-2h", phase: "soak", category: "steady_state"},
      {id: "soak-burst-spike", phase: "soak", category: "burst"},
      {id: "soak-near-capacity", phase: "soak", category: "capacity"},
      {id: "adversarial-reconnect-storm", phase: "adversarial", category: "reconnect"},
      {id: "adversarial-cancel-storm", phase: "adversarial", category: "cancellation"},
      {id: "adversarial-repair-pressure", phase: "adversarial", category: "raptorq_repair"},
      {id: "tuning-queue-bounds", phase: "tuning", category: "queue"},
      {id: "tuning-retry-budget", phase: "tuning", category: "retry"},
      {id: "tuning-admission-thresholds", phase: "tuning", category: "admission"},
      {id: "tuning-scheduler-workers", phase: "tuning", category: "scheduler"}
    ]
  }' > "${SCENARIO_PLAN_JSON}"

jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg run_id "${RUN_ID}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg git_commit "$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --argjson pre_gate "$([[ "${PRE_GATE}" == "true" ]] && echo true || echo false)" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson required_failed "$([[ "${required_failed}" == "true" ]] && echo true || echo false)" \
  '{
    generated_at: $generated_at,
    run_id: $run_id,
    git_commit: $git_commit,
    out_root: $out_root,
    pre_gate: $pre_gate,
    dry_run: $dry_run,
    passed: $passed,
    required_failed: $required_failed,
    replay_script: $replay_sh
  }' > "${MANIFEST_JSON}"

jq -s \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg run_id "${RUN_ID}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg manifest_path "${MANIFEST_JSON}" \
  --arg metrics_template_path "${METRICS_TEMPLATE_JSON}" \
  --arg scenario_plan_path "${SCENARIO_PLAN_JSON}" \
  --argjson pre_gate "$([[ "${PRE_GATE}" == "true" ]] && echo true || echo false)" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson required_failed "$([[ "${required_failed}" == "true" ]] && echo true || echo false)" \
  '{
    generated_at: $generated_at,
    run_id: $run_id,
    out_root: $out_root,
    pre_gate: $pre_gate,
    dry_run: $dry_run,
    passed: $passed,
    required_failed: $required_failed,
    replay_script: $replay_sh,
    manifest_path: $manifest_path,
    metrics_template_path: $metrics_template_path,
    scenario_plan_path: $scenario_plan_path,
    steps: .
  }' "${STEPS_JSONL}" > "${SUMMARY_JSON}"

echo "ASUPERSYNC performance pack complete. Summary: ${SUMMARY_JSON}"
