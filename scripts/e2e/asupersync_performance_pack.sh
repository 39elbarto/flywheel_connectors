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
PHASE="baseline"
METRICS_INPUT=""
BASELINE_SUMMARY=""
FORENSICS_SCHEMA_VERSION="asupersync-forensics/v1"

REQUIRED_METRICS=(
  "latency_p50_ms"
  "latency_p95_ms"
  "latency_p99_ms"
  "throughput_ops_s"
  "rss_mb"
  "queue_depth_p95"
  "reconnect_success_rate"
  "cancel_storm_recovery_ms"
  "error_budget_burn_rate"
)

usage() {
  cat <<'EOF'
Usage: scripts/e2e/asupersync_performance_pack.sh [options]

Runs the ASUPERSYNC performance/reliability pack for bead flywheel_connectors-235t.28.

Options:
  --run-id <id>          Stable run identifier (default: UTC timestamp)
  --out-root <path>      Artifact root (default: artifacts/asupersync/perf/<run-id>)
  --dry-run              Emit commands/artifacts without executing heavy steps
  --pre-gate             Mark run as pre-gate (dependencies not fully complete)
  --phase <name>         Metric phase: baseline|delta|soak|adversarial|tuning
  --metrics-input <path> Optional JSONL metric input file to normalize
  --baseline-summary <path>
                         Baseline normalized summary JSON (required for --phase delta)
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

required_metrics_json() {
  printf '%s\n' "${REQUIRED_METRICS[@]}" | jq -R . | jq -s .
}

validate_phase() {
  case "$1" in
    baseline|delta|soak|adversarial|tuning)
      ;;
    *)
      echo "Invalid --phase value: $1" >&2
      echo "Valid values: baseline, delta, soak, adversarial, tuning" >&2
      exit 2
      ;;
  esac
}

validate_metric_record() {
  local record="$1"
  local line_no="$2"
  local expected_phase="$3"
  local expected_run_id="$4"

  if ! jq -e \
    --arg phase "${expected_phase}" \
    --arg run_id "${expected_run_id}" \
    '
      type == "object"
      and .run_id == $run_id
      and .phase == $phase
      and (.scenario_id | type == "string")
      and (.metric_name | type == "string")
      and (.value | type == "number")
      and (.unit | type == "string")
      and (.component | type == "string")
      and (.sample_count | type == "number")
      and (.window_ms | type == "number")
      and (.captured_at | type == "string")
    ' <<< "${record}" >/dev/null; then
    echo "Invalid metric record at line ${line_no}: ${record}" >&2
    exit 1
  fi
}

ingest_metrics() {
  local source_path="$1"
  local output_path="$2"
  local expected_phase="$3"
  local expected_run_id="$4"
  local line_no=0

  printf '' > "${output_path}"

  if [[ -z "${source_path}" ]]; then
    return 0
  fi

  if [[ ! -f "${source_path}" ]]; then
    echo "Metrics input file not found: ${source_path}" >&2
    exit 2
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_no=$((line_no + 1))
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi

    if ! jq -e . >/dev/null 2>&1 <<< "${line}"; then
      echo "Metrics input line ${line_no} is not valid JSON: ${line}" >&2
      exit 1
    fi

    validate_metric_record "${line}" "${line_no}" "${expected_phase}" "${expected_run_id}"
    jq -c . <<< "${line}" >> "${output_path}"
  done < "${source_path}"
}

build_normalized_summary() {
  local metrics_jsonl="$1"
  local output_path="$2"
  local required_metrics_json="$3"
  local run_id="$4"
  local phase="$5"

  jq -s \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg run_id "${run_id}" \
    --arg phase "${phase}" \
    --argjson required_metrics "${required_metrics_json}" \
    '
      {
        generated_at: $generated_at,
        run_id: $run_id,
        phase: $phase,
        record_count: length,
        metric_names: ([.[].metric_name] | unique | sort),
        missing_required_metrics: ($required_metrics - ([.[].metric_name] | unique)),
        metrics: (
          sort_by(.metric_name)
          | group_by(.metric_name)
          | map({
              metric_name: .[0].metric_name,
              component: .[0].component,
              unit: .[0].unit,
              sample_points: length,
              min: ([.[].value | numbers] | min? // null),
              max: ([.[].value | numbers] | max? // null),
              mean: (
                if ([.[].value | numbers] | length) == 0 then
                  null
                else
                  ([.[].value | numbers] | add) / ([.[].value | numbers] | length)
                end
              )
            })
        ),
        classification: (
          if length == 0 then
            "inconclusive"
          elif (($required_metrics - ([.[].metric_name] | unique)) | length) > 0 then
            "inconclusive"
          else
            "accept"
          end
        )
      }
    ' "${metrics_jsonl}" > "${output_path}"
}

build_delta_summary() {
  local phase="$1"
  local baseline_summary_path="$2"
  local normalized_summary_path="$3"
  local output_path="$4"

  if [[ "${phase}" != "delta" ]]; then
    jq -n \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg phase "${phase}" \
      '{generated_at: $generated_at, phase: $phase, status: "not_applicable", metrics: []}' > "${output_path}"
    return 0
  fi

  if [[ -z "${baseline_summary_path}" ]]; then
    jq -n \
      --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '{generated_at: $generated_at, phase: "delta", status: "missing_baseline_summary", metrics: []}' > "${output_path}"
    return 0
  fi

  if [[ ! -f "${baseline_summary_path}" ]]; then
    echo "Baseline summary file not found: ${baseline_summary_path}" >&2
    exit 2
  fi

  jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --slurpfile baseline "${baseline_summary_path}" \
    --slurpfile current "${normalized_summary_path}" \
    '
      def metric_means(doc): ((doc[0].metrics // []) | map({key: .metric_name, value: .mean}) | from_entries);
      def metric_units(doc): ((doc[0].metrics // []) | map({key: .metric_name, value: (.unit // "")}) | from_entries);

      (metric_means($baseline)) as $baseline_means
      | (metric_means($current)) as $current_means
      | (metric_units($current)) as $current_units
      | ((($baseline_means | keys) + ($current_means | keys)) | unique | sort) as $metric_names
      | {
          generated_at: $generated_at,
          phase: "delta",
          status: (
            if ($baseline_means | length) == 0 then
              "missing_baseline_metrics"
            elif ($current_means | length) == 0 then
              "missing_current_metrics"
            else
              "computed"
            end
          ),
          baseline_run_id: ($baseline[0].run_id // null),
          current_run_id: ($current[0].run_id // null),
          metrics: (
            $metric_names
            | map({
                metric_name: .,
                unit: ($current_units[.] // ""),
                baseline_mean: ($baseline_means[.] // null),
                current_mean: ($current_means[.] // null),
                delta_abs: (
                  if ($baseline_means[.] != null and $current_means[.] != null) then
                    ($current_means[.] - $baseline_means[.])
                  else
                    null
                  end
                ),
                delta_pct: (
                  if ($baseline_means[.] != null and $current_means[.] != null and $baseline_means[.] != 0) then
                    ((($current_means[.] - $baseline_means[.]) / $baseline_means[.]) * 100)
                  else
                    null
                  end
                )
              })
          )
        }
    ' > "${output_path}"
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
    --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
    --arg run_id "${RUN_ID}" \
    --arg step "${step}" \
    --arg scenario_id "${step}" \
    --arg trace_id "${RUN_ID}:${step}" \
    --arg correlation_id "${RUN_ID}:${step}" \
    --arg connector "n/a" \
    --arg zone "n/a" \
    --arg operation "${step}" \
    --arg category "${category}" \
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
      category: $category,
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
    --phase)
      PHASE="${2:-}"
      shift 2
      ;;
    --metrics-input)
      METRICS_INPUT="${2:-}"
      shift 2
      ;;
    --baseline-summary)
      BASELINE_SUMMARY="${2:-}"
      shift 2
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

validate_phase "${PHASE}"

STEPS_JSONL="${OUT_ROOT}/steps.jsonl"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
MANIFEST_JSON="${OUT_ROOT}/manifest.json"
METRICS_TEMPLATE_JSON="${OUT_ROOT}/metrics_template.json"
METRICS_JSONL="${OUT_ROOT}/metrics.jsonl"
NORMALIZED_SUMMARY_JSON="${OUT_ROOT}/normalized_summary.json"
DELTA_SUMMARY_JSON="${OUT_ROOT}/delta_summary.json"
SCENARIO_PLAN_JSON="${OUT_ROOT}/scenario_plan.json"
REPLAY_SH="${OUT_ROOT}/replay.sh"
REQUIRED_METRICS_JSON="$(required_metrics_json)"

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
  SOAK_CMD="bash \"${SCRIPT_DIR}/run_matrix.sh\" --run-id \"${RUN_ID}-soak-matrix\" --seed \"${RUN_ID}\" --out-root \"${OUT_ROOT}/scenarios/soak-matrix\""
  echo "${SOAK_CMD}" >> "${REPLAY_SH}"
  run_step \
    "soak_matrix" \
    "soak" \
    "Scripted soak/adversarial matrix capture" \
    "true" \
    "${SOAK_CMD}"
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

ingest_metrics "${METRICS_INPUT}" "${METRICS_JSONL}" "${PHASE}" "${RUN_ID}"
build_normalized_summary "${METRICS_JSONL}" "${NORMALIZED_SUMMARY_JSON}" "${REQUIRED_METRICS_JSON}" "${RUN_ID}" "${PHASE}"
build_delta_summary "${PHASE}" "${BASELINE_SUMMARY}" "${NORMALIZED_SUMMARY_JSON}" "${DELTA_SUMMARY_JSON}"

NORMALIZED_CLASSIFICATION="$(jq -r '.classification // "inconclusive"' "${NORMALIZED_SUMMARY_JSON}")"
MISSING_REQUIRED_COUNT="$(jq -r '.missing_required_metrics | length' "${NORMALIZED_SUMMARY_JSON}")"
METRIC_RECORD_COUNT="$(jq -r '.record_count // 0' "${NORMALIZED_SUMMARY_JSON}")"
DELTA_STATUS="$(jq -r '.status // "not_applicable"' "${DELTA_SUMMARY_JSON}")"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg phase "${PHASE}" \
  --arg pre_gate "${PRE_GATE}" \
  --argjson required_metrics "${REQUIRED_METRICS_JSON}" \
  '{
    run_id: $run_id,
    phase: $phase,
    metric_contract_version: "1",
    pre_gate: ($pre_gate == "true"),
    required_metrics: $required_metrics,
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
  --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg phase "${PHASE}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg metrics_input "${METRICS_INPUT}" \
  --arg baseline_summary "${BASELINE_SUMMARY}" \
  --arg git_commit "$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)" \
  --argjson pre_gate "$([[ "${PRE_GATE}" == "true" ]] && echo true || echo false)" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson required_failed "$([[ "${required_failed}" == "true" ]] && echo true || echo false)" \
  --arg normalized_classification "${NORMALIZED_CLASSIFICATION}" \
  --arg delta_status "${DELTA_STATUS}" \
  --argjson metric_record_count "${METRIC_RECORD_COUNT}" \
  --argjson missing_required_metrics "${MISSING_REQUIRED_COUNT}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    phase: $phase,
    git_commit: $git_commit,
    out_root: $out_root,
    pre_gate: $pre_gate,
    dry_run: $dry_run,
    passed: $passed,
    required_failed: $required_failed,
    replay_script: $replay_sh,
    metrics_input: ($metrics_input | select(length > 0)),
    baseline_summary: ($baseline_summary | select(length > 0)),
    normalized_classification: $normalized_classification,
    delta_status: $delta_status,
    metric_record_count: $metric_record_count,
    missing_required_metrics: $missing_required_metrics
  }' > "${MANIFEST_JSON}"

jq -s \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg schema_version "${FORENSICS_SCHEMA_VERSION}" \
  --arg run_id "${RUN_ID}" \
  --arg phase "${PHASE}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay_sh "${REPLAY_SH}" \
  --arg manifest_path "${MANIFEST_JSON}" \
  --arg metrics_path "${METRICS_JSONL}" \
  --arg metrics_template_path "${METRICS_TEMPLATE_JSON}" \
  --arg normalized_summary_path "${NORMALIZED_SUMMARY_JSON}" \
  --arg delta_summary_path "${DELTA_SUMMARY_JSON}" \
  --arg scenario_plan_path "${SCENARIO_PLAN_JSON}" \
  --argjson pre_gate "$([[ "${PRE_GATE}" == "true" ]] && echo true || echo false)" \
  --argjson dry_run "$([[ "${DRY_RUN}" == "true" ]] && echo true || echo false)" \
  --argjson passed "$([[ "${overall_passed}" == "true" ]] && echo true || echo false)" \
  --argjson required_failed "$([[ "${required_failed}" == "true" ]] && echo true || echo false)" \
  --arg normalized_classification "${NORMALIZED_CLASSIFICATION}" \
  --arg delta_status "${DELTA_STATUS}" \
  --argjson metric_record_count "${METRIC_RECORD_COUNT}" \
  --argjson missing_required_metrics "${MISSING_REQUIRED_COUNT}" \
  '{
    schema_version: $schema_version,
    generated_at: $generated_at,
    run_id: $run_id,
    phase: $phase,
    out_root: $out_root,
    pre_gate: $pre_gate,
    dry_run: $dry_run,
    passed: $passed,
    required_failed: $required_failed,
    replay_script: $replay_sh,
    manifest_path: $manifest_path,
    metrics_path: $metrics_path,
    metrics_template_path: $metrics_template_path,
    normalized_summary_path: $normalized_summary_path,
    delta_summary_path: $delta_summary_path,
    scenario_plan_path: $scenario_plan_path,
    normalized_classification: $normalized_classification,
    delta_status: $delta_status,
    metric_record_count: $metric_record_count,
    missing_required_metrics: $missing_required_metrics,
    steps: .
  }' "${STEPS_JSONL}" > "${SUMMARY_JSON}"

echo "ASUPERSYNC performance pack complete. Summary: ${SUMMARY_JSON}"
