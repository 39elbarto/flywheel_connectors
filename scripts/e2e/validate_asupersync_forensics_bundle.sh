#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

MODE=""
ROOT=""
RUN_ID=""
REPORT=""
REGISTRY="${SCRIPT_DIR}/scenario_registry.json"

declare -a ISSUES=()
declare -a CHECKED_FILES=()

usage() {
  cat <<'EOF'
Usage: scripts/e2e/validate_asupersync_forensics_bundle.sh [options]

Validate ASUPERSYNC forensic bundles for schema integrity, artifact completeness,
replay-manifest integrity, and actionable failure taxonomy diagnostics.

Options:
  --mode <mode>         Bundle mode:
                        validation-pack | performance-pack | e2e-matrix | unit-gate | integration-gate
  --root <path>         Bundle root directory to validate
  --run-id <id>         Expected run identifier (optional; auto-discovered from summary/manifest)
  --report <path>       Output report JSON path (default: <root>/forensics_validator_report.json)
  --registry <path>     Scenario registry JSON path (default: scripts/e2e/scenario_registry.json)
  -h, --help            Show this help
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

sha256_file() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${file_path}" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${file_path}" | awk '{print $1}'
    return 0
  fi
  openssl dgst -sha256 "${file_path}" | awk '{print $NF}'
}

sha256_text() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
    return 0
  fi
  openssl dgst -sha256 | awk '{print $NF}'
}

add_issue() {
  local rule="$1"
  local severity="$2"
  local message="$3"
  local path="${4:-}"
  local line="${5:-}"
  local issue
  issue="$(jq -c -n \
    --arg rule "${rule}" \
    --arg severity "${severity}" \
    --arg message "${message}" \
    --arg path "${path}" \
    --arg line "${line}" \
    '{
      rule: $rule,
      severity: $severity,
      message: $message,
      path: (if ($path | length) == 0 then null else $path end),
      line: (if ($line | length) == 0 then null else ($line | tonumber?) end)
    }')"
  ISSUES+=("${issue}")
}

add_checked_file() {
  local rel="$1"
  if [[ -n "${rel}" ]]; then
    CHECKED_FILES+=("${rel}")
  fi
}

to_rel_path() {
  local abs="$1"
  if [[ "${abs}" == "${ROOT}" ]]; then
    printf '.'
  elif [[ "${abs}" == "${ROOT}/"* ]]; then
    printf '%s' "${abs#"${ROOT}/"}"
  else
    printf '%s' "${abs}"
  fi
}

resolve_artifact_path() {
  local candidate="$1"
  if [[ -z "${candidate}" || "${candidate}" == "null" ]]; then
    printf ''
    return 0
  fi
  if [[ "${candidate}" = /* ]]; then
    printf '%s' "${candidate}"
    return 0
  fi
  if [[ -e "${ROOT}/${candidate}" ]]; then
    printf '%s' "${ROOT}/${candidate}"
    return 0
  fi
  if [[ -e "${REPO_ROOT}/${candidate}" ]]; then
    printf '%s' "${REPO_ROOT}/${candidate}"
    return 0
  fi
  if [[ "${candidate}" == "$(basename "${ROOT}")/"* ]]; then
    printf '%s' "${ROOT}/${candidate#$(basename "${ROOT}")/}"
  else
    printf '%s' "${ROOT}/${candidate}"
  fi
}

require_file() {
  local rel="$1"
  local rule="$2"
  local abs="${ROOT}/${rel}"
  if [[ ! -f "${abs}" ]]; then
    add_issue "${rule}" "error" "required file is missing" "${rel}"
    return 1
  fi
  add_checked_file "${rel}"
  return 0
}

validate_json_file() {
  local rel="$1"
  local rule="$2"
  local abs="${ROOT}/${rel}"
  if ! require_file "${rel}" "${rule}"; then
    return 1
  fi
  if ! jq -e . "${abs}" >/dev/null 2>&1; then
    add_issue "${rule}" "error" "file is not valid JSON" "${rel}"
    return 1
  fi
  return 0
}

discover_run_id() {
  if [[ -n "${RUN_ID}" ]]; then
    return 0
  fi

  local candidate
  for candidate in "summary.json" "gate_summary.json" "manifest.json"; do
    if [[ -f "${ROOT}/${candidate}" ]]; then
      RUN_ID="$(jq -r '.run_id // empty' "${ROOT}/${candidate}" 2>/dev/null || true)"
      if [[ -n "${RUN_ID}" ]]; then
        return 0
      fi
    fi
  done
}

validate_run_id_field() {
  local rel="$1"
  local rule="$2"
  local abs="${ROOT}/${rel}"
  if ! validate_json_file "${rel}" "${rule}"; then
    return 1
  fi
  if [[ -n "${RUN_ID}" ]]; then
    if ! jq -e --arg run_id "${RUN_ID}" '.run_id == $run_id' "${abs}" >/dev/null 2>&1; then
      add_issue "${rule}" "error" "run_id does not match expected run_id" "${rel}"
      return 1
    fi
  fi
  return 0
}

validate_replay_script() {
  local rel="$1"
  local rule="$2"
  local abs="${ROOT}/${rel}"
  if ! require_file "${rel}" "${rule}"; then
    return 1
  fi
  if [[ ! -x "${abs}" ]]; then
    add_issue "${rule}" "error" "replay script is not executable" "${rel}"
  fi
  if ! head -n 1 "${abs}" | grep -q '^#!/usr/bin/env bash$'; then
    add_issue "${rule}" "error" "replay script must start with bash shebang" "${rel}"
  fi
  if ! rg -q '^set -euo pipefail$' "${abs}"; then
    add_issue "${rule}" "error" "replay script must set strict shell options" "${rel}"
  fi
  local non_comment
  non_comment="$(grep -Evc '^[[:space:]]*(#|$)' "${abs}" || true)"
  if (( non_comment < 2 )); then
    add_issue "${rule}" "error" "replay script missing executable replay commands" "${rel}"
  fi
}

validate_forensics_step_line() {
  local line="$1"
  local rel="$2"
  local line_no="$3"
  local log_field log_abs log_rel outcome reason

  if ! jq -e . >/dev/null 2>&1 <<< "${line}"; then
    add_issue "forensics.steps.json" "error" "invalid JSON line in steps file" "${rel}" "${line_no}"
    return 0
  fi

  if ! jq -e --arg run_id "${RUN_ID}" '
    def non_empty_str: type == "string" and length > 0;
    def nonneg_int: type == "number" and . >= 0 and floor == .;
    type == "object"
    and .schema_version == "asupersync-forensics/v1"
    and ((($run_id | length) == 0) or (.run_id == $run_id))
    and (.run_id | non_empty_str)
    and (.scenario_id | non_empty_str)
    and (.trace_id | non_empty_str)
    and (.correlation_id | non_empty_str)
    and (.connector | non_empty_str)
    and (.zone | non_empty_str)
    and (.operation | non_empty_str)
    and (.attempt | nonneg_int and . >= 1)
    and (.timeout_budget_ms | nonneg_int)
    and ((.cancellation_reason == null) or (.cancellation_reason | non_empty_str))
    and ((.queue_depth == null) or (.queue_depth | type == "number" and . >= 0))
    and ((.decode_budget == null) or (.decode_budget | type == "number" and . >= 0))
    and (.outcome | IN("pass", "fail", "planned"))
    and (.elapsed_ms | nonneg_int)
    and ((has("span_id") | not) or (.span_id | type == "string" and test("^[0-9a-fA-F]{16}$")))
    and ((has("result_code") | not) or (.result_code | non_empty_str))
  ' <<< "${line}" >/dev/null; then
    add_issue "forensics.steps.schema" "error" "forensics step line violates required schema invariants" "${rel}" "${line_no}"
    return 0
  fi

  outcome="$(jq -r '.outcome' <<< "${line}")"
  log_field="$(jq -r '.log_path // .execution_log // empty' <<< "${line}")"

  if [[ "${outcome}" != "planned" ]]; then
    if [[ -z "${log_field}" ]]; then
      add_issue "forensics.steps.log_path" "error" "non-planned step is missing log path" "${rel}" "${line_no}"
    else
      log_abs="$(resolve_artifact_path "${log_field}")"
      if [[ ! -f "${log_abs}" ]]; then
        add_issue "forensics.steps.log_missing" "error" "referenced step log file is missing" "${log_field}" "${line_no}"
      else
        log_rel="$(to_rel_path "${log_abs}")"
        add_checked_file "${log_rel}"
        if [[ ! -s "${log_abs}" ]]; then
          add_issue "forensics.steps.log_empty" "error" "referenced step log file is empty" "${log_rel}" "${line_no}"
        fi
      fi
    fi
  fi

  if [[ "${outcome}" == "fail" ]]; then
    reason="$(jq -r '.reason // .result_code // empty' <<< "${line}")"
    if [[ -z "${reason}" ]]; then
      add_issue "forensics.failure.reason" "error" "failed step must include reason or result_code" "${rel}" "${line_no}"
      return 0
    fi
    case "${reason}" in
      fail|failed|error|unknown)
        add_issue "forensics.failure.actionable_reason" "error" "failure reason is too generic; include actionable taxonomy" "${rel}" "${line_no}"
        ;;
    esac
  fi
}

validate_steps_jsonl() {
  local rel="$1"
  local abs="${ROOT}/${rel}"
  local line_no=0
  local line

  if ! require_file "${rel}" "forensics.steps.file"; then
    return 1
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_no=$((line_no + 1))
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi
    validate_forensics_step_line "${line}" "${rel}" "${line_no}"
  done < "${abs}"
}

validate_results_jsonl() {
  local rel="$1"
  local abs="${ROOT}/${rel}"
  local line_no=0
  local line

  if ! require_file "${rel}" "forensics.results.file"; then
    return 1
  fi

  if [[ ! -f "${REGISTRY}" ]]; then
    add_issue "forensics.registry.file" "error" "scenario registry file missing" "$(to_rel_path "${REGISTRY}")"
  elif ! jq -e . "${REGISTRY}" >/dev/null 2>&1; then
    add_issue "forensics.registry.json" "error" "scenario registry is not valid JSON" "$(to_rel_path "${REGISTRY}")"
  else
    add_checked_file "$(to_rel_path "${REGISTRY}")"
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_no=$((line_no + 1))
    if [[ -z "${line//[[:space:]]/}" ]]; then
      continue
    fi

    if ! jq -e . >/dev/null 2>&1 <<< "${line}"; then
      add_issue "forensics.results.json" "error" "invalid JSON line in results file" "${rel}" "${line_no}"
      continue
    fi

    if ! jq -e --arg run_id "${RUN_ID}" '
      def non_empty_str: type == "string" and length > 0;
      def nonneg_int: type == "number" and . >= 0 and floor == .;
      type == "object"
      and .schema_version == "asupersync-e2e-harness/v1"
      and ((($run_id | length) == 0) or (.run_id == $run_id))
      and (.run_id | non_empty_str)
      and (.scenario | non_empty_str)
      and (.scenario_id | non_empty_str)
      and (.script | non_empty_str)
      and (.required | type == "boolean")
      and (.selected | type == "boolean")
      and (.status | IN("pass", "fail", "skipped", "planned"))
      and (.duration_ms | nonneg_int)
      and (.log | non_empty_str)
      and (.execution_log | non_empty_str)
      and (.command_path | non_empty_str)
      and (.replay_command | non_empty_str)
    ' <<< "${line}" >/dev/null; then
      add_issue "forensics.results.schema" "error" "results line violates required schema invariants" "${rel}" "${line_no}"
      continue
    fi

    local scenario scenario_id script expected required actual_required
    local status log_path execution_log command_path scenario_json reason
    scenario="$(jq -r '.scenario' <<< "${line}")"
    scenario_id="$(jq -r '.scenario_id' <<< "${line}")"
    script="$(jq -r '.script' <<< "${line}")"
    status="$(jq -r '.status' <<< "${line}")"
    log_path="$(jq -r '.log' <<< "${line}")"
    execution_log="$(jq -r '.execution_log' <<< "${line}")"
    command_path="$(jq -r '.command_path' <<< "${line}")"
    reason="$(jq -r '.reason // empty' <<< "${line}")"

    if [[ -f "${REGISTRY}" ]]; then
      expected="$(jq -c --arg key "${scenario}" '.scenarios[] | select(.key == $key)' "${REGISTRY}" | head -n 1 || true)"
      if [[ -z "${expected}" ]]; then
        add_issue "forensics.registry.scenario" "error" "scenario key missing from scenario registry" "${rel}" "${line_no}"
      else
        local expected_id expected_script
        expected_id="$(jq -r '.scenario_id' <<< "${expected}")"
        expected_script="$(jq -r '.script' <<< "${expected}")"
        actual_required="$(jq -r '.required' <<< "${line}")"
        required="$(jq -r '.required' <<< "${expected}")"

        if [[ "${scenario_id}" != "${expected_id}" ]]; then
          add_issue "forensics.registry.scenario_id" "error" "scenario_id does not match registry mapping" "${rel}" "${line_no}"
        fi
        if [[ "${script}" != "${expected_script}" && "${script}" != *"/${expected_script}" ]]; then
          add_issue "forensics.registry.script" "error" "script path does not match registry mapping" "${rel}" "${line_no}"
        fi
        if [[ "${actual_required}" != "${required}" ]]; then
          add_issue "forensics.registry.required" "error" "required flag does not match scenario registry" "${rel}" "${line_no}"
        fi
      fi
    fi

    local command_abs execution_abs log_abs
    command_abs="$(resolve_artifact_path "${command_path}")"
    if [[ ! -f "${command_abs}" ]]; then
      add_issue "forensics.results.command_path" "error" "command file is missing" "${command_path}" "${line_no}"
    else
      add_checked_file "$(to_rel_path "${command_abs}")"
    fi

    scenario_json="$(dirname "${command_abs}")/scenario.json"
    if [[ ! -f "${scenario_json}" ]]; then
      add_issue "forensics.results.scenario_json" "error" "scenario metadata file is missing" "$(to_rel_path "${scenario_json}")" "${line_no}"
    else
      add_checked_file "$(to_rel_path "${scenario_json}")"
      if ! jq -e --arg run_id "${RUN_ID}" --arg scenario "${scenario}" '
        .run_id == $run_id and .scenario == $scenario
      ' "${scenario_json}" >/dev/null 2>&1; then
        add_issue "forensics.results.scenario_json_content" "error" "scenario metadata is malformed or mismatched" "$(to_rel_path "${scenario_json}")" "${line_no}"
      fi
    fi

    if [[ "${status}" == "pass" || "${status}" == "fail" ]]; then
      execution_abs="$(resolve_artifact_path "${execution_log}")"
      if [[ ! -f "${execution_abs}" ]]; then
        add_issue "forensics.results.execution_log" "error" "execution log is missing for executed scenario" "${execution_log}" "${line_no}"
      else
        add_checked_file "$(to_rel_path "${execution_abs}")"
        if [[ ! -s "${execution_abs}" ]]; then
          add_issue "forensics.results.execution_log_empty" "error" "execution log is empty for executed scenario" "$(to_rel_path "${execution_abs}")" "${line_no}"
        fi
      fi

      log_abs="$(resolve_artifact_path "${log_path}")"
      if [[ ! -f "${log_abs}" ]]; then
        add_issue "forensics.results.log_jsonl" "error" "scenario JSONL log artifact is missing" "${log_path}" "${line_no}"
      else
        add_checked_file "$(to_rel_path "${log_abs}")"
        if [[ ! -s "${log_abs}" ]]; then
          add_issue "forensics.results.log_jsonl_empty" "error" "scenario JSONL log artifact is empty" "$(to_rel_path "${log_abs}")" "${line_no}"
        fi
      fi
    fi

    if [[ "${status}" == "fail" ]]; then
      if [[ -z "${reason}" ]]; then
        add_issue "forensics.failure.reason" "error" "failed scenario is missing reason taxonomy" "${rel}" "${line_no}"
      else
        case "${reason}" in
          fail|failed|error|unknown)
            add_issue "forensics.failure.actionable_reason" "error" "failed scenario reason is too generic; include actionable taxonomy" "${rel}" "${line_no}"
            ;;
        esac
      fi
    fi
  done < "${abs}"
}

validate_unit_diagnostics() {
  local rel="$1"
  local abs="${ROOT}/${rel}"
  if ! validate_json_file "${rel}" "forensics.unit.diagnostics.file"; then
    return 1
  fi

  if ! jq -e '
    type == "object"
    and (.summary | type == "object")
    and (.summary.deterministic | type == "boolean")
  ' "${abs}" >/dev/null 2>&1; then
    add_issue "forensics.unit.diagnostics.schema" "error" "unit diagnostics summary is missing required deterministic metadata" "${rel}"
  fi

  while IFS=$'\t' read -r item_id fingerprint rerun; do
    if [[ -z "${item_id}" ]]; then
      continue
    fi
    if [[ -z "${fingerprint}" ]]; then
      add_issue "forensics.unit.diagnostics.fingerprint" "error" "failed diagnostic item is missing deterministic fingerprint" "${rel}"
    fi
    if [[ -z "${rerun}" ]]; then
      add_issue "forensics.unit.diagnostics.rerun" "error" "failed diagnostic item is missing rerun command" "${rel}"
    fi
  done < <(jq -r '
    ([.crate_diagnostics[]?, .connector_diagnostics[]?]
      | map(select(.test_status == "fail"))
      | .[]
      | [.id, (.fingerprint // ""), (.coverage_rows[0].rerun_command // "")]
      | @tsv)
  ' "${abs}")
}

validate_integration_drift() {
  local rel="$1"
  local abs="${ROOT}/${rel}"
  if ! validate_json_file "${rel}" "forensics.integration.drift.file"; then
    return 1
  fi
  if ! jq -e '
    type == "object"
    and (.summary | type == "object")
    and (.cross_connector_analysis | type == "object")
  ' "${abs}" >/dev/null 2>&1; then
    add_issue "forensics.integration.drift.schema" "error" "integration drift report missing required sections" "${rel}"
  fi
}

validate_mode_contract() {
  case "${MODE}" in
    validation-pack)
      validate_steps_jsonl "steps.jsonl" || true
      validate_run_id_field "summary.json" "forensics.validation.summary" || true
      validate_replay_script "replay.sh" "forensics.validation.replay" || true
      if [[ -d "${ROOT}/scenarios/e2e-matrix" ]]; then
        local nested_run_id="${RUN_ID}-e2e-matrix"
        bash "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" \
          --mode e2e-matrix \
          --root "${ROOT}/scenarios/e2e-matrix" \
          --run-id "${nested_run_id}" \
          --report "${ROOT}/scenarios/e2e-matrix/forensics_validator_report.json" >/dev/null || \
          add_issue "forensics.validation.nested_e2e" "error" "nested e2e-matrix bundle failed validation" "scenarios/e2e-matrix"
        add_checked_file "scenarios/e2e-matrix/forensics_validator_report.json"
      fi
      ;;
    performance-pack)
      validate_steps_jsonl "steps.jsonl" || true
      validate_run_id_field "summary.json" "forensics.performance.summary" || true
      validate_run_id_field "manifest.json" "forensics.performance.manifest" || true
      validate_replay_script "replay.sh" "forensics.performance.replay" || true
      validate_run_id_field "metrics_template.json" "forensics.performance.metrics_template" || true
      validate_run_id_field "normalized_summary.json" "forensics.performance.normalized_summary" || true
      validate_run_id_field "scenario_plan.json" "forensics.performance.scenario_plan" || true
      validate_json_file "delta_summary.json" "forensics.performance.delta_summary" || true
      require_file "metrics.jsonl" "forensics.performance.metrics_jsonl" || true
      if [[ -f "${ROOT}/metrics.jsonl" ]]; then
        add_checked_file "metrics.jsonl"
      fi
      if [[ -d "${ROOT}/scenarios/soak-matrix" ]]; then
        local nested_run_id="${RUN_ID}-soak-matrix"
        bash "${SCRIPT_DIR}/validate_asupersync_forensics_bundle.sh" \
          --mode e2e-matrix \
          --root "${ROOT}/scenarios/soak-matrix" \
          --run-id "${nested_run_id}" \
          --report "${ROOT}/scenarios/soak-matrix/forensics_validator_report.json" >/dev/null || \
          add_issue "forensics.performance.nested_soak" "error" "nested soak-matrix bundle failed validation" "scenarios/soak-matrix"
        add_checked_file "scenarios/soak-matrix/forensics_validator_report.json"
      fi
      ;;
    e2e-matrix)
      validate_results_jsonl "results.jsonl" || true
      validate_run_id_field "summary.json" "forensics.e2e.summary" || true
      validate_run_id_field "manifest.json" "forensics.e2e.manifest" || true
      validate_run_id_field "scenario_plan.json" "forensics.e2e.scenario_plan" || true
      validate_replay_script "replay.sh" "forensics.e2e.replay" || true
      ;;
    unit-gate)
      validate_steps_jsonl "steps.jsonl" || true
      validate_run_id_field "gate_summary.json" "forensics.unit.summary" || true
      validate_replay_script "replay.sh" "forensics.unit.replay" || true
      validate_unit_diagnostics "failure_diagnostics.json" || true
      ;;
    integration-gate)
      validate_steps_jsonl "steps.jsonl" || true
      validate_run_id_field "gate_summary.json" "forensics.integration.summary" || true
      validate_replay_script "replay.sh" "forensics.integration.replay" || true
      validate_integration_drift "drift_report.json" || true
      ;;
    *)
      add_issue "forensics.mode" "error" "unsupported mode" "${MODE}"
      ;;
  esac
}

compute_bundle_fingerprint() {
  local files_json files_sorted
  if ((${#CHECKED_FILES[@]} == 0)); then
    printf ''
    return 0
  fi

  files_json="$(printf '%s\n' "${CHECKED_FILES[@]}" | jq -R . | jq -s 'unique | sort')"
  files_sorted="$(jq -r '.[]' <<< "${files_json}")"

  while IFS= read -r rel; do
    [[ -z "${rel}" ]] && continue
    local abs="${ROOT}/${rel}"
    if [[ ! -f "${abs}" ]]; then
      continue
    fi
    local file_hash
    file_hash="$(sha256_file "${abs}")"
    printf '%s\t%s\n' "${rel}" "${file_hash}"
  done <<< "${files_sorted}" | sha256_text
}

write_report() {
  local passed="$1"
  local bundle_fingerprint="$2"
  local issues_json checked_json issue_count

  if ((${#ISSUES[@]} == 0)); then
    issues_json='[]'
  else
    issues_json="$(printf '%s\n' "${ISSUES[@]}" | jq -s 'sort_by(.rule, (.path // ""), (.line // 0), .message)')"
  fi

  if ((${#CHECKED_FILES[@]} == 0)); then
    checked_json='[]'
  else
    checked_json="$(printf '%s\n' "${CHECKED_FILES[@]}" | jq -R . | jq -s 'unique | sort')"
  fi

  issue_count="$(jq -r 'length' <<< "${issues_json}")"

  jq -n \
    --arg schema_version "asupersync-forensics-validator/v1" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg mode "${MODE}" \
    --arg root "${ROOT}" \
    --arg run_id "${RUN_ID}" \
    --arg report_path "${REPORT}" \
    --arg bundle_fingerprint "${bundle_fingerprint}" \
    --argjson passed "${passed}" \
    --argjson issue_count "${issue_count}" \
    --argjson checked_files "${checked_json}" \
    --argjson issues "${issues_json}" \
    '{
      schema_version: $schema_version,
      generated_at: $generated_at,
      mode: $mode,
      root: $root,
      run_id: $run_id,
      passed: $passed,
      issue_count: $issue_count,
      bundle_fingerprint: $bundle_fingerprint,
      checked_files: $checked_files,
      issues: $issues,
      report_path: $report_path
    }' > "${REPORT}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --root)
      ROOT="${2:-}"
      shift 2
      ;;
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --report)
      REPORT="${2:-}"
      shift 2
      ;;
    --registry)
      REGISTRY="${2:-}"
      shift 2
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

require_cmd jq
require_cmd rg
require_cmd openssl

if [[ -z "${MODE}" ]]; then
  echo "--mode is required" >&2
  exit 2
fi

if [[ -z "${ROOT}" ]]; then
  echo "--root is required" >&2
  exit 2
fi

if [[ ! -d "${ROOT}" ]]; then
  echo "bundle root does not exist: ${ROOT}" >&2
  exit 2
fi

ROOT="$(cd "${ROOT}" && pwd)"

if [[ -z "${REPORT}" ]]; then
  REPORT="${ROOT}/forensics_validator_report.json"
fi

discover_run_id
if [[ -z "${RUN_ID}" ]]; then
  add_issue "forensics.run_id" "error" "could not determine run_id from bundle metadata"
fi

validate_mode_contract

bundle_fingerprint="$(compute_bundle_fingerprint)"

if ((${#ISSUES[@]} > 0)); then
  write_report false "${bundle_fingerprint}"
  echo "ASUPERSYNC forensic bundle validation failed: ${REPORT}" >&2
  jq -r '.issues[] | "- [\(.rule)] \(.message)\(if .path then " (\(.path))" else "" end)\(if .line then " line=\(.line)" else "" end)"' "${REPORT}" >&2 || true
  exit 1
fi

write_report true "${bundle_fingerprint}"
echo "ASUPERSYNC forensic bundle validation passed: ${REPORT}"
