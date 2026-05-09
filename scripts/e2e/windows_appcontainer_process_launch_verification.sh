#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/windows_appcontainer_process_launch_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/windows-appcontainer/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/windows_appcontainer_process_launch.jsonl}"
SUMMARY_JSON="${OUT_ROOT}/summary.json"
RAW_LOG="${OUT_ROOT}/logs/fcp_sandbox_windows_appcontainer_tests.log"
TARGET_DIR="${WINDOWS_APPCONTAINER_CARGO_TARGET_DIR:-/tmp/fcp-windows-appcontainer-e2e-target}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
RCH_BIN="${RCH_BIN:-rch}"

mkdir -p "${OUT_ROOT}/logs"
: >"${LOG_JSONL}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

hash16() {
  printf '%s' "$1" | shasum -a 256 | awk '{print substr($1, 1, 16)}'
}

GIT_REVISION="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
HOST_RELEASE="$(uname -r 2>/dev/null || echo unknown)"
OS_BUILD="${HOST_OS} ${HOST_RELEASE}"
CONNECTOR_ID="fcp.windows-appcontainer.e2e"
PROFILE_NAME="fcp-windows-appcontainer-e2e-$(hash16 "${CONNECTOR_ID}")"
CONNECTOR_ID_HASH="$(hash16 "${CONNECTOR_ID}")"
PROFILE_NAME_HASH="$(hash16 "${PROFILE_NAME}")"
JOB_OBJECT_ID_HASH="$(hash16 "${CONNECTOR_ID}:job-object-intent")"
RAW_LOG_ARTIFACT="${RAW_LOG#${REPO_ROOT}/}"
LOG_JSONL_ARTIFACT="${LOG_JSONL#${REPO_ROOT}/}"
SUMMARY_JSON_ARTIFACT="${SUMMARY_JSON#${REPO_ROOT}/}"
TARGET_DIR_HASH="$(hash16 "${TARGET_DIR}")"

echo "[windows-appcontainer-e2e] cargo test -p fcp-sandbox windows_appcontainer"
(
  cd "${REPO_ROOT}"
  "${RCH_BIN}" exec -- env \
    "CARGO_TARGET_DIR=${TARGET_DIR}" \
    "FCP_SANDBOX_WINDOWS_APPCONTAINER=${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" \
    "FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E=${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" \
    cargo test -p fcp-sandbox windows_appcontainer -- --nocapture
) >"${RAW_LOG}" 2>&1

skip_reason=""
real_launch="false"
case "${HOST_OS}" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    if [[ "${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" == "1" || "${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" == "true" ]]; then
      if [[ "${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" == "1" || "${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" == "true" ]]; then
        real_launch="true"
      else
        skip_reason="windows_appcontainer_e2e_opt_in_missing"
      fi
    else
      skip_reason="windows_appcontainer_env_opt_in_missing"
    fi
    ;;
  *)
    skip_reason="host_os_not_windows_or_appcontainer_worker_unavailable"
    ;;
esac

process_id_hash=""
if [[ "${real_launch}" == "true" ]]; then
  process_id="$(sed -n 's/^WINDOWS_APPCONTAINER_E2E_PROCESS_ID=//p' "${RAW_LOG}" | tail -n 1)"
  if [[ -z "${process_id}" ]]; then
    echo "Windows AppContainer real launch proof did not emit a process id" >&2
    exit 1
  fi
  process_id_hash="$(hash16 "${process_id}")"
fi

jq -cn \
  --arg command_line "${COMMAND_LINE}" \
  --arg git_revision "${GIT_REVISION}" \
  --arg os_build "${OS_BUILD}" \
  --arg connector_id_hash "${CONNECTOR_ID_HASH}" \
  --arg profile_name_hash "${PROFILE_NAME_HASH}" \
  --arg job_object_id_hash "${JOB_OBJECT_ID_HASH}" \
  --arg raw_log "${RAW_LOG_ARTIFACT}" \
  --arg log_jsonl "${LOG_JSONL_ARTIFACT}" \
  --arg summary_json "${SUMMARY_JSON_ARTIFACT}" \
  --arg target_dir_hash "${TARGET_DIR_HASH}" \
  --arg skip_reason "${skip_reason}" \
  --arg real_launch "${real_launch}" \
  --arg process_id_hash "${process_id_hash}" \
  '{
    record_type: "windows_appcontainer_process_launch_e2e",
    schema: "fcp.windows_appcontainer_process_launch.script.v1",
    command_line: $command_line,
    git_revision: $git_revision,
    os_build: $os_build,
    connector_id_hash: $connector_id_hash,
    profile_name_hash: $profile_name_hash,
    capability_decision: "mapped",
    sid_present: ($real_launch == "true"),
    launch_mechanism: (if $real_launch == "true" then "startup_info_ex_security_capabilities" else "skipped_inactive" end),
    process_id_hash: (if $process_id_hash == "" then null else $process_id_hash end),
    job_object_id_hash: $job_object_id_hash,
    job_object_attached: ($real_launch == "true"),
    job_object_attachment_intent: (if $real_launch == "true" then "attach_after_launch" else "none" end),
    action_result: (if $real_launch == "true" then "launched" else "structured_skip" end),
    cleanup_result: (if $real_launch == "true" then "drop_closed_handles" else "none" end),
    final_readiness_layer: "process_limit",
    artifact_paths: {
      raw_log: $raw_log,
      log_jsonl: $log_jsonl,
      summary_json: $summary_json,
      target_dir_hash: $target_dir_hash
    },
    skip_reason: (if $skip_reason == "" then null else $skip_reason end)
  }' >>"${LOG_JSONL}"

jq -e '
  select(.record_type == "windows_appcontainer_process_launch_e2e") as $record
  | [
      $record.command_line,
      $record.git_revision,
      $record.os_build,
      $record.connector_id_hash,
      $record.profile_name_hash,
      $record.capability_decision,
      $record.sid_present,
      $record.launch_mechanism,
      $record.job_object_id_hash,
      $record.job_object_attached,
      $record.job_object_attachment_intent,
      $record.action_result,
      $record.cleanup_result,
      $record.final_readiness_layer,
      $record.artifact_paths.raw_log,
      $record.artifact_paths.log_jsonl,
      $record.artifact_paths.summary_json,
      $record.artifact_paths.target_dir_hash
    ]
    | all(. != null)
  and (
    if $record.action_result == "launched" then
      $record.sid_present == true
      and $record.job_object_attached == true
      and $record.job_object_attachment_intent == "attach_after_launch"
      and $record.process_id_hash != null
      and $record.skip_reason == null
    else
      $record.skip_reason != null
    end
  )
' "${LOG_JSONL}" >/dev/null

if grep -aE "${CONNECTOR_ID}|${PROFILE_NAME}|Bearer|token|secret|C:\\\\Users|/Users/|WINDOWS_APPCONTAINER_E2E_PROCESS_ID" "${LOG_JSONL}" >/dev/null; then
  echo "Windows AppContainer JSONL leaked a raw identifier, token marker, or private path" >&2
  exit 1
fi

result="passed_with_structured_skip"
if [[ "${real_launch}" == "true" ]]; then
  result="passed_with_real_launch"
fi

jq -cn \
  --arg run_id "${RUN_ID}" \
  --arg git_revision "${GIT_REVISION}" \
  --arg result "${result}" \
  --arg log_jsonl "${LOG_JSONL_ARTIFACT}" \
  --arg raw_log "${RAW_LOG_ARTIFACT}" \
  --arg target_dir_hash "${TARGET_DIR_HASH}" \
  --arg skip_reason "${skip_reason}" \
  --arg real_launch "${real_launch}" \
  '{
    run_id: $run_id,
    git_revision: $git_revision,
    result: $result,
    real_launch: ($real_launch == "true"),
    log_jsonl: $log_jsonl,
    raw_log: $raw_log,
    target_dir_hash: $target_dir_hash,
    skip_reason: (if $skip_reason == "" then null else $skip_reason end)
  }' >"${SUMMARY_JSON}"

echo "WINDOWS_APPCONTAINER_PROCESS_LAUNCH_JSONL=${LOG_JSONL}"
echo "Windows AppContainer verification artifacts written to ${OUT_ROOT}"
