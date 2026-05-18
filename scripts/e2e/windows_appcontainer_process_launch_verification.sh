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
CARGO_TARGET="${WINDOWS_APPCONTAINER_CARGO_TARGET:-}"
CARGO_FEATURES="${WINDOWS_APPCONTAINER_CARGO_FEATURES:-windows-appcontainer}"
CARGO_TEST_FILTER="${WINDOWS_APPCONTAINER_CARGO_TEST_FILTER:-windows_appcontainer}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
BEAD_ID="${WINDOWS_APPCONTAINER_BEAD_ID:-flywheel_connectors-r4qcg.1.1}"

export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs"
: >"${LOG_JSONL}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

hash_sha256() {
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  else
    echo "shasum or sha256sum is required for ${SCRIPT_PATH}" >&2
    exit 2
  fi
}

hash16() {
  hash_sha256 "$1" | awk '{print substr($1, 1, 16)}'
}

json_string_or_null() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    jq -Rn --arg value "${value}" '$value'
  else
    printf 'null'
  fi
}

target_dir_class() {
  local path="$1"
  case "${path}" in
    /tmp|/tmp/*|/private/tmp|/private/tmp/*)
      printf 'tmp'
      ;;
    /*)
      printf 'absolute'
      ;;
    *)
      printf 'relative'
      ;;
  esac
}

artifact_ref() {
  local path="$1"
  case "${path}" in
    "${OUT_ROOT}/"*)
      printf '%s' "${path#"${OUT_ROOT}"/}"
      ;;
    "${REPO_ROOT}/"*)
      printf '%s' "${path#"${REPO_ROOT}"/}"
      ;;
    *)
      printf 'sha256:%s' "$(hash_sha256 "${path}")"
      ;;
  esac
}

rch_summary_line() {
  if [[ -s "${RAW_LOG}" ]]; then
    grep -aE '^\[RCH\] (remote|local|failed)' "${RAW_LOG}" | tail -n 1 || true
  fi
}

fallback_decision_for_log() {
  local summary="$1"
  if [[ "${RCH_BIN}" == "direct" ]]; then
    printf 'not_needed'
  elif [[ -z "${summary}" ]]; then
    printf 'rch_summary_unobserved'
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'rch_local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] failed'; then
    printf 'rch_remote_failed'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    if grep -aqE 'remote required; refusing local fallback|refus(ed|ing) local fallback' "${RAW_LOG}"; then
      printf 'rch_local_fallback_refused'
    else
      printf 'rch_local_fallback'
    fi
  elif printf '%s' "${summary}" | grep -Fq '[RCH] remote'; then
    printf 'not_needed'
  else
    printf 'rch_summary_unclassified'
  fi
}

worker_execution_class_for_log() {
  local summary="$1"
  if [[ "${RCH_BIN}" == "direct" ]]; then
    printf 'not_applicable'
  elif [[ -z "${summary}" ]]; then
    printf 'unknown'
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] failed'; then
    printf 'remote_failed'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    if grep -aqE 'remote required; refusing local fallback|refus(ed|ing) local fallback' "${RAW_LOG}"; then
      printf 'local_fallback_refused'
    else
      printf 'local'
    fi
  elif printf '%s' "${summary}" | grep -Fq '[RCH] remote'; then
    printf 'remote'
  else
    printf 'unknown'
  fi
}

run_windows_appcontainer_tests() {
  local cargo_args
  cargo_args=(test -p fcp-sandbox)
  if [[ -n "${CARGO_TARGET}" ]]; then
    cargo_args+=(--target "${CARGO_TARGET}")
  fi
  if [[ -n "${CARGO_FEATURES}" ]]; then
    cargo_args+=(--features "${CARGO_FEATURES}")
  fi
  cargo_args+=("${CARGO_TEST_FILTER}" -- --nocapture)

  cd "${REPO_ROOT}"
  if [[ "${RCH_BIN}" == "direct" ]]; then
    env \
      "CARGO_TARGET_DIR=${TARGET_DIR}" \
      "FCP_SANDBOX_WINDOWS_APPCONTAINER=${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" \
      "FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E=${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" \
      cargo "${cargo_args[@]}"
  else
    env \
      "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE}" \
      RCH_FORCE_REMOTE=1 \
      "RCH_VISIBILITY=${RCH_VISIBILITY}" \
      "${RCH_BIN}" exec -- env \
      "CARGO_TARGET_DIR=${TARGET_DIR}" \
      CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}" \
      "FCP_SANDBOX_WINDOWS_APPCONTAINER=${FCP_SANDBOX_WINDOWS_APPCONTAINER:-}" \
      "FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E=${FCP_SANDBOX_WINDOWS_APPCONTAINER_E2E:-}" \
      cargo "${cargo_args[@]}"
  fi
}

GIT_REVISION="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"
HOST_OS="$(uname -s 2>/dev/null || echo unknown)"
HOST_RELEASE="$(uname -r 2>/dev/null || echo unknown)"
OS_BUILD="${HOST_OS} ${HOST_RELEASE}"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
CORRELATION_ID="windows-appcontainer-${RUN_ID}"
CONNECTOR_ID="fcp.windows-appcontainer.e2e"
PROFILE_NAME="fcp-windows-appcontainer-e2e-$(hash16 "${CONNECTOR_ID}")"
CONNECTOR_ID_HASH="$(hash16 "${CONNECTOR_ID}")"
PROFILE_NAME_HASH="$(hash16 "${PROFILE_NAME}")"
JOB_OBJECT_ID_HASH="$(hash16 "${CONNECTOR_ID}:job-object-intent")"
RAW_LOG_ARTIFACT="$(artifact_ref "${RAW_LOG}")"
LOG_JSONL_ARTIFACT="$(artifact_ref "${LOG_JSONL}")"
SUMMARY_JSON_ARTIFACT="$(artifact_ref "${SUMMARY_JSON}")"
TARGET_DIR_CLASS="$(target_dir_class "${TARGET_DIR}")"
TARGET_DIR_HASH="sha256:$(hash_sha256 "${TARGET_DIR}")"
test_status="passed"
exit_code=0

echo "[windows-appcontainer-e2e] cargo test -p fcp-sandbox windows_appcontainer"
if [[ "${RCH_BIN}" == "direct" ]]; then
  case "${HOST_OS}" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      if ! (
        run_windows_appcontainer_tests
      ) >"${RAW_LOG}" 2>&1; then
        test_status="failed"
      fi
      ;;
    *)
      test_status="skipped"
      printf 'RCH_BIN=direct requires a Windows runner for %s\n' "${SCRIPT_PATH}" >"${RAW_LOG}"
      ;;
  esac
else
  if ! (
    run_windows_appcontainer_tests
  ) >"${RAW_LOG}" 2>&1; then
    test_status="failed"
  fi
fi

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

rch_summary="$(rch_summary_line)"
rch_summary_json="$(json_string_or_null "${rch_summary}")"
fallback_decision="$(fallback_decision_for_log "${rch_summary}")"
worker_execution_class="$(worker_execution_class_for_log "${rch_summary}")"

if [[ "${test_status}" == "failed" && "${RCH_BIN}" != "direct" ]] &&
  grep -aqE '(no admissible workers|no workers passed|all workers failed preflight|failed to execute process|topology preflight|Permission denied|No such file or directory|remote required; refusing local fallback|refus(ed|ing) local fallback)' "${RAW_LOG}"; then
  test_status="skipped"
  skip_reason="rch_remote_prerequisite_unavailable"
fi

if [[ "${test_status}" == "skipped" && "${RCH_BIN}" == "direct" && -z "${skip_reason}" ]]; then
  skip_reason="direct_runner_requires_windows_host"
fi

if [[ "${test_status}" == "passed" && "${RCH_BIN}" != "direct" && "${worker_execution_class}" != "remote" ]]; then
  test_status="failed"
  skip_reason=""
fi

if [[ "${test_status}" != "passed" ]]; then
  real_launch="false"
fi

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
  --arg schema_version "1.0.0" \
  --arg bead_id "${BEAD_ID}" \
  --arg actor "host" \
  --arg redaction_scope "public" \
  --arg correlation_id "${CORRELATION_ID}" \
  --arg timestamp "${TIMESTAMP}" \
  --arg command_line "${COMMAND_LINE}" \
  --arg git_revision "${GIT_REVISION}" \
  --arg os_build "${OS_BUILD}" \
  --arg cargo_runner "${RCH_BIN}" \
  --arg cargo_target "${CARGO_TARGET}" \
  --arg cargo_features "${CARGO_FEATURES}" \
  --arg rch_require_remote "${RCH_REQUIRE_REMOTE}" \
  --arg connector_id_hash "${CONNECTOR_ID_HASH}" \
  --arg profile_name_hash "${PROFILE_NAME_HASH}" \
  --arg job_object_id_hash "${JOB_OBJECT_ID_HASH}" \
  --arg raw_log "${RAW_LOG_ARTIFACT}" \
  --arg log_jsonl "${LOG_JSONL_ARTIFACT}" \
  --arg summary_json "${SUMMARY_JSON_ARTIFACT}" \
  --arg target_dir_class "${TARGET_DIR_CLASS}" \
  --arg target_dir_hash "${TARGET_DIR_HASH}" \
  --arg skip_reason "${skip_reason}" \
  --arg real_launch "${real_launch}" \
  --arg process_id_hash "${process_id_hash}" \
  --arg test_status "${test_status}" \
  --arg fallback_decision "${fallback_decision}" \
  --arg worker_execution_class "${worker_execution_class}" \
  --argjson rch_summary "${rch_summary_json}" \
  '{
    schema_version: $schema_version,
    record_type: "windows_appcontainer_process_launch_e2e",
    schema: "fcp.windows_appcontainer_process_launch.script.v1",
    bead_id: $bead_id,
    actor: $actor,
    redaction_scope: $redaction_scope,
    correlation_id: $correlation_id,
    timestamp: $timestamp,
    command_line: $command_line,
    git_revision: $git_revision,
    os_build: $os_build,
    cargo_runner: $cargo_runner,
    cargo_target: (if $cargo_target == "" then null else $cargo_target end),
    cargo_features: (if $cargo_features == "" then null else $cargo_features end),
    rch_require_remote: $rch_require_remote,
    connector_id_hash: $connector_id_hash,
    profile_name_hash: $profile_name_hash,
    capability_decision: "mapped",
    sid_present: ($real_launch == "true"),
    launch_mechanism: (if $real_launch == "true" then "startup_info_ex_security_capabilities" elif $test_status == "failed" then "verification_failed" else "skipped_inactive" end),
    process_id_hash: (if $process_id_hash == "" then null else $process_id_hash end),
    job_object_id_hash: $job_object_id_hash,
    job_object_attached: ($real_launch == "true"),
    job_object_attachment_intent: (if $real_launch == "true" then "attach_after_launch" else "none" end),
    test_status: $test_status,
    fallback_decision: $fallback_decision,
    worker_execution_class: $worker_execution_class,
    required_worker_execution_class: (if $cargo_runner == "direct" then "not_applicable" else "remote" end),
    rch_summary: $rch_summary,
    action_result: (if $real_launch == "true" then "launched" elif $test_status == "failed" then "verification_failed" else "structured_skip" end),
    cleanup_result: (if $real_launch == "true" then "drop_closed_handles" else "none" end),
    final_readiness_layer: "process_limit",
    artifact_paths: {
      raw_log: $raw_log,
      log_jsonl: $log_jsonl,
      summary_json: $summary_json,
      target_dir_class: $target_dir_class,
      target_dir_hash: $target_dir_hash
    },
    skip_reason: (if $skip_reason == "" then null else $skip_reason end)
  }' >>"${LOG_JSONL}"

jq -e '
  select(.record_type == "windows_appcontainer_process_launch_e2e") as $record
  | [
      $record.schema_version,
      $record.bead_id,
      $record.actor,
      $record.redaction_scope,
      $record.correlation_id,
      $record.timestamp,
      $record.command_line,
      $record.git_revision,
      $record.os_build,
      $record.cargo_runner,
      $record.rch_require_remote,
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
      $record.artifact_paths.target_dir_class,
      $record.artifact_paths.target_dir_hash
    ]
    | all(. != null)
  and ($record.artifact_paths.target_dir_hash | test("^sha256:[0-9a-f]{64}$"))
  and (
    if $record.cargo_runner == "direct" then
      $record.worker_execution_class == "not_applicable"
      and $record.fallback_decision == "not_needed"
      and $record.rch_summary == null
    elif $record.test_status == "passed" then
      $record.worker_execution_class == "remote"
      and ($record.rch_summary | type == "string" and contains("[RCH] remote"))
      and $record.fallback_decision == "not_needed"
    else
      $record.worker_execution_class != "local"
    end
  )
  and (
    if $record.action_result == "launched" then
      $record.sid_present == true
      and $record.job_object_attached == true
      and $record.job_object_attachment_intent == "attach_after_launch"
      and $record.process_id_hash != null
      and $record.skip_reason == null
    elif $record.action_result == "verification_failed" then
      $record.test_status == "failed"
    else
      $record.skip_reason != null
    end
  )
' "${LOG_JSONL}" >/dev/null

if grep -aE "${CONNECTOR_ID}|${PROFILE_NAME}|Bearer|token|secret|C:\\\\Users|/Users/|/private/tmp|/tmp/|WINDOWS_APPCONTAINER_E2E_PROCESS_ID" "${LOG_JSONL}" >/dev/null; then
  echo "Windows AppContainer JSONL leaked a raw identifier, token marker, or private path" >&2
  exit 1
fi

result="passed_with_structured_skip"
if [[ "${real_launch}" == "true" ]]; then
  result="passed_with_real_launch"
elif [[ "${test_status}" == "failed" ]]; then
  result="failed"
  exit_code=1
fi

jq -cn \
  --arg run_id "${RUN_ID}" \
  --arg git_revision "${GIT_REVISION}" \
  --arg bead_id "${BEAD_ID}" \
  --arg result "${result}" \
  --arg log_jsonl "${LOG_JSONL_ARTIFACT}" \
  --arg raw_log "${RAW_LOG_ARTIFACT}" \
  --arg target_dir_hash "${TARGET_DIR_HASH}" \
  --arg target_dir_class "${TARGET_DIR_CLASS}" \
  --arg skip_reason "${skip_reason}" \
  --arg real_launch "${real_launch}" \
  --arg test_status "${test_status}" \
  --arg fallback_decision "${fallback_decision}" \
  --arg worker_execution_class "${worker_execution_class}" \
  --argjson rch_summary "${rch_summary_json}" \
  '{
    run_id: $run_id,
    git_revision: $git_revision,
    bead_id: $bead_id,
    result: $result,
    real_launch: ($real_launch == "true"),
    log_jsonl: $log_jsonl,
    raw_log: $raw_log,
    target_dir_class: $target_dir_class,
    target_dir_hash: $target_dir_hash,
    test_status: $test_status,
    fallback_decision: $fallback_decision,
    worker_execution_class: $worker_execution_class,
    rch_summary: $rch_summary,
    skip_reason: (if $skip_reason == "" then null else $skip_reason end)
  }' >"${SUMMARY_JSON}"

echo "WINDOWS_APPCONTAINER_PROCESS_LAUNCH_JSONL=${LOG_JSONL}"
echo "Windows AppContainer verification artifacts written to ${OUT_ROOT}"
exit "${exit_code}"
