#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/tlon_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/tlon_connector/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/tlon_connector_verification.jsonl}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
REMOTE_TARGET_BASE="${REMOTE_TARGET_BASE:-/tmp/rch-fcp-tlon-${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-${REMOTE_TARGET_BASE}-target}"

export RCH_FORCE_REMOTE=1
export RCH_REQUIRE_REMOTE
export RCH_VISIBILITY

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"
: >"${LOG_JSONL}"

OVERALL_STATUS="passed"
EXIT_CODE=0

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 2
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

emit_step() {
  local scenario="$1"
  local outcome="$2"
  local log_path="$3"
  local cargo_target_dir="$4"
  local command="$5"
  local summary worker_class required_worker_class
  summary="$(rch_summary_line "${log_path}")"
  worker_class="$(worker_execution_class_for_log "${log_path}")"
  required_worker_class="$(required_worker_execution_class_for_step "${scenario}")"

  jq -cn \
    --arg record_type "tlon_connector_verification_step" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${git_revision}" \
    --arg connector_id "fcp.tlon" \
    --arg suite_class "local_non_mock" \
    --arg scenario "${scenario}" \
    --arg outcome "${outcome}" \
    --arg log_path "${log_path}" \
    --arg cargo_target_dir "${cargo_target_dir}" \
    --arg command "${command}" \
    --arg worker_execution_class "${worker_class}" \
    --arg required_worker_execution_class "${required_worker_class}" \
    --argjson rch_summary "$(json_string_or_null "${summary}")" \
    '{
      record_type: $record_type,
      command_line: $command_line,
      git_revision: $git_revision,
      connector_id: $connector_id,
      suite_class: $suite_class,
      scenario: $scenario,
      outcome: $outcome,
      log_path: $log_path,
      cargo_target_dir: $cargo_target_dir,
      command: $command,
      worker_execution_class: $worker_execution_class,
      required_worker_execution_class: $required_worker_execution_class,
      rch_summary: $rch_summary,
      redaction: {
        raw_ship_logged: false,
        raw_channel_logged: false,
        session_cookie_logged: false,
        message_body_logged: false
      }
    }' >>"${LOG_JSONL}"
}

json_string_or_null() {
  local value="$1"
  if [[ -n "${value}" ]]; then
    jq -Rn --arg value "${value}" '$value'
  else
    printf 'null'
  fi
}

rch_summary_line() {
  local log_path="$1"
  grep -aE '^\[RCH\] (remote|local|failed)' "${log_path}" | tail -n 1 || true
}

worker_execution_class_for_log() {
  local log_path="$1"
  local summary
  summary="$(rch_summary_line "${log_path}")"

  if [[ -z "${summary}" ]]; then
    printf 'unknown'
  elif printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'local_fallback_refused'
  elif printf '%s' "${summary}" | grep -Fq '[RCH] local'; then
    if grep -aqE 'remote required; refusing local fallback|refus(ed|ing) local fallback' "${log_path}"; then
      printf 'local_fallback_refused'
    else
      printf 'local'
    fi
  elif printf '%s' "${summary}" | grep -Fq 'failed'; then
    printf 'remote_failed'
  elif printf '%s' "${summary}" | grep -Eq '^\[RCH\] remote([[:space:]]|$)' &&
    ! printf '%s' "${summary}" | grep -Eq 'remote required; refusing local fallback|refus(ed|ing) local fallback'; then
    printf 'remote'
  else
    printf 'unknown'
  fi
}

required_worker_execution_class_for_step() {
  case "$1" in
    format_check)
      printf 'source_state'
      ;;
    redaction_scan)
      printf 'not_applicable'
      ;;
    *)
      printf 'remote'
      ;;
  esac
}

classify_failure() {
  local log_path="$1"
  if grep -aE 'RCH-E|remote required; refusing local fallback|refus(ed|ing) local fallback|\[RCH\] local|no admissible workers|no worker assigned|no workers passed|all workers failed preflight|failed to execute process|timeout: failed to execute process|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|No space left on device|missing worker system package' "${log_path}" >/dev/null; then
    printf 'infra_blocked'
  else
    printf 'failed'
  fi
}

promote_status() {
  local status="$1"
  case "${status}" in
    failed)
      OVERALL_STATUS="failed"
      EXIT_CODE=1
      ;;
    infra_blocked)
      if [[ "${OVERALL_STATUS}" == "passed" ]]; then
        OVERALL_STATUS="infra_blocked"
        EXIT_CODE=2
      fi
      ;;
  esac
}

promote_failure() {
  promote_status "failed"
}

run_logged() {
  local name="$1"
  local cargo_target_dir="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local command_text="$*"
  local status="passed"
  local required_worker_class
  required_worker_class="$(required_worker_execution_class_for_step "${name}")"

  echo "[tlon-verification] ${name}: ${command_text}"
  if (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${log_path}" 2>&1; then
    if [[ "${required_worker_class}" == "remote" ]] && [[ "$(worker_execution_class_for_log "${log_path}")" != "remote" ]]; then
      printf '%s\n' "rch command did not produce accepted remote proof" >>"${log_path}"
      status="infra_blocked"
    fi
  else
    status="$(classify_failure "${log_path}")"
  fi

  emit_step "${name}" "${status}" "${log_path}" "${cargo_target_dir}" "${command_text}"
  promote_status "${status}"
}

redaction_scan() {
  local scan_log="${OUT_ROOT}/logs/redaction_scan.log"
  local forbidden=(
    "urbauth-ship=fixture-session"
    "body text that must stay out of evidence"
    "/ship/~zod/general"
    "fixture-credential-id"
  )

  : >"${scan_log}"
  for needle in "${forbidden[@]}"; do
    if grep -R -F -- "${needle}" "${LOG_JSONL}" "${OUT_ROOT}/logs" >>"${scan_log}" 2>&1; then
      emit_step "redaction_scan" "failed" "${scan_log}" "n/a" "grep forbidden fixture material"
      promote_failure
      return
    fi
  done

  emit_step "redaction_scan" "passed" "${scan_log}" "n/a" "grep forbidden fixture material"
}

emit_summary() {
  # shellcheck disable=SC2094 # LOG_JSONL is recorded as a path, not read while appending.
  jq -cn \
    --arg record_type "tlon_connector_verification_summary" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${git_revision}" \
    --arg connector_id "fcp.tlon" \
    --arg outcome "${OVERALL_STATUS}" \
    --arg jsonl "${LOG_JSONL}" \
    '{
      record_type: $record_type,
      command_line: $command_line,
      git_revision: $git_revision,
      connector_id: $connector_id,
      outcome: $outcome,
      local_non_mock: "connectors/tlon/tests/local_non_mock.rs",
      artifacts: { jsonl: $jsonl },
      cleanup_result: "logs_closed"
    }' >>"${LOG_JSONL}"
}

require_cmd jq
require_cmd "${RCH_BIN}"

run_logged \
  cargo_check \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo check -p fcp-tlon --locked --all-targets

run_logged \
  format_check \
  "${TARGET_DIR}" \
  env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo fmt -p fcp-tlon -- --check

run_logged \
  local_non_mock \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    FCP_TEST_COMMAND_LINE="${COMMAND_LINE}" \
    FCP_TEST_GIT_REVISION="${git_revision}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo test -j 2 -p fcp-tlon --locked --test local_non_mock -- --nocapture

run_logged \
  connector_tests \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    FCP_TEST_COMMAND_LINE="${COMMAND_LINE}" \
    FCP_TEST_GIT_REVISION="${git_revision}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo test -j 2 -p fcp-tlon --locked --tests -- --nocapture

run_logged \
  clippy \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo clippy -j 2 -p fcp-tlon --locked --all-targets -- -D warnings

redaction_scan
emit_summary

echo "TLON_CONNECTOR_VERIFICATION_JSONL=${LOG_JSONL}"
exit "${EXIT_CODE}"
