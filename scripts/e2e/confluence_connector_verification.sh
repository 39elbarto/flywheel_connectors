#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/confluence_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/confluence_connector/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/confluence_connector_verification.jsonl}"
RCH_BIN="${RCH_BIN:-rch}"
RCH_REQUIRE_REMOTE="${RCH_REQUIRE_REMOTE:-1}"
RCH_VISIBILITY="${RCH_VISIBILITY:-verbose}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/rch-fcp-confluence-${RUN_ID}-target}"

export RCH_REQUIRE_REMOTE
export RCH_FORCE_REMOTE=1
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

git_revision() {
  git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown
}

hash_text() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

target_dir_class() {
  case "${TARGET_DIR}" in
    /tmp|/tmp/*|/private/tmp|/private/tmp/*)
      printf 'ephemeral_tmp'
      ;;
    target|target/*)
      printf 'repo_relative_target'
      ;;
    *)
      printf 'custom_hashed'
      ;;
  esac
}

artifact_ref() {
  local path="$1"
  case "${path}" in
    "${OUT_ROOT}"/*)
      printf '%s\n' "${path#"${OUT_ROOT}/"}"
      ;;
    *)
      printf 'sha256:%s\n' "$(hash_text "${path}")"
      ;;
  esac
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

failure_class_for_log() {
  local log_path="$1"
  if grep -aE 'RCH-E|remote required; refusing local fallback|refus(ed|ing) local fallback|\[RCH\] local|no admissible workers|no worker assigned|no workers passed|all workers failed preflight|failed to execute process|timeout: failed to execute process|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|No space left on device|missing worker system package|failed to load manifest for dependency .tru.|failed to read .*/toon_rust/Cargo.toml' "${log_path}" >/dev/null; then
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

emit_step() {
  local step="$1"
  local status="$2"
  local log_path="$3"
  local command="$4"
  local summary worker_class
  summary="$(rch_summary_line "${log_path}")"
  worker_class="$(worker_execution_class_for_log "${log_path}")"

  jq -cn \
    --arg record_type "confluence_connector_verification_step" \
    --arg script "${SCRIPT_PATH}" \
    --arg run_id "${RUN_ID}" \
    --arg connector_id "fcp.confluence" \
    --arg git_revision "$(git_revision)" \
    --arg step "${step}" \
    --arg status "${status}" \
    --arg command "${command}" \
    --arg log_artifact "$(artifact_ref "${log_path}")" \
    --arg target_dir_class "$(target_dir_class)" \
    --arg target_dir_hash "sha256:$(hash_text "${TARGET_DIR}")" \
    --arg worker_execution_class "${worker_class}" \
    --argjson rch_summary "$(json_string_or_null "${summary}")" \
    '{
      record_type: $record_type,
      script: $script,
      run_id: $run_id,
      connector_id: $connector_id,
      git_revision: $git_revision,
      step: $step,
      status: $status,
      command: $command,
      log_artifact: $log_artifact,
      cargo_target_dir_class: $target_dir_class,
      cargo_target_dir_hash: $target_dir_hash,
      worker_execution_class: $worker_execution_class,
      required_worker_execution_class: "remote",
      rch_summary: $rch_summary,
      redaction: {
        basic_auth_logged: false,
        email_logged: false,
        api_token_logged: false,
        page_body_logged: false,
        provider_body_logged: false
      }
    }' >>"${LOG_JSONL}"
}

run_logged() {
  local step="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${step}.log"
  local command_text="$*"
  local status="passed"

  echo "[confluence-verification] ${step}: ${command_text}"
  if (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${log_path}" 2>&1; then
    if [[ "$(worker_execution_class_for_log "${log_path}")" != "remote" ]]; then
      printf '%s\n' "rch command did not produce accepted remote proof" >>"${log_path}"
      status="infra_blocked"
    fi
  else
    status="$(failure_class_for_log "${log_path}")"
  fi

  emit_step "${step}" "${status}" "${log_path}" "${command_text}"
  promote_status "${status}"
}

redaction_scan() {
  local scan_log="${OUT_ROOT}/logs/redaction_scan.log"
  local status="passed"
  local haystacks=(
    "${LOG_JSONL}"
    "${OUT_ROOT}/logs/cargo_check.log"
    "${OUT_ROOT}/logs/format_check.log"
    "${OUT_ROOT}/logs/local_non_mock.log"
    "${OUT_ROOT}/logs/connector_tests.log"
    "${OUT_ROOT}/logs/clippy.log"
  )
  local forbidden=(
    "local@example.com"
    "local-confluence-api-token"
    "CONFLUENCE_BODY_SHOULD_NOT_APPEAR_IN_EVIDENCE"
    "provider body should stay out of evidence"
    "Operational runbook"
    "page-created"
    "page-parent"
    "Authorization: Basic"
    "authorization: Basic"
  )

  : >"${scan_log}"
  for needle in "${forbidden[@]}"; do
    if grep -aH -F -- "${needle}" "${haystacks[@]}" >>"${scan_log}" 2>&1; then
      status="failed"
      break
    fi
  done

  emit_step "redaction_scan" "${status}" "${scan_log}" "grep forbidden Confluence fixture material"
  promote_status "${status}"
}

emit_summary() {
  local jsonl_ref
  jsonl_ref="$(artifact_ref "${LOG_JSONL}")"

  jq -cn \
    --arg record_type "confluence_connector_verification_summary" \
    --arg script "${SCRIPT_PATH}" \
    --arg run_id "${RUN_ID}" \
    --arg connector_id "fcp.confluence" \
    --arg git_revision "$(git_revision)" \
    --arg status "${OVERALL_STATUS}" \
    --arg jsonl "${jsonl_ref}" \
    '{
      record_type: $record_type,
      script: $script,
      run_id: $run_id,
      connector_id: $connector_id,
      git_revision: $git_revision,
      status: $status,
      local_non_mock: "connectors/confluence/tests/local_non_mock.rs",
      live_verification: "connectors/confluence/tests/live_verification.rs",
      fixture_mode: "loopback HTTP Confluence fixtures plus sandbox-gated read-only live suite",
      artifacts: { jsonl: $jsonl },
      cleanup_result: "logs_closed"
    }' >>"${LOG_JSONL}"
}

require_cmd jq
require_cmd shasum
require_cmd "${RCH_BIN}"

run_logged \
  cargo_check \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo check -p fcp-confluence --locked --all-targets

run_logged \
  format_check \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo fmt -p fcp-confluence -- --check

run_logged \
  local_non_mock \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo test -j 2 -p fcp-confluence --locked --test local_non_mock -- --nocapture

run_logged \
  connector_tests \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo test -j 2 -p fcp-confluence --locked --tests -- --nocapture

run_logged \
  clippy \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo clippy -j 2 -p fcp-confluence --locked --all-targets -- -D warnings

redaction_scan
emit_summary

echo "CONFLUENCE_CONNECTOR_VERIFICATION_JSONL=${LOG_JSONL}"
exit "${EXIT_CODE}"
