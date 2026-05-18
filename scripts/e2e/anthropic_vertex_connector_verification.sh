#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/anthropic_vertex_connector_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/anthropic_vertex/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/anthropic_vertex_connector_verification.jsonl}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"
RCH_BIN="${RCH_BIN:-rch}"
REMOTE_TARGET_BASE="${REMOTE_TARGET_BASE:-/tmp/rch-fcp-anthropic-vertex-${RUN_ID}}"
TARGET_DIR="${CARGO_TARGET_DIR:-${REMOTE_TARGET_BASE}-target}"

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

  jq -cn \
    --arg record_type "anthropic_vertex_connector_verification_step" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${git_revision}" \
    --arg connector_id "fcp.anthropic-vertex" \
    --arg suite_class "local_non_mock" \
    --arg scenario "${scenario}" \
    --arg outcome "${outcome}" \
    --arg log_path "${log_path}" \
    --arg cargo_target_dir "${cargo_target_dir}" \
    --arg command "${command}" \
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
      redaction: {
        access_token_logged: false,
        quota_project_logged: false,
        prompt_logged: false,
        completion_logged: false,
        provider_body_logged: false
      }
    }' >>"${LOG_JSONL}"
}

promote_failure() {
  OVERALL_STATUS="failed"
  EXIT_CODE=1
}

run_logged() {
  local name="$1"
  local cargo_target_dir="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local command_text="$*"

  echo "[anthropic-vertex-verification] ${name}: ${command_text}"
  if (
    cd "${REPO_ROOT}"
    "$@"
  ) >"${log_path}" 2>&1; then
    emit_step "${name}" "passed" "${log_path}" "${cargo_target_dir}" "${command_text}"
  else
    emit_step "${name}" "failed" "${log_path}" "${cargo_target_dir}" "${command_text}"
    promote_failure
  fi
}

redaction_scan() {
  local scan_log="${OUT_ROOT}/logs/redaction_scan.log"
  local forbidden=(
    "vertex-local-access-token"
    "billing-local-project"
    "local prompt text"
    "local response text"
    "local stream text"
    "provider local body secret"
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
  jq -cn \
    --arg record_type "anthropic_vertex_connector_verification_summary" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${git_revision}" \
    --arg connector_id "fcp.anthropic-vertex" \
    --arg outcome "${OVERALL_STATUS}" \
    --arg jsonl "${LOG_JSONL}" \
    '{
      record_type: $record_type,
      command_line: $command_line,
      git_revision: $git_revision,
      connector_id: $connector_id,
      outcome: $outcome,
      local_non_mock: "connectors/anthropic-vertex/tests/local_non_mock.rs",
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
    cargo check -p fcp-anthropic-vertex --locked --all-targets

run_logged \
  format_check \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo fmt -p fcp-anthropic-vertex -- --check

run_logged \
  local_non_mock \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    FCP_TEST_COMMAND_LINE="${COMMAND_LINE}" \
    FCP_TEST_GIT_REVISION="${git_revision}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo test -j 2 -p fcp-anthropic-vertex --locked --test local_non_mock -- --nocapture

run_logged \
  connector_tests \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    FCP_TEST_COMMAND_LINE="${COMMAND_LINE}" \
    FCP_TEST_GIT_REVISION="${git_revision}" \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo test -j 2 -p fcp-anthropic-vertex --locked --tests -- --nocapture

run_logged \
  clippy \
  "${TARGET_DIR}" \
  "${RCH_BIN}" exec -- env \
    CARGO_TARGET_DIR="${TARGET_DIR}" \
    CARGO_INCREMENTAL=0 \
    CARGO_BUILD_JOBS=2 \
    cargo clippy -j 2 -p fcp-anthropic-vertex --locked --all-targets -- -D warnings

redaction_scan
emit_summary

echo "ANTHROPIC_VERTEX_CONNECTOR_VERIFICATION_JSONL=${LOG_JSONL}"
exit "${EXIT_CODE}"
