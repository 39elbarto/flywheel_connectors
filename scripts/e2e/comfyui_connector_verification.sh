#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/comfyui/${RUN_ID}}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_TARGET_BASE="/tmp/rch-fcp-comfyui-${RUN_ID}"
TARGET_DIR="${FCP_COMFYUI_TARGET_DIR:-${REMOTE_TARGET_BASE}-target}"
RCH_BIN="${RCH_BIN:-rch}"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"

promote_overall_status() {
  local next_status="$1"
  case "${next_status}" in
    failed)
      OVERALL_STATUS="failed"
      EXIT_CODE=1
      ;;
    infra_blocked)
      if [[ "${OVERALL_STATUS}" == "ok" ]]; then
        OVERALL_STATUS="infra_blocked"
        EXIT_CODE=2
      fi
      ;;
  esac
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

log_has_remote_proof_failure() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    if [[ "${line}" == *"rch command did not produce remote proof"* ]]; then
      return 0
    fi
  done < "${log_path}"
  return 1
}

log_has_infra_blocker() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    case "${line}" in
      *"timeout: failed to execute process"*|*"RCH-E"*|*"remote required; refusing local fallback"*|*"rch command did not produce remote proof"*|*"missing worker"*|*"No space left on device"*|*"dbus-1.pc"*|*"connection reset by peer"*|*"Backend unavailable"*|*"unable to update registry"*|*"spurious network error"*|*"failed to get successful HTTP response"*)
        return 0
        ;;
    esac
  done < "${log_path}"
  return 1
}

classify_failure() {
  local log_path="$1"
  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
  elif log_has_infra_blocker "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

command_uses_rch_exec() {
  local previous=""
  for arg in "$@"; do
    if [[ "${previous}" == "${RCH_BIN}" && "${arg}" == "exec" ]]; then
      return 0
    fi
    if [[ "${previous}" == "rch" && "${arg}" == "exec" ]]; then
      return 0
    fi
    previous="${arg}"
  done
  return 1
}

rch_remote_summary_present() {
  local log_path="$1"
  local line
  while IFS= read -r line; do
    if [[ "${line}" == *"[RCH] remote"* ]]; then
      return 0
    fi
  done < "${log_path}"
  return 1
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"
  shift 2

  if command_uses_rch_exec "$@" && ! rch_remote_summary_present "${log_path}"; then
    echo "[comfyui-verification] ${name}: rch command did not produce remote proof" >&2
    echo "rch command did not produce remote proof" >>"${log_path}"
    return 1
  fi
  return 0
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[comfyui-verification] ${name}: $*" >&2
  previous_pwd="$(pwd)"
  cd "${REPO_ROOT}" || return
  "$@" >"${log_path}" 2>&1
  rc="$?"
  cd "${previous_pwd}" || return
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}" "$@"; then
    return 1
  fi
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[comfyui-verification] ${name}: $*" >&2
  previous_pwd="$(pwd)"
  cd "${REPO_ROOT}" || return
  "$@" >"${stdout_path}" 2>"${log_path}"
  rc="$?"
  cd "${previous_pwd}" || return
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}" "$@"; then
    return 1
  fi
  return "${rc}"
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    echo "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

require_cmd jq
require_cmd "${RCH_BIN}"

manifest_check_runner=""
manifest_check_runner="rch:cargo-run"
if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/comfyui/manifest.toml --check --json
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
else
  manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
  promote_overall_status "${manifest_status}"
  manifest_note="manifest validation command failed; inspect logs/manifest_check.log"
  if [[ "${manifest_status}" == "infra_blocked" ]]; then
    if log_has_remote_proof_failure "${OUT_ROOT}/logs/manifest_check.log"; then
      manifest_note="rch command did not produce remote proof for fallback manifest validation"
    else
      manifest_note="infrastructure blocked manifest validation; inspect logs/manifest_check.log"
    fi
  fi
  jq -n \
    --arg status "${manifest_status}" \
    --arg note "${manifest_note}" \
    --arg runner "${manifest_check_runner}" \
    --arg command_output "${manifest_stdout_path}" \
    --arg log "${OUT_ROOT}/logs/manifest_check.log" \
    '{status:$status,note:$note,runner:$runner,command_output:$command_output,log:$log}' \
    >"${OUT_ROOT}/evidence/manifest_check.json"
fi

cargo_check_status="$(run_step cargo_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-comfyui --all-targets)"
format_check_status="$(run_step format_check env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" cargo fmt --package fcp-comfyui --check)"
loopback_status="$(run_step loopback_jsonl env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" COMFYUI_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-comfyui --test integration comfyui_loopback_e2e_jsonl_matrix -- --nocapture)"
live_status="$(run_step live_jsonl env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" COMFYUI_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-comfyui --test live_verification comfyui_live_health_or_structured_skip_jsonl -- --nocapture)"
clippy_status="$(run_step clippy env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-comfyui --all-targets --no-deps -- -D warnings)"

fixture_jsonl_status="${loopback_status}"
if grep -a '^COMFYUI_E2E_JSONL ' "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed 's/^COMFYUI_E2E_JSONL //' \
  | grep -a '"fixture_mode":"wiremock"' >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" ]]; then
    if [[ "${loopback_status}" == "passed" ]]; then
      fixture_jsonl_status="passed"
    else
      fixture_jsonl_status="${loopback_status}"
    fi
  fi
fi

live_jsonl_status="${live_status}"
if grep -a '^COMFYUI_E2E_JSONL ' "${OUT_ROOT}/logs/live_jsonl.log" \
  | sed 's/^COMFYUI_E2E_JSONL //' \
  | grep -a '"fixture_mode":"live"' >"${OUT_ROOT}/evidence/live_health.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/live_health.jsonl" ]]; then
    if [[ "${live_status}" == "passed" ]]; then
      live_jsonl_status="passed"
    else
      live_jsonl_status="${live_status}"
    fi
  fi
fi

redaction_status="passed"
if [[ "${fixture_jsonl_status}" != "passed" || "${live_jsonl_status}" != "passed" ]]; then
  if [[ "${OVERALL_STATUS}" == "ok" ]]; then
    redaction_status="failed"
    promote_overall_status failed
  else
    redaction_status="${OVERALL_STATUS}"
  fi
fi
if grep -E 'comfy-secret|COMFYUI_AUTHORIZATION_HEADER|private prompt|workflow":|output.png' \
  "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" "${OUT_ROOT}/evidence/live_health.jsonl" >/dev/null 2>&1
then
  redaction_status="failed"
  promote_overall_status failed
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-comfyui" \
  --arg repo_root "${REPO_ROOT}" \
  --arg verification_script "scripts/e2e/comfyui_connector_verification.sh" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg git_revision "${git_revision}" \
  --arg target_dir "${TARGET_DIR}" \
  --arg manifest_check_runner "${manifest_check_runner}" \
  --arg rch_bin "${RCH_BIN}" \
  --arg toolchain "${REPO_TOOLCHAIN}" \
  --arg fixture_mode "wiremock" \
  --arg live_mode "COMFYUI_BASE_URL gated" \
  --arg redaction "JSONL carries base-url class, prompt id hash, workflow fixture id, operation, output count, HTTP status, retry decision, cleanup result, and skip reason; it never emits workflow JSON, prompt text, auth headers, full base URLs, or full artifact URLs" \
  '{
    run_id: $run_id,
    connector: $connector,
    repo_root: $repo_root,
    verification_script: $verification_script,
    artifact_root: $artifact_root,
    git_revision: $git_revision,
    target_dir: $target_dir,
    manifest_check_runner: $manifest_check_runner,
    rch_bin: $rch_bin,
    toolchain: $toolchain,
    fixture_mode: $fixture_mode,
    live_mode: $live_mode,
    redaction: $redaction
  }' >"${OUT_ROOT}/environment.json"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf '%s\n' ''
  printf '%s\n' "RUN_ID=\"\${RUN_ID:-\$(date -u +%Y%m%dT%H%M%SZ)}\""
  printf '%s\n' "REPO_TOOLCHAIN=\"\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}\""
  printf '%s\n' "TARGET_DIR=\"\${FCP_COMFYUI_TARGET_DIR:-/tmp/rch-fcp-comfyui-\${RUN_ID}-target}\""
  printf '%s\n' "RCH_BIN=\"\${RCH_BIN:-${RCH_BIN}}\""
  printf '%s\n' 'export RCH_FORCE_REMOTE=1'
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_TARGET_DIR=\"\${TARGET_DIR}\" cargo run -q -p fwc -- manifest fix connectors/comfyui/manifest.toml --check --json"
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_TARGET_DIR=\"\${TARGET_DIR}\" cargo check -p fcp-comfyui --all-targets"
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_TARGET_DIR=\"\${TARGET_DIR}\" cargo fmt --package fcp-comfyui --check"
  printf '%s\n' "git_revision=\"\$(git rev-parse --short HEAD 2>/dev/null || echo unknown)\""
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_TARGET_DIR=\"\${TARGET_DIR}\" COMFYUI_E2E_GIT_REVISION=\"\${git_revision}\" cargo test -p fcp-comfyui --test integration comfyui_loopback_e2e_jsonl_matrix -- --nocapture"
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_TARGET_DIR=\"\${TARGET_DIR}\" COMFYUI_E2E_GIT_REVISION=\"\${git_revision}\" cargo test -p fcp-comfyui --test live_verification comfyui_live_health_or_structured_skip_jsonl -- --nocapture"
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_TARGET_DIR=\"\${TARGET_DIR}\" cargo clippy -p fcp-comfyui --all-targets --no-deps -- -D warnings"
} >"${OUT_ROOT}/replay.sh"
chmod +x "${OUT_ROOT}/replay.sh"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-comfyui" \
  --arg overall_status "${OVERALL_STATUS}" \
  --arg artifacts_root "${OUT_ROOT}" \
  --arg manifest_check "${manifest_status}" \
  --arg cargo_check "${cargo_check_status}" \
  --arg format_check "${format_check_status}" \
  --arg loopback_jsonl "${loopback_status}" \
  --arg fixture_jsonl "${fixture_jsonl_status}" \
  --arg live_jsonl "${live_status}" \
  --arg live_jsonl_extract "${live_jsonl_status}" \
  --arg clippy "${clippy_status}" \
  --arg redaction "${redaction_status}" \
  --arg manifest_check_artifact "${OUT_ROOT}/evidence/manifest_check.json" \
  --arg cargo_check_log "${OUT_ROOT}/logs/cargo_check.log" \
  --arg format_check_log "${OUT_ROOT}/logs/format_check.log" \
  --arg loopback_log "${OUT_ROOT}/logs/loopback_jsonl.log" \
  --arg loopback_jsonl_artifact "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" \
  --arg live_log "${OUT_ROOT}/logs/live_jsonl.log" \
  --arg live_jsonl_artifact "${OUT_ROOT}/evidence/live_health.jsonl" \
  --arg clippy_log "${OUT_ROOT}/logs/clippy.log" \
  --arg environment "${OUT_ROOT}/environment.json" \
  --arg replay "${OUT_ROOT}/replay.sh" \
  '{
    run_id: $run_id,
    connector: $connector,
    overall_status: $overall_status,
    artifacts_root: $artifacts_root,
    steps: {
      manifest_check: $manifest_check,
      cargo_check: $cargo_check,
      format_check: $format_check,
      loopback_jsonl: $loopback_jsonl,
      fixture_jsonl: $fixture_jsonl,
      live_jsonl: $live_jsonl,
      live_jsonl_extract: $live_jsonl_extract,
      clippy: $clippy,
      redaction: $redaction
    },
    artifacts: {
      manifest_check: $manifest_check_artifact,
      cargo_check_log: $cargo_check_log,
      format_check_log: $format_check_log,
      loopback_log: $loopback_log,
      loopback_jsonl: $loopback_jsonl_artifact,
      live_log: $live_log,
      live_jsonl: $live_jsonl_artifact,
      clippy_log: $clippy_log,
      environment: $environment,
      replay: $replay
    }
  }' >"${OUT_ROOT}/summary.json"

echo "ComfyUI verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
