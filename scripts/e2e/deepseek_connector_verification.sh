#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/deepseek/${RUN_ID}}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_PREFIX="${CARGO_TARGET_PREFIX:-/tmp/fcp-deepseek-${RUN_ID}}"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
integration_status="pending"
clippy_status="pending"
live_smoke_status="pending"
fixture_boundary_status="pending"
graduation_gauntlet_status="pending"
manifest_check_runner=""
manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

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
      *"timeout: failed to execute process"*|*"No such file or directory"*|*"RCH-E"*|*"remote required; refusing local fallback"*|*"rch command did not produce remote proof"*|*"missing worker"*|*"dbus-1.pc"*|*"No space left on device"*|*"connection reset by peer"*|*"Backend unavailable"*|*"unable to update registry"*|*"spurious network error"*|*"failed to get successful HTTP response"*)
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
    echo "[deepseek-verification] ${name}: rch command did not produce remote proof" >&2
    echo "rch command did not produce remote proof" >>"${log_path}"
    return 1
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[deepseek-verification] ${name}: $*" >&2
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

run_logged_source_state() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[deepseek-verification] ${name}: $*" >&2
  previous_pwd="$(pwd)"
  cd "${REPO_ROOT}" || return
  "$@" >"${log_path}" 2>&1
  rc="$?"
  cd "${previous_pwd}" || return
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local previous_pwd
  local rc

  echo "[deepseek-verification] ${name}: $*" >&2
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

run_source_state_step() {
  local name="$1"
  shift
  if run_logged_source_state "${name}" "$@"; then
    echo "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    echo "${status}"
  fi
}

run_graduation_gauntlet() {
  local connector_path="connectors/deepseek"
  local jsonl_path="${OUT_ROOT}/evidence/graduation_gauntlet.jsonl"
  local log_path="${OUT_ROOT}/logs/graduation_gauntlet.log"
  local rc
  local status

  : >"${jsonl_path}"
  echo "[deepseek-verification] graduation_gauntlet: scripts/graduation/run_gauntlet.sh ${connector_path}" >&2
  (
    cd "${REPO_ROOT}" || exit
    scripts/graduation/run_gauntlet.sh --jsonl "${jsonl_path}" "${connector_path}"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]]; then
    echo "passed"
    return
  fi
  if [[ "${rc}" -eq 8 && -s "${jsonl_path}" ]] && jq -s -e '
    map(select(.verdict == "fail")) as $failures
    | ($failures | length) == 1
    and $failures[0].check == "readme_status_match"
  ' "${jsonl_path}" >/dev/null; then
    echo "pre_promotion_pending"
    return
  fi

  status="$(classify_failure "${log_path}")"
  promote_overall_status "${status}"
  echo "${status}"
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

require_cmd jq
require_cmd "${RCH_BIN}"

graduation_gauntlet_status="$(run_graduation_gauntlet)"

manifest_check_runner="rch:cargo-run"
if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_PREFIX}-fwc" cargo run -q -p fwc -- manifest fix connectors/deepseek/manifest.toml --check --json
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

cargo_check_status="$(run_step cargo_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_PREFIX}-check" cargo check -p fcp-deepseek --all-targets)"
format_check_status="$(run_source_state_step format_check env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_PREFIX}-fmt" cargo fmt -p fcp-deepseek -- --check)"
integration_status="$(run_step integration_suite env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_PREFIX}-integration" cargo test -p fcp-deepseek --test integration -- --nocapture)"
clippy_status="$(run_step clippy env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_PREFIX}-clippy" cargo clippy -p fcp-deepseek --all-targets -- -D warnings)"

if grep -a '^DEEPSEEK_FIXTURE_JSONL ' "${OUT_ROOT}/logs/integration_suite.log" \
  | sed 's/^DEEPSEEK_FIXTURE_JSONL //' >"${OUT_ROOT}/evidence/fixture_boundary.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/fixture_boundary.jsonl" ]]; then
    if [[ "${integration_status}" == "passed" ]]; then
      fixture_boundary_status="passed"
    else
      fixture_boundary_status="${integration_status}"
    fi
  else
    fixture_boundary_status="failed"
    cat >"${OUT_ROOT}/evidence/fixture_boundary.jsonl" <<EOF
{"event":"deepseek_fixture_missing_jsonl","status":"failed","reason":"integration suite emitted no DEEPSEEK_FIXTURE_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","log":"${OUT_ROOT}/logs/integration_suite.log"}
EOF
    if [[ "${integration_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  fixture_boundary_status="${integration_status}"
  cat >"${OUT_ROOT}/evidence/fixture_boundary.jsonl" <<EOF
{"event":"deepseek_fixture_missing_jsonl","status":"${fixture_boundary_status}","reason":"integration suite did not produce extractable DEEPSEEK_FIXTURE_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","log":"${OUT_ROOT}/logs/integration_suite.log"}
EOF
  if [[ "${integration_status}" == "passed" ]]; then
    fixture_boundary_status="failed"
    promote_overall_status failed
  fi
fi

if [[ "${DEEPSEEK_E2E:-}" == "1" ]]; then
  live_smoke_status="$(run_step live_smoke env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="${TARGET_PREFIX}-live" cargo test -p fcp-deepseek --test live_verification -- --nocapture)"
  if grep -a '^DEEPSEEK_E2E_JSONL ' "${OUT_ROOT}/logs/live_smoke.log" \
    | sed 's/^DEEPSEEK_E2E_JSONL //' >"${OUT_ROOT}/evidence/live_smoke.jsonl"
  then
    if grep -q '"status":"skipped"' "${OUT_ROOT}/evidence/live_smoke.jsonl"; then
      live_smoke_status="skipped"
    fi
  else
    cat >"${OUT_ROOT}/evidence/live_smoke.jsonl" <<EOF
{"event":"deepseek_live_smoke_missing_jsonl","status":"${live_smoke_status}","reason":"live verification command did not emit DEEPSEEK_E2E_JSONL records","git_revision":"${git_revision}","fixture_mode":"live","log":"${OUT_ROOT}/logs/live_smoke.log"}
EOF
    if [[ "${live_smoke_status}" == "passed" ]]; then
      live_smoke_status="failed"
      promote_overall_status failed
    fi
  fi
else
  live_smoke_status="skipped"
  cat >"${OUT_ROOT}/evidence/live_smoke.jsonl" <<EOF
{"event":"deepseek_live_smoke_skipped","status":"skipped","skip_reason":"DEEPSEEK_E2E is not set to 1","git_revision":"${git_revision}","fixture_mode":"wiremock","models":["deepseek-v4-flash","deepseek-v4-pro"],"redaction":"no prompts, completions, reasoning_content, or bearer tokens are emitted; logs carry lengths only"}
EOF
fi

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-deepseek" \
  --arg repo_root "${REPO_ROOT}" \
  --arg verification_script "scripts/e2e/deepseek_connector_verification.sh" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg git_revision "${git_revision}" \
  --arg manifest_check_runner "${manifest_check_runner}" \
  --arg toolchain "${REPO_TOOLCHAIN}" \
  --arg e2e_enabled "$([[ "${DEEPSEEK_E2E:-}" == "1" ]] && echo true || echo false)" \
  '{
    run_id: $run_id,
    connector: $connector,
    repo_root: $repo_root,
    verification_script: $verification_script,
    artifact_root: $artifact_root,
    git_revision: $git_revision,
    manifest_check_runner: $manifest_check_runner,
    toolchain: $toolchain,
    deepseek_e2e_enabled: ($e2e_enabled == "true")
  }' >"${OUT_ROOT}/environment.json"

{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf '%s\n' ''
  printf '%s\n' "RUN_ID=\"\${RUN_ID:-\$(date -u +%Y%m%dT%H%M%SZ)}\""
  printf '%s\n' "REPO_TOOLCHAIN=\"\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}\""
  printf '%s\n' "RCH_BIN=\"\${RCH_BIN:-${RCH_BIN}}\""
  printf '%s\n' "DEEPSEEK_TARGET_PREFIX=\"\${DEEPSEEK_TARGET_PREFIX:-/tmp/fcp-deepseek-replay-\${RUN_ID}}\""
  printf '%s\n' 'export RCH_FORCE_REMOTE=1'
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\"\${DEEPSEEK_TARGET_PREFIX}-fwc\" cargo run -q -p fwc -- manifest fix connectors/deepseek/manifest.toml --check --json"
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\"\${DEEPSEEK_TARGET_PREFIX}-check\" cargo check -p fcp-deepseek --all-targets"
  printf '%s\n' "env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\"\${DEEPSEEK_TARGET_PREFIX}-fmt\" cargo fmt -p fcp-deepseek -- --check"
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\"\${DEEPSEEK_TARGET_PREFIX}-integration\" cargo test -p fcp-deepseek --test integration -- --nocapture"
  printf '%s\n' "env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\"\${DEEPSEEK_TARGET_PREFIX}-clippy\" cargo clippy -p fcp-deepseek --all-targets -- -D warnings"
  printf '%s\n' "if [[ \"\${DEEPSEEK_E2E:-}\" == \"1\" ]]; then"
  printf '%s\n' "  env RCH_VISIBILITY=verbose \"\${RCH_BIN}\" exec -- env \"RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}\" CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=\"\${DEEPSEEK_TARGET_PREFIX}-live\" cargo test -p fcp-deepseek --test live_verification -- --nocapture"
  printf '%s\n' 'fi'
} >"${OUT_ROOT}/replay.sh"
chmod +x "${OUT_ROOT}/replay.sh"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-deepseek" \
  --arg overall_status "${OVERALL_STATUS}" \
  --arg artifacts_root "${OUT_ROOT}" \
  --arg graduation_gauntlet "${graduation_gauntlet_status}" \
  --arg manifest_check "${manifest_status}" \
  --arg cargo_check "${cargo_check_status}" \
  --arg format_check "${format_check_status}" \
  --arg integration_suite "${integration_status}" \
  --arg fixture_boundary "${fixture_boundary_status}" \
  --arg clippy "${clippy_status}" \
  --arg live_smoke "${live_smoke_status}" \
  --arg manifest_check_artifact "${OUT_ROOT}/evidence/manifest_check.json" \
  --arg cargo_check_log "${OUT_ROOT}/logs/cargo_check.log" \
  --arg format_check_log "${OUT_ROOT}/logs/format_check.log" \
  --arg integration_suite_log "${OUT_ROOT}/logs/integration_suite.log" \
  --arg fixture_boundary_jsonl "${OUT_ROOT}/evidence/fixture_boundary.jsonl" \
  --arg clippy_log "${OUT_ROOT}/logs/clippy.log" \
  --arg live_smoke_jsonl "${OUT_ROOT}/evidence/live_smoke.jsonl" \
  --arg environment "${OUT_ROOT}/environment.json" \
  --arg replay "${OUT_ROOT}/replay.sh" \
  '{
    run_id: $run_id,
    connector: $connector,
    overall_status: $overall_status,
    artifacts_root: $artifacts_root,
    steps: {
      graduation_gauntlet: $graduation_gauntlet,
      manifest_check: $manifest_check,
      cargo_check: $cargo_check,
      format_check: $format_check,
      integration_suite: $integration_suite,
      fixture_boundary: $fixture_boundary,
      clippy: $clippy,
      live_smoke: $live_smoke
    },
    artifacts: {
      graduation_gauntlet: ($artifacts_root + "/evidence/graduation_gauntlet.jsonl"),
      graduation_gauntlet_log: ($artifacts_root + "/logs/graduation_gauntlet.log"),
      manifest_check: $manifest_check_artifact,
      cargo_check_log: $cargo_check_log,
      format_check_log: $format_check_log,
      integration_suite_log: $integration_suite_log,
      fixture_boundary_jsonl: $fixture_boundary_jsonl,
      clippy_log: $clippy_log,
      live_smoke_jsonl: $live_smoke_jsonl,
      environment: $environment,
      replay: $replay
    }
  }' >"${OUT_ROOT}/summary.json"

echo "DeepSeek verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
