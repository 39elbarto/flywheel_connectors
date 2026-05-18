#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/huggingface/${RUN_ID}}"
TARGET_DIR="${FCP_HUGGINGFACE_TARGET_DIR:-/tmp/fcp-huggingface-e2e}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
LAST_STEP_STATUS="not_run"

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
loopback_status="pending"
fixture_jsonl_status="pending"
clippy_status="pending"
graduation_gauntlet_status="pending"
manifest_check_runner=""

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

classify_failure() {
  local log_path="$1"
  if grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|missing worker|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"

  if grep -Fq "[RCH] remote" "${log_path}"; then
    return 0
  fi

  echo "[huggingface-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

run_graduation_gauntlet() {
  local connector_path="connectors/huggingface"
  local jsonl_path="${OUT_ROOT}/evidence/graduation_gauntlet.jsonl"
  local log_path="${OUT_ROOT}/logs/graduation_gauntlet.log"
  local rc
  local status

  : >"${jsonl_path}"
  echo "[huggingface-verification] graduation_gauntlet: scripts/graduation/run_gauntlet.sh ${connector_path}" >&2
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

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[huggingface-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}"; then
    return 1
  fi
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[huggingface-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}"; then
    return 1
  fi
  return "${rc}"
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    LAST_STEP_STATUS="passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    LAST_STEP_STATUS="${status}"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

require_cmd rch
require_cmd jq

graduation_gauntlet_status="$(run_graduation_gauntlet)"

manifest_check_runner="${REMOTE_RUNNER}:cargo-run"
manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"
if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/huggingface/manifest.toml --check --json
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
else
  manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
  promote_overall_status "${manifest_status}"
  cat >"${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{"status":"${manifest_status}","command_output":"${manifest_stdout_path}","log":"${OUT_ROOT}/logs/manifest_check.log"}
EOF
fi

run_step cargo_check env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-huggingface --all-targets
cargo_check_status="${LAST_STEP_STATUS}"
run_step format_check env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt --package fcp-huggingface --check
format_check_status="${LAST_STEP_STATUS}"
run_step loopback_jsonl env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" HUGGINGFACE_E2E_GIT_REVISION="${git_revision}" cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture
loopback_status="${LAST_STEP_STATUS}"
run_step clippy env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-huggingface --all-targets --no-deps -- -D warnings
clippy_status="${LAST_STEP_STATUS}"

if grep -a '^HUGGINGFACE_E2E_JSONL ' "${OUT_ROOT}/logs/loopback_jsonl.log" \
  | sed 's/^HUGGINGFACE_E2E_JSONL //' >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl"
then
  if [[ -s "${OUT_ROOT}/evidence/loopback_fixtures.jsonl" ]]; then
    fixture_jsonl_status="passed"
  else
    fixture_jsonl_status="failed"
    cat >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl" <<EOF
{"event":"huggingface_fixture_missing_jsonl","status":"failed","reason":"loopback test emitted no HUGGINGFACE_E2E_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","log":"${OUT_ROOT}/logs/loopback_jsonl.log"}
EOF
    if [[ "${loopback_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  fixture_jsonl_status="${loopback_status}"
  cat >"${OUT_ROOT}/evidence/loopback_fixtures.jsonl" <<EOF
{"event":"huggingface_fixture_missing_jsonl","status":"${fixture_jsonl_status}","reason":"loopback test did not produce extractable HUGGINGFACE_E2E_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","log":"${OUT_ROOT}/logs/loopback_jsonl.log"}
EOF
  if [[ "${loopback_status}" == "passed" ]]; then
    fixture_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-huggingface",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/huggingface_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_dir": "${TARGET_DIR}",
  "manifest_check_runner": "${manifest_check_runner}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "fixture_mode": "wiremock",
  "redaction": "no bearer token, prompt text, generated text, or raw model ids are emitted; logs carry lengths and blake3 model id hashes"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="\${FCP_HUGGINGFACE_TARGET_DIR:-${TARGET_DIR}}"
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
export RCH_FORCE_REMOTE=1

env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/huggingface/manifest.toml --check --json
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo check -p fcp-huggingface --all-targets
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo fmt --package fcp-huggingface --check
git_revision="\$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" HUGGINGFACE_E2E_GIT_REVISION="\${git_revision}" cargo test -p fcp-huggingface --test provider_contract huggingface_loopback_e2e_jsonl_matrix -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo clippy -p fcp-huggingface --all-targets --no-deps -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-huggingface",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "steps": {
    "graduation_gauntlet": "${graduation_gauntlet_status}",
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "loopback_jsonl": "${loopback_status}",
    "fixture_jsonl": "${fixture_jsonl_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "graduation_gauntlet": "${OUT_ROOT}/evidence/graduation_gauntlet.jsonl",
    "graduation_gauntlet_log": "${OUT_ROOT}/logs/graduation_gauntlet.log",
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "loopback_log": "${OUT_ROOT}/logs/loopback_jsonl.log",
    "loopback_jsonl": "${OUT_ROOT}/evidence/loopback_fixtures.jsonl",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "HuggingFace verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
