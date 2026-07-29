#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/glm/${RUN_ID}}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
TARGET_PREFIX="${CARGO_TARGET_PREFIX:-/tmp/fcp-glm-${RUN_ID}}"
BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
LAST_STEP_STATUS="not_run"

manifest_status="pending"
cargo_check_status="pending"
format_check_status="pending"
conformance_status="pending"
integration_status="pending"
local_non_mock_status="pending"
local_non_mock_jsonl_status="pending"
clippy_status="pending"

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

classify_failure() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    echo "infra_blocked"
    return
  fi

  if grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|missing worker|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|all workers failed preflight' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

observed_runner() {
  local log_path="$1"

  if [[ ! -f "${log_path}" ]]; then
    echo "unknown"
  elif grep -Fq "[RCH] remote" "${log_path}"; then
    echo "rch_remote"
  elif grep -Fq "[RCH] local" "${log_path}"; then
    echo "rch_local_fallback"
  else
    echo "rch_unclassified"
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[glm-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[glm-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
  rc="$?"
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

git_revision="$(git -c "safe.directory=${REPO_ROOT}" -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

require_cmd jq
require_cmd "${RCH_BIN}"

manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"
if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-fwc" cargo run -q -p fwc -- manifest fix connectors/glm/manifest.toml --check --json
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
else
  manifest_status="$(classify_failure "${OUT_ROOT}/logs/manifest_check.log")"
  promote_overall_status "${manifest_status}"
  jq -n \
    --arg status "${manifest_status}" \
    --arg command_output "${manifest_stdout_path}" \
    --arg log "${OUT_ROOT}/logs/manifest_check.log" \
    '{status:$status,command_output:$command_output,log:$log}' \
    >"${OUT_ROOT}/evidence/manifest_check.json"
fi

run_step cargo_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-check" cargo check -p fcp-glm --all-targets
cargo_check_status="${LAST_STEP_STATUS}"

run_step format_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-fmt" cargo fmt -p fcp-glm -- --check
format_check_status="${LAST_STEP_STATUS}"

run_step conformance env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-conformance" cargo test -p fcp-glm --test conformance -- --nocapture
conformance_status="${LAST_STEP_STATUS}"

run_step integration env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-integration" cargo test -p fcp-glm --test integration -- --nocapture
integration_status="${LAST_STEP_STATUS}"

run_step local_non_mock env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-local" GIT_REVISION="${git_revision}" cargo test -p fcp-glm --test local_non_mock -- --nocapture
local_non_mock_status="${LAST_STEP_STATUS}"

if grep -a '"suite_class":"local_non_mock"' "${OUT_ROOT}/logs/local_non_mock.log" >"${OUT_ROOT}/evidence/local_non_mock.jsonl"; then
  if jq -s -e '
    length >= 3
    and all(.[]; .connector == "glm")
    and all(.[]; .package == "fcp-glm")
    and all(.[]; .suite_class == "local_non_mock")
    and all(.[]; .bead == "flywheel_connectors-bky21.3.6.28")
    and all(.[]; .cleanup != null)
    and any(.[]; .operation == "glm.chat.completions" and .fixture == "raw_tcp_listener" and .egress == "loopback_only" and .auth == "bearer_observed_redacted" and .request_path == "/api/paas/v4/chat/completions")
    and any(.[]; .operation == "glm.embeddings.create" and .fixture == "raw_tcp_listener" and .egress == "loopback_only" and .auth == "bearer_observed_redacted" and .request_path == "/api/paas/v4/embeddings")
    and any(.[]; .operation == "glm.chat.completions" and .fixture == "raw_tcp_listener_nonblocking" and .egress == "none" and .authz == "wrong_capability_denied_before_socket_accept")
  ' "${OUT_ROOT}/evidence/local_non_mock.jsonl" >/dev/null; then
    local_non_mock_jsonl_status="passed"
  else
    local_non_mock_jsonl_status="failed"
    if [[ "${local_non_mock_status}" == "passed" ]]; then
      promote_overall_status failed
    fi
  fi
else
  local_non_mock_jsonl_status="${local_non_mock_status}"
  cat >"${OUT_ROOT}/evidence/local_non_mock.jsonl" <<EOF
{"event":"glm_local_non_mock_missing_jsonl","status":"${local_non_mock_jsonl_status}","reason":"local_non_mock test emitted no extractable local_non_mock JSONL records","git_revision":"${git_revision}","fixture_mode":"raw_tcp_loopback_http","log":"${OUT_ROOT}/logs/local_non_mock.log"}
EOF
  if [[ "${local_non_mock_status}" == "passed" ]]; then
    local_non_mock_jsonl_status="failed"
    promote_overall_status failed
  fi
fi

if grep -qE 'local_glm_api_key|hello loopback GLM|loopback GLM response|embedding fixture text|must not egress|127\.0\.0\.1:[0-9]+' "${OUT_ROOT}/evidence/local_non_mock.jsonl"; then
  local_non_mock_jsonl_status="failed"
  promote_overall_status failed
fi

run_step clippy env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="${BUILD_JOBS}" CARGO_TARGET_DIR="${TARGET_PREFIX}-clippy" cargo clippy -p fcp-glm --all-targets -- -D warnings
clippy_status="${LAST_STEP_STATUS}"

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-glm",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/glm_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "git_revision": "${git_revision}",
  "target_prefix": "${TARGET_PREFIX}",
  "build_jobs": "${BUILD_JOBS}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "runner": "rch",
  "fixture_mode": "raw_tcp_loopback_http",
  "redaction": "no GLM API key, loopback endpoint, prompt text, completion text, embedding input, or provider response body is emitted in extracted evidence"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

RCH_BIN="\${RCH_BIN:-${RCH_BIN}}"
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
TARGET_PREFIX="\${CARGO_TARGET_PREFIX:-${TARGET_PREFIX}}"
BUILD_JOBS="\${CARGO_BUILD_JOBS:-${BUILD_JOBS}}"
git_revision="\$(git -c "safe.directory=${REPO_ROOT}" -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-fwc" cargo run -q -p fwc -- manifest fix connectors/glm/manifest.toml --check --json
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-check" cargo check -p fcp-glm --all-targets
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-fmt" cargo fmt -p fcp-glm -- --check
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-conformance" cargo test -p fcp-glm --test conformance -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-integration" cargo test -p fcp-glm --test integration -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-local" GIT_REVISION="\${git_revision}" cargo test -p fcp-glm --test local_non_mock -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS="\${BUILD_JOBS}" CARGO_TARGET_DIR="\${TARGET_PREFIX}-clippy" cargo clippy -p fcp-glm --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-glm",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "rch",
  "observed_runners": {
    "manifest_check": "$(observed_runner "${OUT_ROOT}/logs/manifest_check.log")",
    "cargo_check": "$(observed_runner "${OUT_ROOT}/logs/cargo_check.log")",
    "format_check": "$(observed_runner "${OUT_ROOT}/logs/format_check.log")",
    "conformance": "$(observed_runner "${OUT_ROOT}/logs/conformance.log")",
    "integration": "$(observed_runner "${OUT_ROOT}/logs/integration.log")",
    "local_non_mock": "$(observed_runner "${OUT_ROOT}/logs/local_non_mock.log")",
    "clippy": "$(observed_runner "${OUT_ROOT}/logs/clippy.log")"
  },
  "steps": {
    "manifest_check": "${manifest_status}",
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "conformance": "${conformance_status}",
    "integration": "${integration_status}",
    "local_non_mock": "${local_non_mock_status}",
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "conformance_log": "${OUT_ROOT}/logs/conformance.log",
    "integration_log": "${OUT_ROOT}/logs/integration.log",
    "local_non_mock_log": "${OUT_ROOT}/logs/local_non_mock.log",
    "local_non_mock_jsonl": "${OUT_ROOT}/evidence/local_non_mock.jsonl",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  },
  "redaction_checks": {
    "local_non_mock_jsonl": "${local_non_mock_jsonl_status}"
  }
}
EOF

jq -c '.steps' "${OUT_ROOT}/summary.json"
echo "GLM verification artifacts written to ${OUT_ROOT}"
echo "GLM_E2E_JSONL=${OUT_ROOT}/evidence/local_non_mock.jsonl"
exit "${EXIT_CODE}"
