#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/mysql_connector/${RUN_ID}}"
TARGET_DIR="${FCP_MYSQL_TARGET_DIR:-/tmp/fcp-mysql-e2e}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[mysql-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! rch_remote_summary_present "${log_path}"; then
    echo "[mysql-verification] ${name}: rch command did not produce remote proof" >&2
    echo "rch command did not produce remote proof" >>"${log_path}"
    return 2
  fi
  return "${rc}"
}

run_capture_stdout() {
  local name="$1"
  local stdout_path="$2"
  shift 2
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[mysql-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! rch_remote_summary_present "${log_path}"; then
    echo "[mysql-verification] ${name}: rch command did not produce remote proof" >&2
    echo "rch command did not produce remote proof" >>"${log_path}"
    return 2
  fi
  return "${rc}"
}

require_cmd jq
require_cmd "${RCH_BIN}"

command_uses_rch_exec() {
  local previous=""
  for arg in "$@"; do
    if [[ "${previous}" == "rch" && "${arg}" == "exec" ]]; then
      return 0
    fi
    previous="${arg}"
  done
  return 1
}

rch_remote_summary_present() {
  local log_path="$1"
  local summary
  summary="$(grep -aE '\[RCH\][[:space:]]+(remote|local|failed)' "${log_path}" | tail -n 1 || true)"
  [[ "${summary}" =~ \[RCH\][[:space:]]+remote ]]
}

run_capture_stdout \
  manifest_check \
  "${OUT_ROOT}/evidence/manifest_check.json" \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/mysql/manifest.toml --check --json

run_logged \
  cargo_check \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-mysql --all-targets

run_logged \
  format_check \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt -p fcp-mysql -- --check

run_logged \
  doctor_evidence \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture

run_logged \
  self_check_secretless_evidence \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration self_check_secretless_requires_injection_and_evidence -- --nocapture

run_logged \
  compliance_evidence \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration introspection_emits_mutation_approval_evidence -- --nocapture

run_logged \
  integration_suite \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration -- --nocapture

run_logged \
  clippy \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-mysql --all-targets -- -D warnings

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-mysql" \
  --arg repo_root "${REPO_ROOT}" \
  --arg verification_script "scripts/e2e/mysql_connector_verification.sh" \
  --arg artifact_root "${OUT_ROOT}" \
  --arg target_dir "${TARGET_DIR}" \
  --arg rch_bin "${RCH_BIN}" \
  --arg runner "${REMOTE_RUNNER}" \
  --arg toolchain "${REPO_TOOLCHAIN}" \
  '{run_id:$run_id,connector:$connector,repo_root:$repo_root,verification_script:$verification_script,artifact_root:$artifact_root,target_dir:$target_dir,rch_bin:$rch_bin,runner:$runner,toolchain:$toolchain}' \
  > "${OUT_ROOT}/environment.json"

# shellcheck disable=SC2016
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' 'set -euo pipefail'
  printf '%s\n' ''
  printf '%s\n' 'TARGET_DIR="${FCP_MYSQL_TARGET_DIR:-/tmp/fcp-mysql-e2e}"'
  printf '%s\n' 'RCH_BIN="${RCH_BIN:-rch}"'
  printf '%s\n' 'REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"'
  printf '%s\n' 'export RCH_FORCE_REMOTE=1'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/mysql/manifest.toml --check --json'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-mysql --all-targets'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt -p fcp-mysql -- --check'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration self_check_secretless_requires_injection_and_evidence -- --nocapture'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration introspection_emits_mutation_approval_evidence -- --nocapture'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-mysql --test integration -- --nocapture'
  printf '%s\n' 'env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-mysql --all-targets -- -D warnings'
} > "${OUT_ROOT}/replay.sh"
chmod +x "${OUT_ROOT}/replay.sh"

jq -n \
  --arg run_id "${RUN_ID}" \
  --arg connector "fcp-mysql" \
  --arg artifacts_root "${OUT_ROOT}" \
  --arg manifest_check "${OUT_ROOT}/evidence/manifest_check.json" \
  --arg cargo_check_log "${OUT_ROOT}/logs/cargo_check.log" \
  --arg format_check_log "${OUT_ROOT}/logs/format_check.log" \
  --arg doctor_evidence_log "${OUT_ROOT}/logs/doctor_evidence.log" \
  --arg self_check_secretless_evidence_log "${OUT_ROOT}/logs/self_check_secretless_evidence.log" \
  --arg compliance_evidence_log "${OUT_ROOT}/logs/compliance_evidence.log" \
  --arg integration_suite_log "${OUT_ROOT}/logs/integration_suite.log" \
  --arg clippy_log "${OUT_ROOT}/logs/clippy.log" \
  --arg environment "${OUT_ROOT}/environment.json" \
  --arg replay "${OUT_ROOT}/replay.sh" \
  '{
    run_id:$run_id,
    connector:$connector,
    artifacts_root:$artifacts_root,
    artifacts:{
      manifest_check:$manifest_check,
      cargo_check_log:$cargo_check_log,
      format_check_log:$format_check_log,
      doctor_evidence_log:$doctor_evidence_log,
      self_check_secretless_evidence_log:$self_check_secretless_evidence_log,
      compliance_evidence_log:$compliance_evidence_log,
      integration_suite_log:$integration_suite_log,
      clippy_log:$clippy_log,
      environment:$environment,
      replay:$replay
    }
  }' > "${OUT_ROOT}/summary.json"

echo "MySQL verification artifacts written to ${OUT_ROOT}"
