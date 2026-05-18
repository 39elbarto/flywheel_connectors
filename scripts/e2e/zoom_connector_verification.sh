#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/zoom_connector/${RUN_ID}}"
TARGET_DIR="${FCP_ZOOM_TARGET_DIR:-/tmp/fcp-zoom-e2e}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0

manifest_status="pending"
manifest_note=""
cargo_check_status="pending"
format_check_status="pending"
health_guidance_status="pending"
doctor_guidance_status="pending"
self_check_status="pending"
retryable_self_check_status="pending"
pagination_evidence_status="pending"
dangerous_delete_status="pending"
compliance_status="pending"
integration_suite_status="pending"
crate_suite_status="pending"
clippy_status="pending"
manifest_check_runner=""
manifest_stdout_path="${OUT_ROOT}/evidence/manifest_check.command.json"

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

  echo "[zoom-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[zoom-verification] ${name}: $*"
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

  echo "[zoom-verification] ${name}: $*"
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
  if grep -Eq 'timeout: failed to execute process|RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|missing worker|No space left on device|dbus-1\.pc|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|The system library .*dbus-1.* required|pkg-config --libs --cflags dbus-1' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

classify_manifest_failure() {
  local log_path="$1"
  if grep -Eq 'missing worker system package dbus-1\.pc|The system library .*dbus-1.* required|pkg-config --libs --cflags dbus-1' "${log_path}"; then
    echo "infra_blocked"
  else
    classify_failure "${log_path}"
  fi
}

run_status_step() {
  local status_var="$1"
  local name="$2"
  shift 2

  if run_logged "${name}" "$@"; then
    printf -v "${status_var}" '%s' "passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    printf -v "${status_var}" '%s' "${status}"
    promote_overall_status "${status}"
  fi
}

require_cmd "${RCH_BIN}"

manifest_check_runner="${REMOTE_RUNNER}:cargo-run"

if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/zoom/manifest.toml --check --json
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
else
  manifest_status="$(classify_manifest_failure "${OUT_ROOT}/logs/manifest_check.log")"
  if [[ "${manifest_status}" == "infra_blocked" ]]; then
    manifest_note="rch worker image missing dbus-1.pc while building fwc for manifest validation"
  else
    manifest_note="manifest validation command failed; inspect logs/manifest_check.log"
  fi
  cat > "${OUT_ROOT}/evidence/manifest_check.json" <<EOF
{
  "status": "${manifest_status}",
  "note": "${manifest_note}",
  "command_output": "${manifest_stdout_path}",
  "log": "${OUT_ROOT}/logs/manifest_check.log"
}
EOF
  promote_overall_status "${manifest_status}"
fi

run_status_step cargo_check_status cargo_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-zoom --all-targets
run_status_step format_check_status format_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt --manifest-path connectors/zoom/Cargo.toml --check
run_status_step health_guidance_status health_guidance_evidence env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration health_unconfigured_includes_guidance -- --nocapture
run_status_step doctor_guidance_status doctor_guidance_evidence env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
run_status_step self_check_status self_check_evidence env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration self_check_ready_with_mock_zoom_api_and_evidence -- --nocapture
run_status_step retryable_self_check_status retryable_self_check_evidence env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration self_check_retryable_zoom_failure_reports_degraded -- --nocapture
run_status_step pagination_evidence_status pagination_evidence env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration invoke_meetings_list_preserves_pagination_evidence -- --nocapture
run_status_step dangerous_delete_status dangerous_delete_evidence env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration invoke_dangerous_meetings_delete_preserves_artifact_evidence -- --nocapture
run_status_step compliance_status compliance_evidence env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration introspection_emits_v3_compliance_evidence -- --nocapture
run_status_step integration_suite_status integration_suite env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom --test integration -- --nocapture
run_status_step crate_suite_status crate_suite env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-zoom -- --nocapture
run_status_step clippy_status clippy env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-zoom --all-targets -- -D warnings

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-zoom",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/zoom_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "target_dir": "${TARGET_DIR}",
  "manifest_check_runner": "${manifest_check_runner}",
  "rch_bin": "${RCH_BIN}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "scope_note": "first slice covers meetings, users, recordings, webinar inventory, readiness, and dangerous meeting deletion evidence"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="\${FCP_ZOOM_TARGET_DIR:-${TARGET_DIR}}"
RCH_BIN="\${RCH_BIN:-${RCH_BIN}}"
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
export RCH_FORCE_REMOTE=1

env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/zoom/manifest.toml --check --json
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo fmt --manifest-path connectors/zoom/Cargo.toml --check
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo check -p fcp-zoom --all-targets
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration health_unconfigured_includes_guidance -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration self_check_ready_with_mock_zoom_api_and_evidence -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration self_check_retryable_zoom_failure_reports_degraded -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration invoke_meetings_list_preserves_pagination_evidence -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration invoke_dangerous_meetings_delete_preserves_artifact_evidence -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration introspection_emits_v3_compliance_evidence -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom --test integration -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-zoom -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo clippy -p fcp-zoom --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-zoom",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "steps": {
    "manifest_check": {
      "status": "${manifest_status}",
      "note": "${manifest_note}"
    },
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "health_guidance_evidence": "${health_guidance_status}",
    "doctor_guidance_evidence": "${doctor_guidance_status}",
    "self_check_evidence": "${self_check_status}",
    "retryable_self_check_evidence": "${retryable_self_check_status}",
    "pagination_evidence": "${pagination_evidence_status}",
    "dangerous_delete_evidence": "${dangerous_delete_status}",
    "compliance_evidence": "${compliance_status}",
    "integration_suite": "${integration_suite_status}",
    "crate_suite": "${crate_suite_status}",
    "clippy": "${clippy_status}"
  },
  "artifacts": {
    "manifest_check": "${OUT_ROOT}/evidence/manifest_check.json",
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "health_guidance_evidence_log": "${OUT_ROOT}/logs/health_guidance_evidence.log",
    "doctor_guidance_evidence_log": "${OUT_ROOT}/logs/doctor_guidance_evidence.log",
    "self_check_evidence_log": "${OUT_ROOT}/logs/self_check_evidence.log",
    "retryable_self_check_evidence_log": "${OUT_ROOT}/logs/retryable_self_check_evidence.log",
    "pagination_evidence_log": "${OUT_ROOT}/logs/pagination_evidence.log",
    "dangerous_delete_evidence_log": "${OUT_ROOT}/logs/dangerous_delete_evidence.log",
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "crate_suite_log": "${OUT_ROOT}/logs/crate_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Zoom verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
