#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/package_registry_connector/${RUN_ID}}"
TARGET_DIR="${FCP_PACKAGE_REGISTRY_TARGET_DIR:-/tmp/fcp-package-registry-e2e-target}"
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

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[package-registry-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && requires_rch_remote_proof "${name}" && ! require_rch_remote_proof "${name}" "${log_path}"; then
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

  echo "[package-registry-verification] ${name}: $*"
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${stdout_path}" 2>"${log_path}"
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && requires_rch_remote_proof "${name}" && ! require_rch_remote_proof "${name}" "${log_path}"; then
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

classify_manifest_failure() {
  local log_path="$1"
  # shellcheck disable=SC2016
  if grep -Eq 'RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|missing worker system package dbus-1\.pc|The system library `dbus-1` required|pkg-config --libs --cflags dbus-1' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

classify_step_failure() {
  local log_path="$1"
  if grep -Eq 'RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|No space left on device|connection reset by peer|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response|missing worker system package|timeout: failed to execute process' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"

  if grep -Fq "[RCH] remote" "${log_path}"; then
    return 0
  fi

  echo "[package-registry-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

requires_rch_remote_proof() {
  case "$1" in
    format_check)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

require_cmd rch

manifest_check_runner="${REMOTE_RUNNER}:cargo-run"
manifest_check_cmd=(
  env
  RCH_VISIBILITY=verbose
  rch
  exec
  --
  env
  "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}"
  CARGO_TARGET_DIR="${TARGET_DIR}"
  cargo
  run
  -q
  -p
  fwc
  --
  manifest
  fix
  connectors/package-registry/manifest.toml
  --check
  --json
)

if run_capture_stdout \
  manifest_check \
  "${manifest_stdout_path}" \
  "${manifest_check_cmd[@]}"
then
  manifest_status="passed"
  cp "${manifest_stdout_path}" "${OUT_ROOT}/evidence/manifest_check.json"
else
  manifest_status="$(classify_manifest_failure "${OUT_ROOT}/logs/manifest_check.log")"
  if [[ "${manifest_status}" == "infra_blocked" ]]; then
    if grep -Fq "rch command did not produce remote proof" "${OUT_ROOT}/logs/manifest_check.log"; then
      manifest_note="rch command did not produce remote proof for manifest validation"
    else
      manifest_note="infrastructure blocked manifest validation; inspect logs/manifest_check.log"
    fi
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

if run_logged \
  cargo_check \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-package-registry --all-targets
then
  cargo_check_status="passed"
else
  cargo_check_status="$(classify_step_failure "${OUT_ROOT}/logs/cargo_check.log")"
  promote_overall_status "${cargo_check_status}"
fi

if run_logged \
  format_check \
  env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt --manifest-path connectors/package-registry/Cargo.toml --check
then
  format_check_status="passed"
else
  format_check_status="$(classify_step_failure "${OUT_ROOT}/logs/format_check.log")"
  promote_overall_status "${format_check_status}"
fi

if run_logged \
  health_guidance_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry --test integration health_unconfigured_includes_guidance -- --nocapture
then
  health_guidance_status="passed"
else
  health_guidance_status="$(classify_step_failure "${OUT_ROOT}/logs/health_guidance_evidence.log")"
  promote_overall_status "${health_guidance_status}"
fi

if run_logged \
  doctor_guidance_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
then
  doctor_guidance_status="passed"
else
  doctor_guidance_status="$(classify_step_failure "${OUT_ROOT}/logs/doctor_guidance_evidence.log")"
  promote_overall_status "${doctor_guidance_status}"
fi

if run_logged \
  self_check_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry --test integration self_check_ready_with_crates_override_and_evidence -- --nocapture
then
  self_check_status="passed"
else
  self_check_status="$(classify_step_failure "${OUT_ROOT}/logs/self_check_evidence.log")"
  promote_overall_status "${self_check_status}"
fi

if run_logged \
  retryable_self_check_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry --test integration self_check_retryable_registry_failure_reports_degraded -- --nocapture
then
  retryable_self_check_status="passed"
else
  retryable_self_check_status="$(classify_step_failure "${OUT_ROOT}/logs/retryable_self_check_evidence.log")"
  promote_overall_status "${retryable_self_check_status}"
fi

if run_logged \
  pagination_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry --test integration invoke_search_uses_npm_pagination_offset -- --nocapture
then
  pagination_evidence_status="passed"
else
  pagination_evidence_status="$(classify_step_failure "${OUT_ROOT}/logs/pagination_evidence.log")"
  promote_overall_status "${pagination_evidence_status}"
fi

if run_logged \
  compliance_evidence \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry --test integration introspection_emits_v3_compliance_evidence -- --nocapture
then
  compliance_status="passed"
else
  compliance_status="$(classify_step_failure "${OUT_ROOT}/logs/compliance_evidence.log")"
  promote_overall_status "${compliance_status}"
fi

if run_logged \
  integration_suite \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry --test integration -- --nocapture
then
  integration_suite_status="passed"
else
  integration_suite_status="$(classify_step_failure "${OUT_ROOT}/logs/integration_suite.log")"
  promote_overall_status "${integration_suite_status}"
fi

if run_logged \
  crate_suite \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-package-registry -- --nocapture
then
  crate_suite_status="passed"
else
  crate_suite_status="$(classify_step_failure "${OUT_ROOT}/logs/crate_suite.log")"
  promote_overall_status "${crate_suite_status}"
fi

if run_logged \
  clippy \
  env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-package-registry --all-targets -- -D warnings
then
  clippy_status="passed"
else
  clippy_status="$(classify_step_failure "${OUT_ROOT}/logs/clippy.log")"
  promote_overall_status "${clippy_status}"
fi

cat > "${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-package-registry",
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/package_registry_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "target_dir": "${TARGET_DIR}",
  "manifest_check_runner": "${manifest_check_runner}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "scope_note": "first slice is read-only metadata and readiness; no publish or mutation workflows are exercised"
}
EOF

cat > "${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="\${FCP_PACKAGE_REGISTRY_TARGET_DIR:-${TARGET_DIR}}"
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
export RCH_FORCE_REMOTE=1

env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo run -q -p fwc -- manifest fix connectors/package-registry/manifest.toml --check --json
env -u RCH_FORCE_REMOTE -u RCH_REQUIRE_REMOTE RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo fmt --manifest-path connectors/package-registry/Cargo.toml --check
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo check -p fcp-package-registry --all-targets
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry --test integration health_unconfigured_includes_guidance -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry --test integration doctor_unconfigured_reports_operator_guidance -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry --test integration self_check_ready_with_crates_override_and_evidence -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry --test integration self_check_retryable_registry_failure_reports_degraded -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry --test integration invoke_search_uses_npm_pagination_offset -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry --test integration introspection_emits_v3_compliance_evidence -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry --test integration -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo test -p fcp-package-registry -- --nocapture
env RCH_VISIBILITY=verbose rch exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${TARGET_DIR}" cargo clippy -p fcp-package-registry --all-targets -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat > "${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "connector": "fcp-package-registry",
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
    "compliance_evidence_log": "${OUT_ROOT}/logs/compliance_evidence.log",
    "integration_suite_log": "${OUT_ROOT}/logs/integration_suite.log",
    "crate_suite_log": "${OUT_ROOT}/logs/crate_suite.log",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Package Registry verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
